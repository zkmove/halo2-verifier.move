use anyhow::{anyhow, ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shared_crypto::intent::Intent;
use std::path::PathBuf;
use std::str::FromStr;
use sui_config::{sui_config_dir, SUI_KEYSTORE_FILENAME};
use sui_json::SuiJsonValue;
use sui_keys::keystore::{AccountKeystore, FileBasedKeystore};
use sui_sdk::rpc_types::{
    ObjectChange, SuiObjectDataOptions, SuiParsedData, SuiTransactionBlockResponse,
    SuiTransactionBlockResponseOptions,
};
use sui_sdk::types::base_types::{FullObjectID, ObjectID, SuiAddress};
pub use sui_sdk::types::programmable_transaction_builder::ProgrammableTransactionBuilder;
pub use sui_sdk::types::transaction::{Argument, ProgrammableTransaction};
use sui_sdk::types::transaction::{
    ObjectArg, SharedObjectMutability, Transaction, TransactionData,
};
use sui_sdk::types::transaction_driver_types::ExecuteTransactionRequestType;
use sui_sdk::types::Identifier;
use sui_sdk::{SuiClient, SuiClientBuilder};
pub use sui_verifier_api::artifact::{ChunkPlan, DEFAULT_CHUNK_SIZE};

const MODULE_ARTIFACT_BUILDER: &str = "artifact_builder";
const FUNC_PUBLISH_PARAMS_BUILDER: &str = "publish_params_builder";
const FUNC_PUBLISH_VK_BUILDER: &str = "publish_vk_builder";
const FUNC_PUBLISH_CIRCUIT_INFO_BUILDER: &str = "publish_circuit_info_builder";
const FUNC_PUBLISH_PROOF_BUILDER: &str = "publish_proof_builder";
const FUNC_APPEND_CHUNK: &str = "append_chunk";
const FUNC_FINALIZE_PARAMS_TO_SENDER: &str = "finalize_params_to_sender";
const FUNC_FINALIZE_VK_TO_SENDER: &str = "finalize_vk_to_sender";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SuiPtbConfig {
    pub rpc_url: String,
    pub keystore_path: Option<PathBuf>,
    pub sender: Option<String>,
    pub gas_budget: u64,
    pub chunk_size: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxResponse {
    pub digest: String,
    pub created_objects: Vec<CreatedObject>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedObject {
    pub object_id: String,
    pub object_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadedProofRef {
    pub proof_builder: String,
    pub proof_digest: Vec<u8>,
    pub proof_bytes: usize,
    pub tx_digests: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadedVerifierArtifacts {
    pub params_object_id: String,
    pub vk_object_id: String,
    pub params_digest: Vec<u8>,
    pub vk_digest: Vec<u8>,
    pub circuit_digest: Vec<u8>,
    pub tx_digests: Vec<String>,
}

pub struct SuiPtbClient {
    client: SuiClient,
    keystore: FileBasedKeystore,
    sender: SuiAddress,
    gas_budget: u64,
    chunk_size: usize,
}

impl SuiPtbClient {
    pub async fn connect(config: SuiPtbConfig) -> anyhow::Result<Self> {
        let explicit_keystore_path = config.keystore_path;
        let keystore_path = explicit_keystore_path
            .clone()
            .unwrap_or(sui_config_dir()?.join(SUI_KEYSTORE_FILENAME));
        if explicit_keystore_path.is_some() {
            ensure!(
                keystore_path.exists(),
                "Sui keystore does not exist: {}",
                keystore_path.display()
            );
        }
        let keystore = FileBasedKeystore::load_or_create(&keystore_path)
            .with_context(|| format!("failed to load Sui keystore {}", keystore_path.display()))?;
        let sender = match config.sender {
            Some(sender) => SuiAddress::from_str(&sender)
                .with_context(|| format!("invalid Sui sender address: {sender}"))?,
            None => *keystore.addresses().first().ok_or_else(|| {
                anyhow!("Sui keystore has no addresses: {}", keystore_path.display())
            })?,
        };
        let client = SuiClientBuilder::default()
            .build(&config.rpc_url)
            .await
            .with_context(|| format!("failed to connect to Sui RPC {}", config.rpc_url))?;
        Ok(Self {
            client,
            keystore,
            sender,
            gas_budget: config.gas_budget,
            chunk_size: config.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE),
        })
    }

    pub fn sender(&self) -> SuiAddress {
        self.sender
    }

    pub async fn execute_ptb(&self, ptb: ProgrammableTransaction) -> anyhow::Result<TxResponse> {
        let input_objects = ptb
            .input_objects()
            .context("failed to collect PTB input objects")?
            .into_iter()
            .map(|object| object.object_id())
            .collect::<Vec<_>>();
        let gas_price = self.client.read_api().get_reference_gas_price().await?;
        let gas = self
            .client
            .transaction_builder()
            .select_gas(self.sender, None, self.gas_budget, input_objects, gas_price)
            .await?;
        let tx_data = TransactionData::new_programmable(
            self.sender,
            vec![gas],
            ptb,
            self.gas_budget,
            gas_price,
        );
        self.sign_and_execute(tx_data).await
    }

    pub async fn object_input(
        &self,
        builder: &mut ProgrammableTransactionBuilder,
        object_id: &str,
        mutable: bool,
    ) -> anyhow::Result<Argument> {
        let object_id = parse_object_id(object_id, "object id")?;
        let full_ref = self
            .client
            .transaction_builder()
            .get_full_object_ref(object_id)
            .await?;
        let object_arg = match full_ref.0 {
            FullObjectID::Fastpath(_) => ObjectArg::ImmOrOwnedObject(full_ref.as_object_ref()),
            FullObjectID::Consensus((id, initial_shared_version)) => ObjectArg::SharedObject {
                id,
                initial_shared_version,
                mutability: if mutable {
                    SharedObjectMutability::Mutable
                } else {
                    SharedObjectMutability::Immutable
                },
            },
        };
        builder.obj(object_arg)
    }

    pub async fn move_call(
        &self,
        package: &str,
        module: &str,
        function: &str,
        args: Vec<Value>,
    ) -> anyhow::Result<TxResponse> {
        let package = parse_object_id(package, "package")?;
        let args = args
            .into_iter()
            .map(SuiJsonValue::new)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let tx_data = self
            .client
            .transaction_builder()
            .move_call(
                self.sender,
                package,
                module,
                function,
                vec![],
                args,
                None,
                self.gas_budget,
                None,
            )
            .await?;
        self.sign_and_execute(tx_data).await
    }

    async fn sign_and_execute(&self, tx_data: TransactionData) -> anyhow::Result<TxResponse> {
        let signature = self
            .keystore
            .sign_secure(&self.sender, &tx_data, Intent::sui_transaction())
            .await?;
        let response = self
            .client
            .quorum_driver_api()
            .execute_transaction_block(
                Transaction::from_data(tx_data, vec![signature]),
                SuiTransactionBlockResponseOptions::full_content(),
                Some(ExecuteTransactionRequestType::WaitForLocalExecution),
            )
            .await?;
        tx_response(response)
    }

    pub async fn upload_proof(
        &self,
        verifier_api_package: &str,
        proof: Vec<u8>,
    ) -> anyhow::Result<UploadedProofRef> {
        let plan = ChunkPlan::new(proof, Some(self.chunk_size))?;
        let mut tx_digests = Vec::new();
        let builder_tx = self
            .move_call(
                verifier_api_package,
                MODULE_ARTIFACT_BUILDER,
                FUNC_PUBLISH_PROOF_BUILDER,
                vec![],
            )
            .await?;
        let proof_builder = created_object_id(&builder_tx, "::artifact_builder::ArtifactBuilder")?;
        tx_digests.push(builder_tx.digest);

        for chunk in &plan.chunks {
            let append_tx = self
                .move_call(
                    verifier_api_package,
                    MODULE_ARTIFACT_BUILDER,
                    FUNC_APPEND_CHUNK,
                    vec![Value::String(proof_builder.clone()), byte_array_json(chunk)],
                )
                .await?;
            tx_digests.push(append_tx.digest);
        }

        Ok(UploadedProofRef {
            proof_builder,
            proof_digest: plan.digest.to_vec(),
            proof_bytes: plan.total_len,
            tx_digests,
        })
    }

    pub async fn upload_verifier_artifacts(
        &self,
        verifier_api_package: &str,
        params: Vec<u8>,
        vk: Vec<u8>,
        circuit: Vec<u8>,
    ) -> anyhow::Result<UploadedVerifierArtifacts> {
        let params = ChunkPlan::new(params, Some(self.chunk_size))?;
        let vk = ChunkPlan::new(vk, Some(self.chunk_size))?;
        let circuit = ChunkPlan::new(circuit, Some(self.chunk_size))?;
        let mut tx_digests = Vec::new();

        let params_builder = self
            .create_builder(
                verifier_api_package,
                FUNC_PUBLISH_PARAMS_BUILDER,
                &mut tx_digests,
            )
            .await?;
        let vk_builder = self
            .create_builder(
                verifier_api_package,
                FUNC_PUBLISH_VK_BUILDER,
                &mut tx_digests,
            )
            .await?;
        let circuit_builder = self
            .create_builder(
                verifier_api_package,
                FUNC_PUBLISH_CIRCUIT_INFO_BUILDER,
                &mut tx_digests,
            )
            .await?;

        self.append_chunks(
            verifier_api_package,
            &params_builder,
            &params.chunks,
            &mut tx_digests,
        )
        .await?;
        self.append_chunks(
            verifier_api_package,
            &vk_builder,
            &vk.chunks,
            &mut tx_digests,
        )
        .await?;
        self.append_chunks(
            verifier_api_package,
            &circuit_builder,
            &circuit.chunks,
            &mut tx_digests,
        )
        .await?;

        let params_tx = self
            .move_call(
                verifier_api_package,
                MODULE_ARTIFACT_BUILDER,
                FUNC_FINALIZE_PARAMS_TO_SENDER,
                vec![Value::String(params_builder), params.digest.to_json_value()],
            )
            .await?;
        let params_object_id =
            created_object_id(&params_tx, "::serialized_params_store::SerializedParams")?;
        tx_digests.push(params_tx.digest);

        let vk_tx = self
            .move_call(
                verifier_api_package,
                MODULE_ARTIFACT_BUILDER,
                FUNC_FINALIZE_VK_TO_SENDER,
                vec![
                    Value::String(vk_builder),
                    Value::String(circuit_builder),
                    vk.digest.to_json_value(),
                    circuit.digest.to_json_value(),
                ],
            )
            .await?;
        let vk_object_id = created_object_id(&vk_tx, "::native_verifier::SerializedVK")?;
        tx_digests.push(vk_tx.digest);

        Ok(UploadedVerifierArtifacts {
            params_object_id,
            vk_object_id,
            params_digest: params.digest.to_vec(),
            vk_digest: vk.digest.to_vec(),
            circuit_digest: circuit.digest.to_vec(),
            tx_digests,
        })
    }

    pub async fn read_object_field(
        &self,
        object_id: &str,
        field_name: &str,
    ) -> anyhow::Result<String> {
        let value = self.read_object_field_json(object_id, field_name).await?;
        Ok(match value {
            Value::String(value) => value,
            Value::Number(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            other => other.to_string(),
        })
    }

    pub async fn read_object_field_json(
        &self,
        object_id: &str,
        field_name: &str,
    ) -> anyhow::Result<Value> {
        let object_id = parse_object_id(object_id, "object id")?;
        let object = self
            .client
            .read_api()
            .get_object_with_options(object_id, SuiObjectDataOptions::new().with_content())
            .await?;
        let data = object
            .data
            .ok_or_else(|| anyhow!("object {object_id} was not returned"))?;
        let content = data
            .content
            .ok_or_else(|| anyhow!("object {object_id} did not include parsed content"))?;
        let SuiParsedData::MoveObject(move_object) = content else {
            return Err(anyhow!("object {object_id} is not a Move object"));
        };
        let value = move_object
            .fields
            .field_value(field_name)
            .ok_or_else(|| anyhow!("object {object_id} has no field {field_name}"))?;
        Ok(value.to_json_value())
    }

    async fn create_builder(
        &self,
        package: &str,
        function: &str,
        tx_digests: &mut Vec<String>,
    ) -> anyhow::Result<String> {
        let tx = self
            .move_call(package, MODULE_ARTIFACT_BUILDER, function, vec![])
            .await?;
        let object_id = created_object_id(&tx, "::artifact_builder::ArtifactBuilder")?;
        tx_digests.push(tx.digest);
        Ok(object_id)
    }

    async fn append_chunks(
        &self,
        package: &str,
        builder: &str,
        chunks: &[Vec<u8>],
        tx_digests: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        ensure!(!chunks.is_empty(), "chunk list must not be empty");
        for chunk in chunks {
            let tx = self
                .move_call(
                    package,
                    MODULE_ARTIFACT_BUILDER,
                    FUNC_APPEND_CHUNK,
                    vec![Value::String(builder.to_string()), byte_array_json(chunk)],
                )
                .await?;
            tx_digests.push(tx.digest);
        }
        Ok(())
    }
}

pub fn add_new_proof_builder_call(
    builder: &mut ProgrammableTransactionBuilder,
    verifier_api_package: &str,
) -> anyhow::Result<Argument> {
    add_move_call(
        builder,
        verifier_api_package,
        MODULE_ARTIFACT_BUILDER,
        "new_proof_builder",
        vec![],
    )
}

pub fn add_append_chunk_call(
    builder: &mut ProgrammableTransactionBuilder,
    verifier_api_package: &str,
    proof_builder: Argument,
    chunk: Vec<u8>,
) -> anyhow::Result<Argument> {
    let chunk = builder.pure(chunk)?;
    add_move_call(
        builder,
        verifier_api_package,
        MODULE_ARTIFACT_BUILDER,
        FUNC_APPEND_CHUNK,
        vec![proof_builder, chunk],
    )
}

pub fn add_move_call(
    builder: &mut ProgrammableTransactionBuilder,
    package: &str,
    module: &str,
    function: &str,
    args: Vec<Argument>,
) -> anyhow::Result<Argument> {
    Ok(builder.programmable_move_call(
        parse_object_id(package, "package")?,
        Identifier::new(module)?,
        Identifier::new(function)?,
        vec![],
        args,
    ))
}

fn parse_object_id(value: &str, label: &str) -> anyhow::Result<ObjectID> {
    ObjectID::from_hex_literal(value).with_context(|| format!("invalid {label}: {value}"))
}

fn tx_response(response: SuiTransactionBlockResponse) -> anyhow::Result<TxResponse> {
    if response.status_ok() != Some(true) {
        return Err(anyhow!(
            "Sui transaction {} failed: {:?}",
            response.digest,
            response.effects
        ));
    }
    let created_objects = response
        .object_changes
        .unwrap_or_default()
        .into_iter()
        .filter_map(|change| match change {
            ObjectChange::Created {
                object_id,
                object_type,
                ..
            } => Some(CreatedObject {
                object_id: object_id.to_hex_uncompressed(),
                object_type: object_type.to_string(),
            }),
            _ => None,
        })
        .collect();
    Ok(TxResponse {
        digest: response.digest.to_string(),
        created_objects,
    })
}

fn created_object_id(tx: &TxResponse, type_suffix: &str) -> anyhow::Result<String> {
    tx.created_objects
        .iter()
        .find(|object| object.object_type.ends_with(type_suffix))
        .map(|object| object.object_id.clone())
        .ok_or_else(|| anyhow!("transaction {} did not create {type_suffix}", tx.digest))
}

fn byte_array_json(bytes: &[u8]) -> Value {
    Value::Array(bytes.iter().copied().map(Value::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_array_json_matches_sui_cli_shape() {
        assert_eq!(byte_array_json(&[1, 2, 3]), serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn created_object_parser_filters_by_suffix() {
        let tx = TxResponse {
            digest: "abc".to_string(),
            created_objects: vec![CreatedObject {
                object_id: "0x1".to_string(),
                object_type: "0x2::artifact_builder::ArtifactBuilder".to_string(),
            }],
        };
        assert_eq!(
            created_object_id(&tx, "::artifact_builder::ArtifactBuilder").unwrap(),
            "0x1"
        );
    }
}
