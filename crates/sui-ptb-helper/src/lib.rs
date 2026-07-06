//! Shared Sui PTB primitives for app integrations.
//!
//! Downstream apps should use the Sui types re-exported by this crate instead of
//! declaring their own `sui-*` dependencies. Keeping the PTB builder and
//! argument types on this single API surface avoids cross-workspace duplicate
//! Sui dependency graphs.

use anyhow::{anyhow, ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shared_crypto::intent::Intent;
use std::path::PathBuf;
use std::str::FromStr;
use sui_config::{sui_config_dir, SUI_KEYSTORE_FILENAME};
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
use sui_sdk::types::{Identifier, TypeTag};
use sui_sdk::{SuiClient, SuiClientBuilder};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SuiPtbConfig {
    pub rpc_url: String,
    pub keystore_path: Option<PathBuf>,
    pub sender: Option<String>,
    pub gas_budget: u64,
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

impl TxResponse {
    pub fn created_object_id(&self, type_suffix: &str) -> anyhow::Result<String> {
        self.created_objects
            .iter()
            .find(|object| object.object_type.ends_with(type_suffix))
            .map(|object| object.object_id.clone())
            .ok_or_else(|| anyhow!("transaction {} did not create {type_suffix}", self.digest))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectAccess {
    Immutable,
    Mutable,
}

impl ObjectAccess {
    fn shared_mutability(self) -> SharedObjectMutability {
        match self {
            Self::Immutable => SharedObjectMutability::Immutable,
            Self::Mutable => SharedObjectMutability::Mutable,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MoveTarget {
    package: ObjectID,
    module: Identifier,
    function: Identifier,
    type_arguments: Vec<TypeTag>,
}

impl MoveTarget {
    pub fn new(package: &str, module: &str, function: &str) -> anyhow::Result<Self> {
        Ok(Self {
            package: parse_object_id(package, "package")?,
            module: Identifier::new(module)?,
            function: Identifier::new(function)?,
            type_arguments: vec![],
        })
    }

    pub fn with_type_arguments(mut self, type_arguments: Vec<TypeTag>) -> Self {
        self.type_arguments = type_arguments;
        self
    }
}

pub struct SuiPtbClient {
    client: SuiClient,
    keystore: FileBasedKeystore,
    sender: SuiAddress,
    gas_budget: u64,
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
        })
    }

    pub fn sender(&self) -> SuiAddress {
        self.sender
    }

    pub async fn execute(&self, ptb: ProgrammableTransaction) -> anyhow::Result<TxResponse> {
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

    pub async fn input_object(
        &self,
        builder: &mut ProgrammableTransactionBuilder,
        object_id: &str,
        access: ObjectAccess,
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
                mutability: access.shared_mutability(),
            },
        };
        builder.obj(object_arg)
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
}

pub fn move_call(
    builder: &mut ProgrammableTransactionBuilder,
    target: MoveTarget,
    args: Vec<Argument>,
) -> Argument {
    builder.programmable_move_call(
        target.package,
        target.module,
        target.function,
        target.type_arguments,
        args,
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_object_id_filters_by_suffix() {
        let tx = TxResponse {
            digest: "abc".to_string(),
            created_objects: vec![CreatedObject {
                object_id: "0x1".to_string(),
                object_type: "0x2::example::CreatedThing".to_string(),
            }],
        };
        assert_eq!(
            tx.created_object_id("::example::CreatedThing").unwrap(),
            "0x1"
        );
    }

    #[test]
    fn move_call_appends_ptb_command() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let result = move_call(
            &mut builder,
            MoveTarget::new("0x1", "module_name", "function_name").unwrap(),
            vec![],
        );
        assert_eq!(result, Argument::Result(0));
        assert_eq!(builder.finish().commands.len(), 1);
    }
}
