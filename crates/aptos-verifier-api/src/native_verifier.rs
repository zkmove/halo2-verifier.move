use anyhow::Error;
use halo2_backend::arithmetic::CurveAffine;
use halo2_backend::helpers::SerdeFormat;
use halo2_backend::plonk::VerifyingKey;
use halo2_backend::poly::commitment::Params;
use halo2_backend::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::halo2curves::ff::FromUniformBytes;
use halo2_proofs::plonk::Circuit;
use serde_json::json;
use halo2_verifier::circuit::generate_serialized_circuit;
use halo2_verifier::params::serialize_kzg_params;
use halo2_verifier::public_inputs::PublicInputs;
use crate::{ArgWithTypeJSON, EntryFunctionArgumentsJSON, HexEncodedBytes, FUNC_PUBLISH_CIRCUIT_NATIVE, FUNC_PUBLISH_PARAMS_NATIVE, FUNC_PUBLISH_VK_NATIVE, FUNC_VERIFY_PROOF_NATIVE, MODULE_PARAMS, MODULE_VERIFIER_NATIVE};

/// Build publish serialized kzg params transaction payload for aptos.
pub fn build_publish_params_native_transaction_payload(
    params: &ParamsKZG<Bn256>,
    params_contract_address: String,
) -> Result<EntryFunctionArgumentsJSON, Error> {
    let params_bytes = serialize_kzg_params(&params.verifier_params())
        .map_err(|e| Error::msg(format!("serialize kzg params failed: {}", e)))?;
    let json = EntryFunctionArgumentsJSON {
        function_id: format!(
            "{}::{}::{}",
            params_contract_address, MODULE_PARAMS, FUNC_PUBLISH_PARAMS_NATIVE
        ),
        type_args: vec![],
        args: vec![ArgWithTypeJSON {
            r#type: "hex".to_string(),
            value: json!(HexEncodedBytes(params_bytes).to_string()),
        }],
    };
    Ok(json)
}

/// Build publish serialized vk transaction payload for aptos.
pub fn build_publish_vk_native_transaction_payload(
    vk: &VerifyingKey<G1Affine>,
    native_verifier_contract_address: String,
) -> Result<EntryFunctionArgumentsJSON, Error> {
    let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);
    let json = EntryFunctionArgumentsJSON {
        function_id: format!("{}::{}::{}", native_verifier_contract_address, MODULE_VERIFIER_NATIVE, FUNC_PUBLISH_VK_NATIVE),
        type_args: vec![],
        args: vec![ArgWithTypeJSON {
            r#type: "hex".to_string(),
            value: json!(HexEncodedBytes(vk_bytes).to_string()),
        }],
    };
    Ok(json)
}

/// Build publish serialized circuit transaction payload for aptos.
pub fn build_publish_circuit_native_transaction_payload<C, P, ConcreteCircuit>(
    params: &P,
    circuit: &ConcreteCircuit,
    native_verifier_contract_address: String,
) -> Result<EntryFunctionArgumentsJSON, Error>
where
    C: CurveAffine,
    P: Params<C>,
    ConcreteCircuit: Circuit<C::Scalar>,
    C::Scalar: FromUniformBytes<64>,
    C::ScalarExt: FromUniformBytes<64>,
{
    let circuit_bytes = generate_serialized_circuit(params, circuit)
        .map_err(|e| Error::msg(format!("generate serialized circuit failed: {}", e)))?;

    let json = EntryFunctionArgumentsJSON {
        function_id: format!(
            "{}::{}::{}",
            native_verifier_contract_address, MODULE_VERIFIER_NATIVE, FUNC_PUBLISH_CIRCUIT_NATIVE
        ),
        type_args: vec![],
        args: vec![ArgWithTypeJSON {
            r#type: "hex".to_string(),
            value: json!(HexEncodedBytes(circuit_bytes).to_string()),
        }],
    };
    Ok(json)
}

/// Build verify proof transaction payload for aptos.
pub fn build_verify_proof_native_transaction_payload<C>(
    proof: Vec<u8>,
    proof_kzg_variant: u8,
    public_inputs: Vec<Vec<C::Scalar>>,
    native_verifier_contract_address: &str,
    native_verifier_address: &str,
    params_address: &str,
    k: Option<u32>,
) -> anyhow::Result<EntryFunctionArgumentsJSON, Error>
where
    C: CurveAffine,
{
    let instances = PublicInputs::<C>(public_inputs).to_bytes();
    let k_bytes = bcs::to_bytes(&k)
        .map_err(|e| Error::msg(format!("serialize k option failed: {}", e)))?;
    let json = EntryFunctionArgumentsJSON {
        function_id: format!(
            "{}::{}::{}",
            native_verifier_contract_address, MODULE_VERIFIER_NATIVE, FUNC_VERIFY_PROOF_NATIVE
        ),
        type_args: vec![],
        args: vec![
            ArgWithTypeJSON {
                r#type: "address".to_string(),
                value: json!(params_address),
            },
            ArgWithTypeJSON {
                r#type: "address".to_string(),
                value: json!(native_verifier_address),
            },
            ArgWithTypeJSON {
                r#type: "hex".to_string(),
                value: json!(HexEncodedBytes(instances).to_string()),
            },
            ArgWithTypeJSON {
                r#type: "hex".to_string(),
                value: json!(HexEncodedBytes(proof).to_string()),
            },
            ArgWithTypeJSON {
                r#type: "u8".to_string(),
                value: json!(proof_kzg_variant),
            },
            ArgWithTypeJSON {
                r#type: "raw".to_string(),
                value: json!(HexEncodedBytes(k_bytes).to_string()),
            },
        ],
    };

    Ok(json)
}