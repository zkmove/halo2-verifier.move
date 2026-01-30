use crate::types::{ArgWithTypeJSON, EntryFunctionArgumentsJSON, HexEncodedBytes};
use anyhow::{Error, Result};
use halo2_backend::arithmetic::CurveAffine;
use halo2_backend::helpers::SerdeFormat;
use halo2_backend::plonk::VerifyingKey;
use halo2_backend::poly::commitment::Params;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::halo2curves::ff::{FromUniformBytes, PrimeField};
use halo2_proofs::plonk::Circuit;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_verifier::circuit::{generate_serialized_circuit, generate_serialized_protocol};
use halo2_verifier::params::serialize_kzg_params;
use serde_json::json;

pub mod types;

/// module names shared by move verifier and native verifier
const VERIFIER_MODULE: &str = "verifier_api";
const PARAMS_MODULE: &str = "param_store";
const VK_MODULE: &str = "vk_store";

/// function names for move verifier
const PUBLISH_PROTOCOL_FUNC: &str = "publish_protocol";
const VERIFY_PROOF_FUNC: &str = "verify_proof";

/// function names for native verifier
const PUBLISH_PARAMS_FUNC: &str = "publish_serialized_params";
const PUBLISH_VK_FUNC: &str = "publish_serialized_vk";
const PUBLISH_CIRCUIT_FUNC: &str = "publish_serialized_circuit";

/// Move verifier related APIs
/// build publish protocol transaction payload for aptos.
/// Returns a structure which can be serialized to json string,
/// and when output the json to file, it can be run by `aptos move run`.
pub fn build_publish_protocol_transaction_payload<ConcreteCircuit>(
    params: &ParamsKZG<Bn256>,
    circuit: &ConcreteCircuit,
    verifier_address: String,
) -> Result<EntryFunctionArgumentsJSON, Error>
where
    ConcreteCircuit: Circuit<Fr>,
{
    let protocol = generate_serialized_protocol(params, circuit)
        .expect("generate circuit info should not fail");

    let args: Vec<_> = protocol
        .into_iter()
        .map(|arg| ArgWithTypeJSON {
            arg_type: "hex".to_string(),
            value: json!(arg
                .into_iter()
                .map(|i| HexEncodedBytes(i).to_string())
                .collect::<Vec<_>>()),
        })
        .collect();
    let json = EntryFunctionArgumentsJSON {
        function_id: format!(
            "{}::{}::{}",
            verifier_address, VERIFIER_MODULE, PUBLISH_PROTOCOL_FUNC
        ),
        type_args: vec![],
        args,
    };
    Ok(json)
}

/// Move verifier related APIs
/// Build verify proof transaction payload for aptos.
/// Returns a structure which can be serialized to json string,
/// and when output the json to file, it can be run by `aptos move run`.
#[allow(clippy::let_and_return)]
pub fn build_verify_proof_transaction_payload(
    proof: Vec<u8>,
    proof_kzg_variant: u8,
    instances: Vec<Vec<Fr>>,
    verifier_address: String,
    param_address: String,
    protocol_address: String,
) -> EntryFunctionArgumentsJSON {
    let instances = instances
        .iter()
        .map(|fr| {
            fr.iter()
                .map(|f| HexEncodedBytes(f.to_repr().as_ref().to_vec()).to_string())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let json = EntryFunctionArgumentsJSON {
        function_id: format!(
            "{}::{}::{}",
            verifier_address, VERIFIER_MODULE, VERIFY_PROOF_FUNC
        ),
        type_args: vec![],
        args: vec![
            ArgWithTypeJSON {
                arg_type: "address".to_string(),
                value: json!(param_address),
            },
            ArgWithTypeJSON {
                arg_type: "address".to_string(),
                value: json!(protocol_address),
            },
            ArgWithTypeJSON {
                arg_type: "hex".to_string(),
                value: json!(instances),
            },
            ArgWithTypeJSON {
                arg_type: "hex".to_string(),
                value: json!(HexEncodedBytes(proof.clone()).to_string()),
            },
            ArgWithTypeJSON {
                arg_type: "u8".to_string(),
                value: json!(proof_kzg_variant),
            },
        ],
    };

    json
}

/// Native verifier related APIs
/// Build publish serialized kzg params transaction payload for aptos.
pub fn build_publish_params_transaction_payload(
    params: &ParamsKZG<Bn256>,
    params_store_address: String,
) -> Result<EntryFunctionArgumentsJSON, Error> {
    let params_bytes = serialize_kzg_params(&params.verifier_params())
        .map_err(|e| Error::msg(format!("serialize kzg params failed: {}", e)))?;
    let json = EntryFunctionArgumentsJSON {
        function_id: format!(
            "{}::{}::{}",
            params_store_address, PARAMS_MODULE, PUBLISH_PARAMS_FUNC
        ),
        type_args: vec![],
        args: vec![ArgWithTypeJSON {
            arg_type: "hex".to_string(),
            value: json!(HexEncodedBytes(params_bytes).to_string()),
        }],
    };
    Ok(json)
}

/// Native verifier related APIs
/// Build publish serialized vk transaction payload for aptos.
pub fn build_publish_vk_transaction_payload(
    vk: &VerifyingKey<G1Affine>,
    vk_store_address: String,
) -> EntryFunctionArgumentsJSON {
    let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);
    let json = EntryFunctionArgumentsJSON {
        function_id: format!("{}::{}::{}", vk_store_address, VK_MODULE, PUBLISH_VK_FUNC),
        type_args: vec![],
        args: vec![ArgWithTypeJSON {
            arg_type: "hex".to_string(),
            value: json!(HexEncodedBytes(vk_bytes).to_string()),
        }],
    };
    json
}

/// Native verifier related APIs
/// Build publish serialized circuit transaction payload for aptos.
pub fn build_publish_circuit_transaction_payload<C, P, ConcreteCircuit>(
    params: &P,
    circuit: &ConcreteCircuit,
    vk_store_address: String,
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
            vk_store_address, VK_MODULE, PUBLISH_CIRCUIT_FUNC
        ),
        type_args: vec![],
        args: vec![ArgWithTypeJSON {
            arg_type: "hex".to_string(),
            value: json!(HexEncodedBytes(circuit_bytes).to_string()),
        }],
    };
    Ok(json)
}
