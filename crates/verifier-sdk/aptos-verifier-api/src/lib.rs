use crate::types::{ArgWithTypeJSON, EntryFunctionArgumentsJSON, HexEncodedBytes};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::{Circuit, Error};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use serde_json::json;
use shape_generator::generate_circuit_info;
use shape_generator::serialize::serialize;

pub mod proving;
pub mod types;
pub use shape_generator;

const VERIFIER_MODULE: &str = "verifier_api";
const PUBLISH_CIRCUIT: &str = "publish_circuit";
const VERIFY_PROOF_FUNC: &str = "verify";

/// build publish protocol transaction payload for aptos.
/// we only support kzg on bn254 for now.
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
    let protocol = generate_circuit_info(params, circuit)?;

    let data = serialize(protocol.into()).unwrap();

    let args: Vec<_> = data
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
            verifier_address, VERIFIER_MODULE, PUBLISH_CIRCUIT
        ),
        type_args: vec![],
        args,
    };
    Ok(json)
}

/// Build verify proof transaction payload for aptos.
/// we only support kzg on bn254 for now.
/// Returns a structure which can be serialized to json string,
/// and when output the json to file, it can be run by `aptos move run`.
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
