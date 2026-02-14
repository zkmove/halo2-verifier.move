use crate::{ArgWithTypeJSON, EntryFunctionArgumentsJSON, HexEncodedBytes, FUNC_PUBLISH_CIRCUIT, FUNC_PUBLISH_PARAMS, FUNC_VERIFY_PROOF, MODULE_PARAMS, MODULE_VERIFIER};
use anyhow::{Error, Result};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_verifier::circuit::{generate_serialized_protocol};
use serde_json::json;
use group::GroupEncoding;

/// build publish kzg params transaction payload for aptos.
pub fn build_publish_params_transaction_payload(
    params: &ParamsKZG<Bn256>,
    params_contract_address: &str,
) -> Result<EntryFunctionArgumentsJSON, Error> {
    let g = params.g().first().unwrap();
    let g2 = params.g2();
    let s_g2 = params.s_g2();

    let g_bytes = g.to_bytes().as_ref().to_vec();
    let g2_bytes = g2.to_bytes().as_ref().to_vec();
    let s_g2_bytes = s_g2.to_bytes().as_ref().to_vec();

    let json = EntryFunctionArgumentsJSON {
        function_id: format!(
            "{}::{}::{}",
            params_contract_address, MODULE_PARAMS, FUNC_PUBLISH_PARAMS
        ),
        type_args: vec![],
        args: vec![
            ArgWithTypeJSON {
                r#type: "hex".to_string(),
                value: json!(HexEncodedBytes(g_bytes).to_string()),
            },
            ArgWithTypeJSON {
                r#type: "hex".to_string(),
                value: json!(HexEncodedBytes(g2_bytes).to_string()),
            },
            ArgWithTypeJSON {
                r#type: "hex".to_string(),
                value: json!(HexEncodedBytes(s_g2_bytes).to_string()),
            },
        ],
    };
    Ok(json)
}

/// build publish circuit transaction payload for aptos.
/// Returns a structure which can be serialized to json string
pub fn build_publish_circuit_transaction_payload<ConcreteCircuit>(
    params: &ParamsKZG<Bn256>,
    circuit: &ConcreteCircuit,
    verifier_contract_address: &str,
) -> Result<EntryFunctionArgumentsJSON, Error>
where
    ConcreteCircuit: Circuit<Fr>,
{
    let protocol = generate_serialized_protocol(params, circuit)
        .map_err(|e| Error::msg(format!("generate serialized protocol failed: {}", e)))?;

    let args: Vec<_> = protocol
        .into_iter()
        .map(|arg| ArgWithTypeJSON {
            r#type: "hex".to_string(),
            value: json!(arg
                .into_iter()
                .map(|i| HexEncodedBytes(i).to_string())
                .collect::<Vec<_>>()),
        })
        .collect();
    let json = EntryFunctionArgumentsJSON {
        function_id: format!(
            "{}::{}::{}",
            verifier_contract_address, MODULE_VERIFIER, FUNC_PUBLISH_CIRCUIT
        ),
        type_args: vec![],
        args,
    };
    Ok(json)
}

/// Build verify proof transaction payload for aptos.
/// Returns a structure which can be serialized to json string,
pub fn build_verify_proof_transaction_payload(
    proof: Vec<u8>,
    proof_kzg_variant: u8,
    public_inputs: Vec<Vec<Fr>>,
    verifier_contract_address: &str,
    verifier_address: &str,
    params_address: &str,
) ->Result<EntryFunctionArgumentsJSON, Error> {
    let instances = public_inputs
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
            verifier_contract_address, MODULE_VERIFIER, FUNC_VERIFY_PROOF
        ),
        type_args: vec![],
        args: vec![
            ArgWithTypeJSON {
                r#type: "address".to_string(),
                value: json!(params_address),
            },
            ArgWithTypeJSON {
                r#type: "address".to_string(),
                value: json!(verifier_address),
            },
            ArgWithTypeJSON {
                r#type: "hex".to_string(),
                value: json!(instances),
            },
            ArgWithTypeJSON {
                r#type: "hex".to_string(),
                value: json!(HexEncodedBytes(proof).to_string()),
            },
            ArgWithTypeJSON {
                r#type: "u8".to_string(),
                value: json!(proof_kzg_variant),
            },
        ],
    };

    Ok(json)
}
