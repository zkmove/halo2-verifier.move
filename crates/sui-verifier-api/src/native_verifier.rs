use crate::{
    compact_json, SuiMoveCallJSON, FUNC_PUBLISH_PARAMS_NATIVE, FUNC_PUBLISH_VK_NATIVE,
    FUNC_VERIFY_PROOF_NATIVE, MODULE_PARAMS_NATIVE, MODULE_VERIFIER_NATIVE,
};
use anyhow::Error;
use halo2_backend::arithmetic::CurveAffine;
use halo2_backend::helpers::{SerdeCurveAffine, SerdeFormat, SerdePrimeField};
use halo2_backend::plonk::VerifyingKey;
use halo2_backend::poly::commitment::Params;
use halo2_backend::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::ff::FromUniformBytes;
use halo2_proofs::plonk::Circuit;
use halo2_verifier::circuit::generate_serialized_circuit;
use halo2_verifier::params::serialize_kzg_params;
use halo2_verifier::public_inputs::PublicInputs;
use serde_json::json;

fn bytes_arg(bytes: Vec<u8>) -> serde_json::Value {
    serde_json::Value::Array(bytes.into_iter().map(|byte| json!(byte)).collect())
}

fn move_call(
    package: &str,
    module: &str,
    function: &str,
    args: Vec<serde_json::Value>,
) -> anyhow::Result<SuiMoveCallJSON, Error> {
    let mut cli_args = vec![
        "--package".to_string(),
        package.to_string(),
        "--module".to_string(),
        module.to_string(),
        "--function".to_string(),
        function.to_string(),
        "--args".to_string(),
    ];
    for arg in &args {
        match arg {
            serde_json::Value::String(value) => cli_args.push(value.clone()),
            _ => cli_args.push(compact_json(arg)?),
        }
    }

    Ok(SuiMoveCallJSON {
        package: package.to_string(),
        module: module.to_string(),
        function: function.to_string(),
        type_args: vec![],
        args,
        cli_args,
    })
}

/// Build publish serialized KZG params transaction payload for Sui.
///
/// Targets `serialized_params_store::publish_serialized_params(store, params_bytes)`.
/// `store` must be an existing shared `SerializedParams` object created by
/// the publisher via `create_serialized_params_store`; the on-chain entry
/// requires the transaction sender to equal `store.publisher`.
pub fn build_publish_params_native_transaction_payload(
    params: &ParamsKZG<Bn256>,
    verifier_api_package: &str,
    params_store_object_id: &str,
) -> anyhow::Result<SuiMoveCallJSON, Error> {
    let params_bytes = serialize_kzg_params(&params.verifier_params())
        .map_err(|e| Error::msg(format!("serialize kzg params failed: {}", e)))?;

    build_publish_params_native_transaction_payload_from_bytes(
        params_bytes,
        verifier_api_package,
        params_store_object_id,
    )
}

/// Build publish serialized KZG params transaction payload from already serialized bytes.
///
/// See [`build_publish_params_native_transaction_payload`] for the on-chain
/// signature this targets.
pub fn build_publish_params_native_transaction_payload_from_bytes(
    params_bytes: Vec<u8>,
    verifier_api_package: &str,
    params_store_object_id: &str,
) -> anyhow::Result<SuiMoveCallJSON, Error> {
    move_call(
        verifier_api_package,
        MODULE_PARAMS_NATIVE,
        FUNC_PUBLISH_PARAMS_NATIVE,
        vec![json!(params_store_object_id), bytes_arg(params_bytes)],
    )
}

/// Build publish serialized VK transaction payload for Sui.
///
/// Sui stores the verification key and circuit info together in one object,
/// so this builds the single `native_verifier::publish_serialized_vk` call.
pub fn build_publish_vk_native_transaction_payload<C, P, ConcreteCircuit>(
    vk: &VerifyingKey<C>,
    params: &P,
    circuit: &ConcreteCircuit,
    verifier_api_package: &str,
) -> anyhow::Result<SuiMoveCallJSON, Error>
where
    C: SerdeCurveAffine,
    P: Params<C>,
    ConcreteCircuit: Circuit<C::Scalar>,
    C::Scalar: SerdePrimeField + FromUniformBytes<64>,
    C::ScalarExt: FromUniformBytes<64>,
{
    let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);
    let circuit_bytes = generate_serialized_circuit(params, circuit)
        .map_err(|e| Error::msg(format!("generate serialized circuit failed: {}", e)))?;

    build_publish_vk_native_transaction_payload_from_bytes(
        vk_bytes,
        circuit_bytes,
        verifier_api_package,
    )
}

/// Build publish serialized VK transaction payload from already serialized bytes.
pub fn build_publish_vk_native_transaction_payload_from_bytes(
    vk_bytes: Vec<u8>,
    circuit_bytes: Vec<u8>,
    verifier_api_package: &str,
) -> anyhow::Result<SuiMoveCallJSON, Error> {
    move_call(
        verifier_api_package,
        MODULE_VERIFIER_NATIVE,
        FUNC_PUBLISH_VK_NATIVE,
        vec![bytes_arg(vk_bytes), bytes_arg(circuit_bytes)],
    )
}

/// Build verify proof transaction payload for `verifier_api::native_verifier::verify`.
#[allow(clippy::too_many_arguments)]
pub fn build_verify_proof_native_transaction_payload<C>(
    proof: Vec<u8>,
    proof_kzg_variant: u8,
    public_inputs: Vec<Vec<C::Scalar>>,
    verifier_api_package: &str,
    params_object_id: &str,
    vk_object_id: &str,
    k: Option<u32>,
) -> anyhow::Result<SuiMoveCallJSON, Error>
where
    C: CurveAffine,
{
    let public_inputs = bytes_arg(PublicInputs::<C>(public_inputs).to_bytes());
    let proof = bytes_arg(proof);
    let k_present = k.is_some();
    let k = k.unwrap_or_default();

    let args = vec![
        json!(params_object_id),
        json!(vk_object_id),
        public_inputs,
        proof,
        json!(proof_kzg_variant),
        json!(k_present),
        json!(k),
    ];

    move_call(
        verifier_api_package,
        MODULE_VERIFIER_NATIVE,
        FUNC_VERIFY_PROOF_NATIVE,
        args,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};

    #[test]
    fn builds_publish_params_payload() {
        let payload = build_publish_params_native_transaction_payload_from_bytes(
            vec![1, 2, 3],
            "0xapi",
            "0xstore",
        )
        .unwrap();

        assert_eq!(payload.package, "0xapi");
        assert_eq!(payload.module, "serialized_params_store");
        assert_eq!(payload.function, "publish_serialized_params");
        assert_eq!(payload.args, vec![json!("0xstore"), json!([1, 2, 3])]);
        assert_eq!(
            payload.cli_args,
            [
                "--package",
                "0xapi",
                "--module",
                "serialized_params_store",
                "--function",
                "publish_serialized_params",
                "--args",
                "0xstore",
                "[1,2,3]"
            ]
        );
    }

    #[test]
    fn builds_publish_vk_payload() {
        let payload =
            build_publish_vk_native_transaction_payload_from_bytes(vec![1, 2], vec![3, 4], "0xapi")
                .unwrap();

        assert_eq!(payload.package, "0xapi");
        assert_eq!(payload.module, "native_verifier");
        assert_eq!(payload.function, "publish_serialized_vk");
        assert_eq!(payload.args, vec![json!([1, 2]), json!([3, 4])]);
        assert_eq!(
            payload.cli_args,
            [
                "--package",
                "0xapi",
                "--module",
                "native_verifier",
                "--function",
                "publish_serialized_vk",
                "--args",
                "[1,2]",
                "[3,4]"
            ]
        );
    }

    #[test]
    fn builds_verify_payload_for_api_sui_native_verifier() {
        let payload = build_verify_proof_native_transaction_payload::<G1Affine>(
            vec![1, 2, 3],
            0,
            vec![vec![Fr::from(7)]],
            "0xapi",
            "0xparams",
            "0xvk",
            Some(12),
        )
        .unwrap();

        assert_eq!(payload.package, "0xapi");
        assert_eq!(payload.module, "native_verifier");
        assert_eq!(payload.function, "verify");
        assert_eq!(payload.args.len(), 7);
        assert_eq!(payload.args[0], json!("0xparams"));
        assert_eq!(payload.args[1], json!("0xvk"));
        assert_eq!(
            payload.args[2],
            bytes_arg(PublicInputs::<G1Affine>(vec![vec![Fr::from(7)]]).to_bytes())
        );
        assert_eq!(payload.args[3], json!([1, 2, 3]));
        assert_eq!(payload.args[4], json!(0));
        assert_eq!(payload.args[5], json!(true));
        assert_eq!(payload.args[6], json!(12));
        assert_eq!(
            payload.cli_args[..7],
            [
                "--package",
                "0xapi",
                "--module",
                "native_verifier",
                "--function",
                "verify",
                "--args"
            ]
        );
    }
}
