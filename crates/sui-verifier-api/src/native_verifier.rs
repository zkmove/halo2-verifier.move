use crate::{compact_json, SuiMoveCallJSON, FUNC_VERIFY_WITH_ARTIFACTS, MODULE_HALO2_KZG};
use anyhow::Error;
use halo2_backend::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::ff::PrimeField;
use serde_json::json;

/// Build a Sui Move call descriptor for `sui::halo2_kzg::verify_with_artifacts`.
#[allow(clippy::too_many_arguments)]
pub fn build_verify_proof_native_transaction_payload<C>(
    proof: Vec<u8>,
    proof_kzg_variant: u8,
    public_inputs: Vec<Vec<C::Scalar>>,
    halo2_kzg_package: &str,
    params_object_id: &str,
    vk_object_id: &str,
    circuit_object_id: &str,
    k: Option<u32>,
) -> anyhow::Result<SuiMoveCallJSON, Error>
where
    C: CurveAffine,
{
    let public_inputs = public_inputs
        .iter()
        .map(|instance| {
            instance
                .iter()
                .map(|scalar| {
                    scalar
                        .to_repr()
                        .as_ref()
                        .iter()
                        .map(|byte| json!(*byte))
                        .collect::<Vec<_>>()
                })
                .map(serde_json::Value::Array)
                .collect::<Vec<_>>()
        })
        .map(serde_json::Value::Array)
        .collect::<Vec<_>>();
    let public_inputs = serde_json::Value::Array(public_inputs);
    let proof = serde_json::Value::Array(proof.into_iter().map(|byte| json!(byte)).collect());
    let k_present = k.is_some();
    let k = k.unwrap_or_default();

    let args = vec![
        json!(params_object_id),
        json!(vk_object_id),
        json!(circuit_object_id),
        public_inputs,
        proof,
        json!(proof_kzg_variant),
        json!(k_present),
        json!(k),
    ];

    let mut cli_args = vec![
        "--package".to_string(),
        halo2_kzg_package.to_string(),
        "--module".to_string(),
        MODULE_HALO2_KZG.to_string(),
        "--function".to_string(),
        FUNC_VERIFY_WITH_ARTIFACTS.to_string(),
        "--args".to_string(),
    ];
    for arg in &args {
        match arg {
            serde_json::Value::String(value) => cli_args.push(value.clone()),
            _ => cli_args.push(compact_json(arg)?),
        }
    }

    Ok(SuiMoveCallJSON {
        package: halo2_kzg_package.to_string(),
        module: MODULE_HALO2_KZG.to_string(),
        function: FUNC_VERIFY_WITH_ARTIFACTS.to_string(),
        type_args: vec![],
        args,
        cli_args,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_HALO2_KZG_PACKAGE;
    use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};

    #[test]
    fn builds_verify_with_artifacts_payload() {
        let payload = build_verify_proof_native_transaction_payload::<G1Affine>(
            vec![1, 2, 3],
            0,
            vec![vec![Fr::from(7)]],
            DEFAULT_HALO2_KZG_PACKAGE,
            "0xparams",
            "0xvk",
            "0xcircuit",
            Some(12),
        )
        .unwrap();

        assert_eq!(payload.package, "0x2");
        assert_eq!(payload.module, "halo2_kzg");
        assert_eq!(payload.function, "verify_with_artifacts");
        assert_eq!(payload.args.len(), 8);
        assert_eq!(payload.args[0], json!("0xparams"));
        assert_eq!(payload.args[1], json!("0xvk"));
        assert_eq!(payload.args[2], json!("0xcircuit"));
        assert_eq!(payload.args[5], json!(0));
        assert_eq!(payload.args[6], json!(true));
        assert_eq!(payload.args[7], json!(12));
        assert_eq!(
            payload.cli_args[..7],
            [
                "--package",
                "0x2",
                "--module",
                "halo2_kzg",
                "--function",
                "verify_with_artifacts",
                "--args"
            ]
        );
    }
}
