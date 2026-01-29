use bcs;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::ff::PrimeField;

#[derive(Clone)]
pub struct PublicInputs<C: CurveAffine>(pub Vec<Vec<C::Scalar>>);

impl<C: CurveAffine> PublicInputs<C>
where
    C::Scalar: PrimeField,
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let serialized: Vec<Vec<Vec<u8>>> = self
            .0
            .iter()
            .map(|column| {
                column
                    .iter()
                    .map(|scalar| scalar.to_repr().as_ref().to_vec())
                    .collect()
            })
            .collect();

        bcs::to_bytes(&serialized).expect("BCS serialization failed")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let serialized: Vec<Vec<Vec<u8>>> =
            bcs::from_bytes(bytes).map_err(|e| format!("BCS deserialization failed: {}", e))?;

        let mut columns = Vec::with_capacity(serialized.len());

        for column_bytes in serialized {
            let mut column = Vec::with_capacity(column_bytes.len());

            for scalar_bytes in column_bytes {
                let mut repr = <C::Scalar as PrimeField>::Repr::default();
                if scalar_bytes.len() != repr.as_ref().len() {
                    return Err(format!(
                        "Invalid scalar byte length: expected {}, got {}",
                        repr.as_ref().len(),
                        scalar_bytes.len()
                    ));
                }

                repr.as_mut().copy_from_slice(&scalar_bytes);

                let scalar = <C::Scalar as PrimeField>::from_repr(repr)
                    .into_option()
                    .ok_or("Invalid field element".to_string())?;

                column.push(scalar);
            }
            columns.push(column);
        }
        Ok(PublicInputs(columns))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::arithmetic::Field;
    use halo2curves::bn256::{Fr, G1Affine};
    use rand::rngs::OsRng;

    #[test]
    fn test_to_bytes_and_from_bytes() {
        let num_columns = 4;
        let num_rows = 3;
        let mut columns = (0..num_columns)
            .map(|_| Vec::with_capacity(num_rows))
            .collect::<Vec<_>>();

        for col in &mut columns {
            for _ in 0..num_rows {
                col.push(Fr::random(OsRng));
            }
        }

        let public_inputs = PublicInputs::<G1Affine>(columns);

        let bytes = public_inputs.to_bytes();

        let restored =
            PublicInputs::<G1Affine>::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(public_inputs.0.len(), restored.0.len());
        for (orig_col, rest_col) in public_inputs.0.iter().zip(restored.0.iter()) {
            assert_eq!(orig_col.len(), rest_col.len());
            for (orig_scalar, rest_scalar) in orig_col.iter().zip(rest_col.iter()) {
                assert_eq!(orig_scalar, rest_scalar);
            }
        }
    }
}
