use bcs::Error;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::ff::PrimeField;

pub(crate) fn encode_field<C: CurveAffine>(f: &C::Scalar) -> Vec<u8> {
    PrimeField::to_repr(f).as_ref().to_vec()
}

pub(crate) fn decode_field<C: CurveAffine>(data: &[u8]) -> Option<C::Scalar> {
    let mut repr = <C::Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(data);
    <C::Scalar as PrimeField>::from_repr(repr).into()
}

pub(crate) fn bytes_to_affines<C: CurveAffine>(bytes: &[u8]) -> bcs::Result<Vec<C>> {
    let point_size = 32; // bn256 G1Affine compressed format size
    if !bytes.len().is_multiple_of(point_size) {
        return Err(Error::Custom(format!(
            "Commitments bytes length not multiple of point size (expected multiple of {}, got {})",
            point_size,
            bytes.len()
        )));
    }

    let mut v = Vec::with_capacity(bytes.len() / point_size);
    for (i, chunk) in bytes.chunks(point_size).enumerate() {
        let mut repr = C::Repr::default();
        repr.as_mut().copy_from_slice(chunk);
        let point = C::from_bytes(&repr)
            .into_option()
            .ok_or_else(|| Error::Custom(format!("Invalid commitment point at index {}", i)))?;
        v.push(point);
    }
    Ok(v)
}
