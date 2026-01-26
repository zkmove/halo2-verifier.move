use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG, SerdeFormat};

pub fn serialize_kzg_params(params: &ParamsKZG<Bn256>) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    params
        .write_custom(&mut buf, SerdeFormat::RawBytes)
        .map_err(|e| format!("Failed to serialize KZG parameters: {}", e))?;
    Ok(buf)
}

pub fn deserialize_kzg_params(data: &[u8]) -> Result<ParamsKZG<Bn256>, String> {
    let mut cursor = std::io::Cursor::new(data);
    ParamsKZG::<Bn256>::read_custom(&mut cursor, SerdeFormat::RawBytes)
        .map_err(|e| format!("Failed to deserialize KZG parameters: {}", e))
}

/// Load KZG parameters embedded at compile time.
pub fn load_default_kzg_params() -> Result<ParamsKZG<Bn256>, String> {
    const PARAMS_BYTES: &[u8] = include_bytes!("params/kzg_bn254_12.srs");
    deserialize_kzg_params(PARAMS_BYTES)
}
