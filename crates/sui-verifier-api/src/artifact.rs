use anyhow::{anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;

// Mirrors verifier_api::input_limits constants in packages/api-sui/sources/input_limits.move.
pub const MAX_PARAMS_BYTES: usize = 240 * 1024;
pub const MAX_VK_BYTES: usize = 240 * 1024;
pub const MAX_CIRCUIT_INFO_BYTES: usize = 240 * 1024;
pub const MAX_PROOF_BYTES: usize = 96 * 1024;
pub const MAX_PUBLIC_INPUTS_BYTES: usize = 16 * 1024;
pub const MAX_CHUNK_SIZE: usize = 15 * 1024;

pub const DEFAULT_CHUNK_SIZE: usize = MAX_CHUNK_SIZE;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Digest32(pub [u8; 32]);

impl Digest32 {
    pub fn from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() == 32, "digest must be exactly 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn to_json_value(self) -> serde_json::Value {
        json!(self.0)
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Digest32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

pub fn digest32(bytes: &[u8]) -> Digest32 {
    let hash = blake2b_simd::Params::new().hash_length(32).hash(bytes);
    Digest32::from_slice(hash.as_bytes()).expect("blake2b digest length is fixed")
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ChunkPlan {
    pub chunk_size: usize,
    pub total_len: usize,
    pub digest: Digest32,
    pub chunks: Vec<Vec<u8>>,
}

impl ChunkPlan {
    pub fn new(bytes: Vec<u8>, chunk_size: Option<usize>) -> anyhow::Result<Self> {
        let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
        ensure!(chunk_size > 0, "chunk size must be positive");
        ensure!(
            chunk_size <= MAX_CHUNK_SIZE,
            "chunk size {chunk_size} exceeds max chunk size {MAX_CHUNK_SIZE}"
        );
        ensure!(!bytes.is_empty(), "artifact bytes must not be empty");
        let total_len = bytes.len();
        let digest = digest32(&bytes);
        let chunks = bytes
            .chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();
        if chunks.is_empty() {
            return Err(anyhow!("artifact bytes must produce at least one chunk"));
        }
        Ok(Self {
            chunk_size,
            total_len,
            digest,
            chunks,
        })
    }
}

pub fn ensure_artifact_size(label: &str, bytes_len: usize, max_bytes: usize) -> anyhow::Result<()> {
    ensure!(!label.is_empty(), "artifact label must not be empty");
    ensure!(
        bytes_len <= max_bytes,
        "{label} artifact is {bytes_len} bytes, exceeds max size {max_bytes}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_and_digest_are_stable() {
        let plan = ChunkPlan::new(vec![1, 2, 3, 4, 5], Some(2)).unwrap();
        assert_eq!(plan.total_len, 5);
        assert_eq!(plan.chunks, vec![vec![1, 2], vec![3, 4], vec![5]]);
        assert_eq!(plan.digest.to_vec().len(), 32);
    }

    #[test]
    fn rejects_chunk_size_above_chain_limit() {
        let err = ChunkPlan::new(vec![1, 2, 3], Some(MAX_CHUNK_SIZE + 1)).unwrap_err();
        assert!(err.to_string().contains("exceeds max chunk size"));
    }

    #[test]
    fn artifact_size_check_reports_label_and_limit() {
        let err = ensure_artifact_size("proof", MAX_PROOF_BYTES + 1, MAX_PROOF_BYTES).unwrap_err();
        assert!(err.to_string().contains("proof artifact"));
        assert!(err.to_string().contains(&MAX_PROOF_BYTES.to_string()));
    }
}
