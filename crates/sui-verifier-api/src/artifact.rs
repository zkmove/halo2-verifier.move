use anyhow::{anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const DEFAULT_CHUNK_SIZE: usize = 15_360;

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
}
