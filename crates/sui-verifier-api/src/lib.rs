use core::fmt;
use serde::{Deserialize, Serialize};

pub mod native_verifier;

pub const DEFAULT_HALO2_KZG_PACKAGE: &str = "0x2";
pub const MODULE_HALO2_KZG: &str = "halo2_kzg";
pub const FUNC_VERIFY_WITH_ARTIFACTS: &str = "verify_with_artifacts";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexEncodedBytes(pub Vec<u8>);

impl fmt::Display for HexEncodedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SuiMoveCallJSON {
    pub package: String,
    pub module: String,
    pub function: String,
    pub type_args: Vec<String>,
    pub args: Vec<serde_json::Value>,
    pub cli_args: Vec<String>,
}

pub(crate) fn compact_json(value: &serde_json::Value) -> anyhow::Result<String> {
    serde_json::to_string(value).map_err(Into::into)
}
