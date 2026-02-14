use core::fmt;
use serde::{Deserialize, Serialize};

/// native verifier related APIs
pub mod native_verifier;
/// move verifier related APIs
pub mod verifier;

/// constants share by move verifier and native verifier
pub const MODULE_PARAMS: &str = "params_store";

/// constants for move verifier
pub const MODULE_VERIFIER: &str = "verifier";
pub const FUNC_PUBLISH_PARAMS: &str = "create";
pub const FUNC_PUBLISH_CIRCUIT: &str = "publish_circuit";
pub const FUNC_VERIFY_PROOF: &str = "verify";

/// constants for native verifier
pub const MODULE_VERIFIER_NATIVE: &str = "native_verifier";
pub const FUNC_PUBLISH_PARAMS_NATIVE: &str = "publish_serialized_params";
pub const FUNC_PUBLISH_VK_NATIVE: &str = "publish_serialized_vk";
pub const FUNC_PUBLISH_CIRCUIT_NATIVE: &str = "publish_serialized_circuit";
pub const FUNC_VERIFY_PROOF_NATIVE: &str = "verify";


#[derive(Deserialize, Serialize)]
/// JSON file format for function arguments.
pub struct ArgWithTypeJSON {
    pub r#type: String,
    pub value: serde_json::Value,
}

#[derive(Deserialize, Serialize)]
pub struct ArgWithNameAndTypeJSON {
    pub name: String,
    pub r#type: String,
    pub value: serde_json::Value,
}

#[derive(Deserialize, Serialize)]
/// JSON file format for entry function arguments.
pub struct EntryFunctionArgumentsJSON {
    pub function_id: String,
    pub type_args: Vec<String>,
    pub args: Vec<ArgWithTypeJSON>,
}

/// Hex encoded bytes to allow for having bytes represented in JSON
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexEncodedBytes(pub Vec<u8>);

impl fmt::Display for HexEncodedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))?;
        Ok(())
    }
}
