// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{error, fmt};

/// Typed verifier errors for callers that must not depend on display strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The proof is well-formed but does not verify against the supplied artifacts.
    InvalidProof(String),
    /// One of the serialized inputs cannot be decoded or violates the verifier ABI.
    MalformedInput(String),
    /// The inputs describe a verifier configuration this implementation does not support.
    UnsupportedConfig(String),
    /// An unexpected verifier error that should not be reachable from normal malformed input.
    Internal(String),
}

impl VerifyError {
    pub fn invalid_proof(message: impl Into<String>) -> Self {
        Self::InvalidProof(message.into())
    }

    pub fn malformed_input(message: impl Into<String>) -> Self {
        Self::MalformedInput(message.into())
    }

    pub fn unsupported_config(message: impl Into<String>) -> Self {
        Self::UnsupportedConfig(message.into())
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::InvalidProof(message) => write!(f, "invalid proof: {message}"),
            VerifyError::MalformedInput(message) => write!(f, "malformed input: {message}"),
            VerifyError::UnsupportedConfig(message) => write!(f, "unsupported config: {message}"),
            VerifyError::Internal(message) => write!(f, "internal verifier error: {message}"),
        }
    }
}

impl error::Error for VerifyError {}
