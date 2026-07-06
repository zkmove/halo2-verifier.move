use crate::artifact::{
    ensure_artifact_size, ChunkPlan, Digest32, MAX_CHUNK_SIZE, MAX_CIRCUIT_INFO_BYTES,
    MAX_PARAMS_BYTES, MAX_PROOF_BYTES, MAX_VK_BYTES,
};
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use sui_ptb_helper::{
    move_call, Argument, MoveTarget, ProgrammableTransactionBuilder, SuiPtbClient,
};

const MODULE_ARTIFACT_BUILDER: &str = "artifact_builder";
const FUNC_NEW_PARAMS_BUILDER: &str = "new_params_builder";
const FUNC_NEW_VK_BUILDER: &str = "new_vk_builder";
const FUNC_NEW_CIRCUIT_INFO_BUILDER: &str = "new_circuit_info_builder";
const FUNC_NEW_PROOF_BUILDER: &str = "new_proof_builder";
const FUNC_APPEND_CHUNK: &str = "append_chunk";
const FUNC_FINALIZE_PARAMS: &str = "finalize_params";
const FUNC_FINALIZE_VK: &str = "finalize_vk";

const TYPE_SUFFIX_ARTIFACT_BUILDER: &str = "::artifact_builder::ArtifactBuilder";
const TYPE_SUFFIX_SERIALIZED_PARAMS: &str = "::serialized_params_store::SerializedParams";
const TYPE_SUFFIX_SERIALIZED_VK: &str = "::native_verifier::SerializedVK";

#[derive(Clone, Debug)]
pub struct StagedProof {
    pub proof_builder: Argument,
    pub proof_digest: Digest32,
    pub proof_bytes: usize,
    pub chunk_count: usize,
}

#[derive(Clone, Debug)]
pub struct StagedVerifierArtifacts {
    pub params_object: Argument,
    pub vk_object: Argument,
    pub params_digest: Digest32,
    pub vk_digest: Digest32,
    pub circuit_digest: Digest32,
    pub params_bytes: usize,
    pub vk_bytes: usize,
    pub circuit_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofUploadReceipt {
    pub proof_builder_id: String,
    pub proof_digest: Vec<u8>,
    pub proof_bytes: usize,
    pub tx_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierArtifactsUploadReceipt {
    pub params_object_id: String,
    pub vk_object_id: String,
    pub params_digest: Vec<u8>,
    pub vk_digest: Vec<u8>,
    pub circuit_digest: Vec<u8>,
    pub tx_digest: String,
}

pub struct ArtifactPtb<'a> {
    ptb: &'a mut ProgrammableTransactionBuilder,
    verifier_api_package: String,
}

impl<'a> ArtifactPtb<'a> {
    pub fn new(
        ptb: &'a mut ProgrammableTransactionBuilder,
        verifier_api_package: impl Into<String>,
    ) -> Self {
        Self {
            ptb,
            verifier_api_package: verifier_api_package.into(),
        }
    }

    pub fn params_builder(&mut self) -> anyhow::Result<Argument> {
        self.artifact_call(FUNC_NEW_PARAMS_BUILDER, vec![])
    }

    pub fn vk_builder(&mut self) -> anyhow::Result<Argument> {
        self.artifact_call(FUNC_NEW_VK_BUILDER, vec![])
    }

    pub fn circuit_info_builder(&mut self) -> anyhow::Result<Argument> {
        self.artifact_call(FUNC_NEW_CIRCUIT_INFO_BUILDER, vec![])
    }

    pub fn proof_builder(&mut self) -> anyhow::Result<Argument> {
        self.artifact_call(FUNC_NEW_PROOF_BUILDER, vec![])
    }

    pub fn append_chunk(
        &mut self,
        artifact_builder: Argument,
        chunk: Vec<u8>,
    ) -> anyhow::Result<()> {
        ensure!(
            chunk.len() <= MAX_CHUNK_SIZE,
            "chunk is {} bytes, exceeds max chunk size {}",
            chunk.len(),
            MAX_CHUNK_SIZE
        );
        let chunk = self.ptb.pure(chunk)?;
        let _ = self.artifact_call(FUNC_APPEND_CHUNK, vec![artifact_builder, chunk])?;
        Ok(())
    }

    pub fn append_chunks(
        &mut self,
        artifact_builder: Argument,
        chunks: impl IntoIterator<Item = Vec<u8>>,
    ) -> anyhow::Result<usize> {
        let mut count = 0;
        for chunk in chunks {
            self.append_chunk(artifact_builder, chunk)?;
            count += 1;
        }
        ensure!(count > 0, "chunk list must not be empty");
        Ok(count)
    }

    pub fn finalize_params(
        &mut self,
        params_builder: Argument,
        expected_digest: Digest32,
    ) -> anyhow::Result<Argument> {
        let expected_digest = self.ptb.pure(expected_digest.to_vec())?;
        self.artifact_call(FUNC_FINALIZE_PARAMS, vec![params_builder, expected_digest])
    }

    pub fn finalize_vk(
        &mut self,
        vk_builder: Argument,
        circuit_builder: Argument,
        expected_vk_digest: Digest32,
        expected_circuit_digest: Digest32,
    ) -> anyhow::Result<Argument> {
        let expected_vk_digest = self.ptb.pure(expected_vk_digest.to_vec())?;
        let expected_circuit_digest = self.ptb.pure(expected_circuit_digest.to_vec())?;
        self.artifact_call(
            FUNC_FINALIZE_VK,
            vec![
                vk_builder,
                circuit_builder,
                expected_vk_digest,
                expected_circuit_digest,
            ],
        )
    }

    pub fn stage_proof(
        &mut self,
        proof: Vec<u8>,
        chunk_size: Option<usize>,
    ) -> anyhow::Result<StagedProof> {
        ensure_artifact_size("proof", proof.len(), MAX_PROOF_BYTES)?;
        let plan = ChunkPlan::new(proof, chunk_size)?;
        let proof_builder = self.proof_builder()?;
        let chunk_count = self.append_chunks(proof_builder, plan.chunks)?;
        Ok(StagedProof {
            proof_builder,
            proof_digest: plan.digest,
            proof_bytes: plan.total_len,
            chunk_count,
        })
    }

    pub fn stage_verifier_artifacts(
        &mut self,
        params: Vec<u8>,
        vk: Vec<u8>,
        circuit: Vec<u8>,
        chunk_size: Option<usize>,
    ) -> anyhow::Result<StagedVerifierArtifacts> {
        ensure_artifact_size("params", params.len(), MAX_PARAMS_BYTES)?;
        ensure_artifact_size("vk", vk.len(), MAX_VK_BYTES)?;
        ensure_artifact_size("circuit info", circuit.len(), MAX_CIRCUIT_INFO_BYTES)?;

        let params = ChunkPlan::new(params, chunk_size)
            .context("failed to chunk serialized params artifact")?;
        let vk =
            ChunkPlan::new(vk, chunk_size).context("failed to chunk serialized vk artifact")?;
        let circuit = ChunkPlan::new(circuit, chunk_size)
            .context("failed to chunk serialized circuit info artifact")?;

        let params_builder = self.params_builder()?;
        let vk_builder = self.vk_builder()?;
        let circuit_builder = self.circuit_info_builder()?;
        self.append_chunks(params_builder, params.chunks)?;
        self.append_chunks(vk_builder, vk.chunks)?;
        self.append_chunks(circuit_builder, circuit.chunks)?;

        let params_object = self.finalize_params(params_builder, params.digest)?;
        let vk_object = self.finalize_vk(vk_builder, circuit_builder, vk.digest, circuit.digest)?;

        Ok(StagedVerifierArtifacts {
            params_object,
            vk_object,
            params_digest: params.digest,
            vk_digest: vk.digest,
            circuit_digest: circuit.digest,
            params_bytes: params.total_len,
            vk_bytes: vk.total_len,
            circuit_bytes: circuit.total_len,
        })
    }

    fn artifact_call(&mut self, function: &str, args: Vec<Argument>) -> anyhow::Result<Argument> {
        Ok(move_call(
            self.ptb,
            MoveTarget::new(
                &self.verifier_api_package,
                MODULE_ARTIFACT_BUILDER,
                function,
            )?,
            args,
        ))
    }
}

pub struct ArtifactUploader<'a> {
    client: &'a SuiPtbClient,
    verifier_api_package: String,
}

impl<'a> ArtifactUploader<'a> {
    pub fn new(client: &'a SuiPtbClient, verifier_api_package: impl Into<String>) -> Self {
        Self {
            client,
            verifier_api_package: verifier_api_package.into(),
        }
    }

    pub async fn upload_proof(
        &self,
        proof: Vec<u8>,
        chunk_size: Option<usize>,
    ) -> anyhow::Result<ProofUploadReceipt> {
        let mut ptb = ProgrammableTransactionBuilder::new();
        let staged = {
            let mut artifact_ptb = ArtifactPtb::new(&mut ptb, &self.verifier_api_package);
            artifact_ptb.stage_proof(proof, chunk_size)?
        };
        ptb.transfer_arg(self.client.sender(), staged.proof_builder);
        let response = self.client.execute(ptb.finish()).await?;
        let proof_builder_id = response.created_object_id(TYPE_SUFFIX_ARTIFACT_BUILDER)?;

        Ok(ProofUploadReceipt {
            proof_builder_id,
            proof_digest: staged.proof_digest.to_vec(),
            proof_bytes: staged.proof_bytes,
            tx_digest: response.digest,
        })
    }

    pub async fn upload_verifier_artifacts(
        &self,
        params: Vec<u8>,
        vk: Vec<u8>,
        circuit: Vec<u8>,
        chunk_size: Option<usize>,
    ) -> anyhow::Result<VerifierArtifactsUploadReceipt> {
        let mut ptb = ProgrammableTransactionBuilder::new();
        let staged = {
            let mut artifact_ptb = ArtifactPtb::new(&mut ptb, &self.verifier_api_package);
            artifact_ptb.stage_verifier_artifacts(params, vk, circuit, chunk_size)?
        };
        ptb.transfer_args(
            self.client.sender(),
            vec![staged.params_object, staged.vk_object],
        );
        let response = self.client.execute(ptb.finish()).await?;
        let params_object_id = response.created_object_id(TYPE_SUFFIX_SERIALIZED_PARAMS)?;
        let vk_object_id = response.created_object_id(TYPE_SUFFIX_SERIALIZED_VK)?;

        Ok(VerifierArtifactsUploadReceipt {
            params_object_id,
            vk_object_id,
            params_digest: staged.params_digest.to_vec(),
            vk_digest: staged.vk_digest.to_vec(),
            circuit_digest: staged.circuit_digest.to_vec(),
            tx_digest: response.digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::digest32;

    #[test]
    fn stage_proof_builds_builder_and_chunk_commands() {
        let mut ptb = ProgrammableTransactionBuilder::new();
        let staged = {
            let mut artifact_ptb = ArtifactPtb::new(&mut ptb, "0x2");
            artifact_ptb
                .stage_proof(vec![1, 2, 3, 4, 5], Some(2))
                .unwrap()
        };

        let tx = ptb.finish();
        assert_eq!(staged.proof_digest, digest32(&[1, 2, 3, 4, 5]));
        assert_eq!(staged.proof_bytes, 5);
        assert_eq!(staged.chunk_count, 3);
        assert_eq!(tx.commands.len(), 4);
        let commands = format!("{:?}", tx.commands);
        assert!(commands.contains(FUNC_NEW_PROOF_BUILDER));
        assert!(commands.matches(FUNC_APPEND_CHUNK).count() == 3);
    }

    #[test]
    fn stage_verifier_artifacts_builds_single_ptb_sequence() {
        let mut ptb = ProgrammableTransactionBuilder::new();
        let staged = {
            let mut artifact_ptb = ArtifactPtb::new(&mut ptb, "0x2");
            artifact_ptb
                .stage_verifier_artifacts(vec![1, 2, 3], vec![4, 5], vec![6, 7, 8], Some(2))
                .unwrap()
        };

        let tx = ptb.finish();
        assert_eq!(staged.params_digest, digest32(&[1, 2, 3]));
        assert_eq!(staged.vk_digest, digest32(&[4, 5]));
        assert_eq!(staged.circuit_digest, digest32(&[6, 7, 8]));
        assert_eq!(tx.commands.len(), 10);
        let commands = format!("{:?}", tx.commands);
        assert!(commands.contains(FUNC_NEW_PARAMS_BUILDER));
        assert!(commands.contains(FUNC_NEW_VK_BUILDER));
        assert!(commands.contains(FUNC_NEW_CIRCUIT_INFO_BUILDER));
        assert!(commands.contains(FUNC_FINALIZE_PARAMS));
        assert!(commands.contains(FUNC_FINALIZE_VK));
    }

    #[test]
    fn append_chunk_rejects_oversized_chunk_before_building_command() {
        let mut ptb = ProgrammableTransactionBuilder::new();
        let err = {
            let mut artifact_ptb = ArtifactPtb::new(&mut ptb, "0x2");
            let proof_builder = artifact_ptb.proof_builder().unwrap();
            artifact_ptb
                .append_chunk(proof_builder, vec![0; MAX_CHUNK_SIZE + 1])
                .unwrap_err()
        };

        let tx = ptb.finish();
        assert!(err.to_string().contains("exceeds max chunk size"));
        assert_eq!(tx.commands.len(), 1);
        assert!(!format!("{:?}", tx.commands).contains(FUNC_APPEND_CHUNK));
    }

    #[test]
    fn stage_proof_rejects_oversized_proof_before_building_commands() {
        let mut ptb = ProgrammableTransactionBuilder::new();
        let err = {
            let mut artifact_ptb = ArtifactPtb::new(&mut ptb, "0x2");
            artifact_ptb
                .stage_proof(vec![0; MAX_PROOF_BYTES + 1], Some(2))
                .unwrap_err()
        };

        assert!(err.to_string().contains("proof artifact"));
        assert!(ptb.finish().commands.is_empty());
    }

    #[test]
    fn stage_verifier_artifacts_rejects_oversized_params_before_building_commands() {
        let mut ptb = ProgrammableTransactionBuilder::new();
        let err = {
            let mut artifact_ptb = ArtifactPtb::new(&mut ptb, "0x2");
            artifact_ptb
                .stage_verifier_artifacts(vec![0; MAX_PARAMS_BYTES + 1], vec![1], vec![2], Some(2))
                .unwrap_err()
        };

        assert!(err.to_string().contains("params artifact"));
        assert!(ptb.finish().commands.is_empty());
    }
}
