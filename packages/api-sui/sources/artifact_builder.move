module verifier_api::artifact_builder;

use sui::event;
use sui::hash;
use verifier_api::input_limits;
use verifier_api::native_verifier;
use verifier_api::native_verifier::{SerializedCircuit, SerializedProof, SerializedVK};
use verifier_api::serialized_public_inputs;
use verifier_api::serialized_public_inputs::SerializedPublicInputs;
use verifier_api::serialized_params_store;
use verifier_api::serialized_params_store::SerializedParams;

const EWrongArtifactKind: u64 = 3;
const EDigestMismatch: u64 = 4;
const EEmptyArtifact: u64 = 5;

const KIND_PARAMS: u8 = 0;
const KIND_VK: u8 = 1;
const KIND_CIRCUIT_INFO: u8 = 2;
const KIND_PUBLIC_INPUTS: u8 = 3;
const KIND_PROOF: u8 = 4;

public struct ArtifactBuilder has key, store {
    id: UID,
    kind: u8,
    bytes: vector<u8>,
    max_bytes: u64,
}

public struct BuilderCreated has copy, drop {
    builder_id: ID,
    kind: u8,
    max_bytes: u64,
    owner: address,
}

public struct ChunkAppended has copy, drop {
    builder_id: ID,
    kind: u8,
    chunk_len: u64,
    total_len: u64,
}

public struct ArtifactFinalized has copy, drop {
    builder_id: ID,
    artifact_id: ID,
    kind: u8,
    total_len: u64,
    digest: vector<u8>,
    owner: address,
}

public fun kind_params(): u8 { KIND_PARAMS }

public fun kind_vk(): u8 { KIND_VK }

public fun kind_circuit_info(): u8 { KIND_CIRCUIT_INFO }

public fun kind_public_inputs(): u8 { KIND_PUBLIC_INPUTS }

public fun kind_proof(): u8 { KIND_PROOF }

public fun max_chunk_bytes(): u64 { input_limits::max_chunk_bytes() }

public fun new_params_builder(ctx: &mut TxContext): ArtifactBuilder {
    new_builder(KIND_PARAMS, input_limits::max_params_bytes(), ctx)
}

public fun new_vk_builder(ctx: &mut TxContext): ArtifactBuilder {
    new_builder(KIND_VK, input_limits::max_vk_bytes(), ctx)
}

public fun new_circuit_info_builder(ctx: &mut TxContext): ArtifactBuilder {
    new_builder(KIND_CIRCUIT_INFO, input_limits::max_circuit_info_bytes(), ctx)
}

public fun new_public_inputs_builder(ctx: &mut TxContext): ArtifactBuilder {
    new_builder(KIND_PUBLIC_INPUTS, input_limits::max_public_inputs_bytes(), ctx)
}

public fun new_proof_builder(ctx: &mut TxContext): ArtifactBuilder {
    new_builder(KIND_PROOF, input_limits::max_proof_bytes(), ctx)
}

entry fun publish_params_builder(ctx: &mut TxContext) {
    transfer::transfer(new_params_builder(ctx), ctx.sender())
}

entry fun publish_vk_builder(ctx: &mut TxContext) {
    transfer::transfer(new_vk_builder(ctx), ctx.sender())
}

entry fun publish_circuit_info_builder(ctx: &mut TxContext) {
    transfer::transfer(new_circuit_info_builder(ctx), ctx.sender())
}

entry fun publish_public_inputs_builder(ctx: &mut TxContext) {
    transfer::transfer(new_public_inputs_builder(ctx), ctx.sender())
}

entry fun publish_proof_builder(ctx: &mut TxContext) {
    transfer::transfer(new_proof_builder(ctx), ctx.sender())
}

public fun append_chunk(builder: &mut ArtifactBuilder, chunk: vector<u8>) {
    let chunk_len = chunk.length();
    input_limits::assert_chunk_size(&chunk);
    input_limits::assert_total_size(builder.bytes.length() + chunk.length(), builder.max_bytes);
    builder.bytes.append(chunk);
    event::emit(ChunkAppended {
        builder_id: object::uid_to_inner(&builder.id),
        kind: builder.kind,
        chunk_len,
        total_len: builder.bytes.length(),
    })
}

public fun finalize_params(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
): SerializedParams {
    let (builder_id, bytes) = finish(builder, KIND_PARAMS, expected_digest);
    let params = serialized_params_store::new_serialized_params(bytes, ctx);
    emit_finalized(
        builder_id,
        object::id(&params),
        KIND_PARAMS,
        serialized_params_store::params_digest(&params),
        serialized_params_store::params_bytes(&params).length(),
        ctx,
    );
    params
}

public fun finalize_vk(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
): SerializedVK {
    let (builder_id, bytes) = finish(builder, KIND_VK, expected_digest);
    let vk = native_verifier::new_serialized_vk(bytes, ctx);
    emit_finalized(
        builder_id,
        object::id(&vk),
        KIND_VK,
        native_verifier::get_serialized_vk_digest(&vk),
        native_verifier::get_serialized_vk(&vk).length(),
        ctx,
    );
    vk
}

public fun finalize_circuit_info(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
): SerializedCircuit {
    let (builder_id, bytes) = finish(builder, KIND_CIRCUIT_INFO, expected_digest);
    let circuit = native_verifier::new_serialized_circuit(bytes, ctx);
    emit_finalized(
        builder_id,
        object::id(&circuit),
        KIND_CIRCUIT_INFO,
        native_verifier::get_serialized_circuit_digest(&circuit),
        native_verifier::get_serialized_circuit(&circuit).length(),
        ctx,
    );
    circuit
}

public fun finalize_public_inputs(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
): SerializedPublicInputs {
    let (builder_id, bytes) = finish(builder, KIND_PUBLIC_INPUTS, expected_digest);
    let public_inputs = serialized_public_inputs::new_serialized_public_inputs_from_bcs_bytes(bytes, ctx);
    emit_finalized(
        builder_id,
        object::id(&public_inputs),
        KIND_PUBLIC_INPUTS,
        serialized_public_inputs::public_inputs_digest(&public_inputs),
        serialized_public_inputs::public_inputs_bytes(&public_inputs).length(),
        ctx,
    );
    public_inputs
}

public fun finalize_proof(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
): SerializedProof {
    let (builder_id, bytes) = finish(builder, KIND_PROOF, expected_digest);
    let proof = native_verifier::new_serialized_proof(bytes, ctx);
    emit_finalized(
        builder_id,
        object::id(&proof),
        KIND_PROOF,
        native_verifier::get_serialized_proof_digest(&proof),
        native_verifier::get_serialized_proof(&proof).length(),
        ctx,
    );
    proof
}

entry fun finalize_params_to_sender(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_transfer(finalize_params(builder, expected_digest, ctx), ctx.sender())
}

entry fun finalize_vk_to_sender(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_transfer(finalize_vk(builder, expected_digest, ctx), ctx.sender())
}

entry fun finalize_circuit_info_to_sender(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_transfer(finalize_circuit_info(builder, expected_digest, ctx), ctx.sender())
}

entry fun finalize_public_inputs_to_sender(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_transfer(finalize_public_inputs(builder, expected_digest, ctx), ctx.sender())
}

entry fun finalize_proof_to_sender(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_transfer(finalize_proof(builder, expected_digest, ctx), ctx.sender())
}

entry fun finalize_params_and_freeze(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_freeze_object(finalize_params(builder, expected_digest, ctx))
}

entry fun finalize_vk_and_freeze(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_freeze_object(finalize_vk(builder, expected_digest, ctx))
}

entry fun finalize_circuit_info_and_freeze(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_freeze_object(finalize_circuit_info(builder, expected_digest, ctx))
}

entry fun finalize_public_inputs_and_freeze(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_freeze_object(finalize_public_inputs(builder, expected_digest, ctx))
}

entry fun finalize_proof_and_freeze(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_freeze_object(finalize_proof(builder, expected_digest, ctx))
}

public fun builder_kind(builder: &ArtifactBuilder): u8 {
    builder.kind
}

public fun builder_len(builder: &ArtifactBuilder): u64 {
    builder.bytes.length()
}

public fun destroy(builder: ArtifactBuilder) {
    let ArtifactBuilder { id, kind: _, bytes: _, max_bytes: _ } = builder;
    object::delete(id)
}

fun new_builder(kind: u8, max_bytes: u64, ctx: &mut TxContext): ArtifactBuilder {
    let builder = ArtifactBuilder {
        id: object::new(ctx),
        kind,
        bytes: vector[],
        max_bytes,
    };
    event::emit(BuilderCreated {
        builder_id: object::id(&builder),
        kind,
        max_bytes,
        owner: ctx.sender(),
    });
    builder
}

fun finish(
    builder: ArtifactBuilder,
    expected_kind: u8,
    expected_digest: vector<u8>,
): (ID, vector<u8>) {
    let ArtifactBuilder { id, kind, bytes, max_bytes: _ } = builder;
    let builder_id = object::uid_to_inner(&id);
    object::delete(id);
    assert!(kind == expected_kind, EWrongArtifactKind);
    assert!(!bytes.is_empty(), EEmptyArtifact);
    assert!(hash::blake2b256(&bytes) == expected_digest, EDigestMismatch);
    (builder_id, bytes)
}

fun emit_finalized(
    builder_id: ID,
    artifact_id: ID,
    kind: u8,
    digest: vector<u8>,
    total_len: u64,
    ctx: &TxContext,
) {
    event::emit(ArtifactFinalized {
        builder_id,
        artifact_id,
        kind,
        total_len,
        digest,
        owner: ctx.sender(),
    })
}
