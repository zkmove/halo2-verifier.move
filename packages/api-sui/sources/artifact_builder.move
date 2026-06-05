module verifier_api::artifact_builder;

use sui::event;
use sui::hash;
use verifier_api::input_limits;
use verifier_api::native_verifier;
use verifier_api::native_verifier::SerializedVK;
use verifier_api::serialized_params_store;
use verifier_api::serialized_params_store::SerializedParams;

const EWrongArtifactKind: u64 = 3;
const EDigestMismatch: u64 = 4;
const EEmptyArtifact: u64 = 5;
const EVerifyProof: u64 = 6;

const KIND_PARAMS: u8 = 0;
const KIND_VK: u8 = 1;
const KIND_CIRCUIT_INFO: u8 = 2;
const KIND_PROOF: u8 = 3;

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

/// Emitted by `finalize_vk` when both vk and circuit-info builders are
/// consumed together to produce a single `SerializedVK`.
public struct VkArtifactFinalized has copy, drop {
    vk_builder_id: ID,
    circuit_builder_id: ID,
    artifact_id: ID,
    vk_digest: vector<u8>,
    circuit_digest: vector<u8>,
    vk_len: u64,
    circuit_len: u64,
    owner: address,
}

public fun kind_params(): u8 { KIND_PARAMS }

public fun kind_vk(): u8 { KIND_VK }

public fun kind_circuit_info(): u8 { KIND_CIRCUIT_INFO }

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

/// Consume a vk builder and a circuit-info builder, verify both digests, and
/// emit a single `SerializedVK` that bundles vk + circuit. This is the
/// canonical chunked-upload finalization path now that vk and circuit info
/// are stored together on Sui.
public fun finalize_vk(
    vk_builder: ArtifactBuilder,
    circuit_builder: ArtifactBuilder,
    expected_vk_digest: vector<u8>,
    expected_circuit_digest: vector<u8>,
    ctx: &mut TxContext,
): SerializedVK {
    let (vk_builder_id, vk_bytes) = finish(vk_builder, KIND_VK, expected_vk_digest);
    let (circuit_builder_id, circuit_bytes) =
        finish(circuit_builder, KIND_CIRCUIT_INFO, expected_circuit_digest);

    let vk_len = vk_bytes.length();
    let circuit_len = circuit_bytes.length();
    let vk = native_verifier::new_serialized_vk(vk_bytes, circuit_bytes, ctx);
    event::emit(VkArtifactFinalized {
        vk_builder_id,
        circuit_builder_id,
        artifact_id: object::id(&vk),
        vk_digest: native_verifier::get_serialized_vk_digest(&vk),
        circuit_digest: native_verifier::get_serialized_circuit_digest(&vk),
        vk_len,
        circuit_len,
        owner: ctx.sender(),
    });
    vk
}

public fun verify_proof_from_builder(
    params: &SerializedParams,
    vk: &SerializedVK,
    proof_builder: ArtifactBuilder,
    expected_proof_digest: vector<u8>,
    public_inputs: vector<u8>,
    kzg_variant: u8,
    k_present: bool,
    k: u32,
): bool {
    let (_, proof) = finish(proof_builder, KIND_PROOF, expected_proof_digest);
    native_verifier::verify_proof_bcs(
        params,
        vk,
        public_inputs,
        proof,
        kzg_variant,
        k_present,
        k,
    )
}

entry fun verify_proof_builder(
    params: &SerializedParams,
    vk: &SerializedVK,
    proof_builder: ArtifactBuilder,
    expected_proof_digest: vector<u8>,
    public_inputs: vector<u8>,
    kzg_variant: u8,
    k_present: bool,
    k: u32,
) {
    assert!(
        verify_proof_from_builder(
            params,
            vk,
            proof_builder,
            expected_proof_digest,
            public_inputs,
            kzg_variant,
            k_present,
            k,
        ),
        EVerifyProof,
    )
}

/// Chunked-publish into a shared `SerializedParams` store: consume the
/// params builder, validate the digest, and overwrite the bytes on
/// `store`. Auth check (`store.publisher == sender`) happens inside
/// `serialized_params_store::publish_serialized_params`. Emits both
/// `ArtifactFinalized` (builder telemetry) and `SerializedParamsPublished`
/// (publish event from the store module).
entry fun finalize_params_to_store(
    store: &mut SerializedParams,
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &TxContext,
) {
    let (builder_id, bytes) = finish(builder, KIND_PARAMS, expected_digest);
    let total_len = bytes.length();
    let digest = hash::blake2b256(&bytes);
    serialized_params_store::publish_serialized_params(store, bytes, ctx);
    event::emit(ArtifactFinalized {
        builder_id,
        artifact_id: object::id(store),
        kind: KIND_PARAMS,
        total_len,
        digest,
        owner: serialized_params_store::publisher(store),
    })
}

entry fun finalize_params_to_sender(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_transfer(finalize_params(builder, expected_digest, ctx), ctx.sender())
}

entry fun finalize_vk_to_sender(
    vk_builder: ArtifactBuilder,
    circuit_builder: ArtifactBuilder,
    expected_vk_digest: vector<u8>,
    expected_circuit_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_transfer(
        finalize_vk(
            vk_builder,
            circuit_builder,
            expected_vk_digest,
            expected_circuit_digest,
            ctx,
        ),
        ctx.sender(),
    )
}

entry fun finalize_params_and_freeze(
    builder: ArtifactBuilder,
    expected_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_freeze_object(finalize_params(builder, expected_digest, ctx))
}

entry fun finalize_vk_and_freeze(
    vk_builder: ArtifactBuilder,
    circuit_builder: ArtifactBuilder,
    expected_vk_digest: vector<u8>,
    expected_circuit_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::public_freeze_object(
        finalize_vk(
            vk_builder,
            circuit_builder,
            expected_vk_digest,
            expected_circuit_digest,
            ctx,
        ),
    )
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
