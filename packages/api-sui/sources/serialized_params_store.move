module verifier_api::serialized_params_store;

use sui::dynamic_field as field;
use sui::event;
use sui::hash;
use verifier_api::input_limits;

const EUnsupportedVersion: u64 = 0;
const EEmptyParams: u64 = 1;
const EParamsNotFound: u64 = 2;
const VERSION: u16 = 1;

public struct SerializedParamsStore has key {
    id: UID,
}

public struct ParamsOwner has copy, drop, store {
    addr: address,
}

public struct SerializedParamsRecord has drop, store {
    version: u16,
    params_bytes: vector<u8>,
    params_digest: vector<u8>,
}

public struct SerializedParams has key, store {
    id: UID,
    version: u16,
    params_bytes: vector<u8>,
    params_digest: vector<u8>,
}

public struct SerializedParamsPublished has copy, drop {
    publisher: address,
    version: u16,
    digest: vector<u8>,
    size: u64,
}

public fun artifact_version(): u16 { VERSION }

public fun max_params_bytes(): u64 { input_limits::max_params_bytes() }

public fun new_serialized_params_store(ctx: &mut TxContext): SerializedParamsStore {
    SerializedParamsStore { id: object::new(ctx) }
}

entry fun create_serialized_params_store(ctx: &mut TxContext) {
    transfer::share_object(new_serialized_params_store(ctx))
}

fun params_key(addr: address): ParamsOwner {
    ParamsOwner { addr }
}

fun new_serialized_params_record(params_bytes: vector<u8>): SerializedParamsRecord {
    assert!(params_bytes.length() > 0, EEmptyParams);
    input_limits::assert_params_size(&params_bytes);
    let params_digest = hash::blake2b256(&params_bytes);
    SerializedParamsRecord {
        version: VERSION,
        params_bytes,
        params_digest,
    }
}

public fun new_serialized_params(
    params_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedParams {
    let SerializedParamsRecord { version, params_bytes, params_digest } =
        new_serialized_params_record(params_bytes);
    SerializedParams {
        id: object::new(ctx),
        version,
        params_bytes,
        params_digest,
    }
}

public entry fun publish_serialized_params(
    store: &mut SerializedParamsStore,
    publisher: address,
    params_bytes: vector<u8>,
) {
    let record = new_serialized_params_record(params_bytes);
    let version = record.version;
    let digest = record.params_digest;
    let size = record.params_bytes.length();
    field::replace<ParamsOwner, SerializedParamsRecord, SerializedParamsRecord>(
        &mut store.id,
        params_key(publisher),
        record,
    );
    event::emit(SerializedParamsPublished { publisher, version, digest, size });
}

public fun contains_serialized_params(store: &SerializedParamsStore, addr: address): bool {
    field::exists_with_type<ParamsOwner, SerializedParamsRecord>(&store.id, params_key(addr))
}

fun borrow_record(store: &SerializedParamsStore, addr: address): &SerializedParamsRecord {
    assert!(contains_serialized_params(store, addr), EParamsNotFound);
    field::borrow<ParamsOwner, SerializedParamsRecord>(&store.id, params_key(addr))
}

public fun get_serialized_params(store: &SerializedParamsStore, addr: address): vector<u8> {
    borrow_record(store, addr).params_bytes
}

public fun get_serialized_params_digest(store: &SerializedParamsStore, addr: address): vector<u8> {
    borrow_record(store, addr).params_digest
}

public fun get_serialized_params_version(store: &SerializedParamsStore, addr: address): u16 {
    borrow_record(store, addr).version
}

public fun assert_supported_version_for(store: &SerializedParamsStore, addr: address) {
    assert!(borrow_record(store, addr).version == VERSION, EUnsupportedVersion)
}

public fun version(params: &SerializedParams): u16 {
    params.version
}

public fun assert_supported_version(params: &SerializedParams) {
    assert!(params.version == VERSION, EUnsupportedVersion)
}

public fun params_bytes(params: &SerializedParams): vector<u8> {
    params.params_bytes
}

public fun params_digest(params: &SerializedParams): vector<u8> {
    params.params_digest
}

public fun destroy(params: SerializedParams) {
    let SerializedParams { id, version: _, params_bytes: _, params_digest: _ } = params;
    object::delete(id)
}

#[test_only]
public fun destroy_store(store: SerializedParamsStore) {
    let SerializedParamsStore { id } = store;
    object::delete(id)
}
