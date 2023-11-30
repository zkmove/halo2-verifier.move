module halo2_verifier::bn254_utils {
    use aptos_std::crypto_algebra::{Self, Element};
    use std::bn254_algebra::{Fr, G1, FormatFrLsb, FormatG1Compr, G2, FormatG2Compr, FormatG1Uncompr};
    use std::option::Option;

    const FR_SERIALIZED_LEN: u64 = 32;
    const G_COMPRESSED_LEN: u64 = 32;
    const FR_S: u32 = 28;


    public inline fun g_compressed_len(): u64 {
        G_COMPRESSED_LEN
    }
    public inline fun fr_serialized_len(): u64 {
        FR_SERIALIZED_LEN
    }

    public fun S_FR(): u32 {
        FR_S
    }
    fun ROOT_OF_UNITY_FR(): Element<Fr> {
        abort 100
    }

    public fun root_of_unity(k: u32): Element<Fr> {
        let times = FR_S - k;
        let i = 0;
        let result = ROOT_OF_UNITY_FR();
        while (i < times) {
            result = crypto_algebra::sqr(&result);
        };
        result
    }

    public fun delta<G>(): Element<G> {
        abort 100
    }

    public fun pow<G>(_e: &Element<G>, _num: u64): Element<G> {
        abort 100
    }

    public fun invert(x: &Element<Fr>): Element<Fr> {
        std::option::extract(&mut crypto_algebra::inv<Fr>(x))
    }

    public fun serialize_fr(e: &Element<Fr>): vector<u8>{
        crypto_algebra::serialize<Fr, FormatFrLsb>(e)
    }
    public fun deserialize_fr(e: &vector<u8>): Option<Element<Fr>>{
        crypto_algebra::deserialize<Fr, FormatFrLsb>(e)
    }

    public fun serialize_g1(e: &Element<G1>): vector<u8>{
        crypto_algebra::serialize<G1, FormatG1Compr>(e)
    }
    public fun serialize_g1_uncompressed(e: &Element<G1>): vector<u8>{
        crypto_algebra::serialize<G1, FormatG1Uncompr>(e)
    }
    public fun deserialize_g1(e: &vector<u8>): Option<Element<G1>>{
        crypto_algebra::deserialize<G1, FormatG1Compr>(e)
    }

    public fun serialize_g2(e: &Element<G2>): vector<u8>{

        crypto_algebra::serialize<G2, FormatG2Compr>(e)
    }
    public fun deserialize_g2(e: &vector<u8>): Option<Element<G2>>{
        crypto_algebra::deserialize<G2, FormatG2Compr>(e)
    }

}
