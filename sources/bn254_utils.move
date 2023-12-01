module halo2_verifier::bn254_utils {
    use std::bn254_algebra::{Fr, G1, FormatFrLsb, FormatG1Compr, G2, FormatG2Compr, FormatG1Uncompr, Fq};
    use std::option::{Self, Option};
    use std::vector;

    use aptos_std::crypto_algebra::{Self, Element};

    #[test_only]
    use aptos_std::crypto_algebra::enable_cryptography_algebra_natives;

    const FR_S: u32 = 28;

    /// the following R, R2, R3 are derived from these of https://github.com/privacy-scaling-explorations/halo2curves/blob/a3f15e4106c8ba999ac958ff95aa543eb76adfba/src/bn256/fr.rs.
    /// `R = 2^256 mod r`
    /// `0xe0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb`
    const R: vector<u8> = x"0100000000000000000000000000000000000000000000000000000000000000";
    /// `R^2 = 2^512 mod r`
    /// `0x216d0b17f4e44a58c49833d53bb808553fe3ab1e35c59e31bb8e645ae216da7`
    const R2: vector<u8> = x"fbffff4f1c3496ac29cd609f9576fc362e4679786fa36e662fdf079ac1770a0e";
    /// `R^3 = 2^768 mod r`
    /// `0xcf8594b7fcc657c893cc664a19fcfed2a489cbe1cfbb6b85e94d8e1b4bf0040`
    const R3: vector<u8> = x"a76d21ae45e6b81be3595ce3b13afe538580bb533d83498ca5444e7fb1d01602";

    public fun S_FR(): u32 {
        FR_S
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

    fun ROOT_OF_UNITY_FR(): Element<Fr> {
        abort 100
    }

    public fun delta<G>(): Element<G> {
        abort 100
    }

    public fun pow<G>(_e: &Element<G>, _num: u64): Element<G> {
        abort 100
    }

    public fun fr_from_u512_le(bytes_lo: &vector<u8>, bytes_hi: &vector<u8>): Element<Fr> {
        from_u512_le<Fr>(bytes_lo, bytes_hi)
    }

    public fun fq_from_u512_le(bytes_lo: &vector<u8>, bytes_hi: &vector<u8>): Element<Fq> {
        from_u512_le<Fq>(bytes_lo, bytes_hi)
    }

    /// create a Field from u512 bytes in little endian.
    /// refer `Field::from_u512` of https://github.com/privacy-scaling-explorations/halo2curves/blob/a3f15e4106c8ba999ac958ff95aa543eb76adfba/src/derive/field.rs
    fun from_u512_le<F>(bytes_lo: &vector<u8>, bytes_hi: &vector<u8>): Element<F> {
        let len = vector::length(bytes_lo);
        assert!(len == 32, 100);
        let len = vector::length(bytes_hi);
        assert!(len == 32, 100);

        let lo = option::destroy_some(crypto_algebra::deserialize<F, FormatFrLsb>(bytes_lo));
        let hi = option::destroy_some(crypto_algebra::deserialize<F, FormatFrLsb>(bytes_hi));
        let r3 = option::destroy_some(crypto_algebra::deserialize<F, FormatFrLsb>(&R3));
        let r2 = option::destroy_some(crypto_algebra::deserialize<F, FormatFrLsb>(&R2));

        // r2 have an inverse, so just unwrap here
        let hi = option::destroy_some(crypto_algebra::div(&crypto_algebra::mul(&hi, &r3), &r2));
        crypto_algebra::add(&lo, &hi)
    }

    public fun invert(x: &Element<Fr>): Element<Fr> {
        std::option::extract(&mut crypto_algebra::inv<Fr>(x))
    }

    public fun serialize_fr(e: &Element<Fr>): vector<u8> {
        crypto_algebra::serialize<Fr, FormatFrLsb>(e)
    }

    public fun deserialize_fr(e: &vector<u8>): Option<Element<Fr>> {
        crypto_algebra::deserialize<Fr, FormatFrLsb>(e)
    }

    public fun serialize_g1(e: &Element<G1>): vector<u8> {
        crypto_algebra::serialize<G1, FormatG1Compr>(e)
    }

    public fun serialize_g1_uncompressed(e: &Element<G1>): vector<u8> {
        crypto_algebra::serialize<G1, FormatG1Uncompr>(e)
    }

    public fun deserialize_g1(e: &vector<u8>): Option<Element<G1>> {
        crypto_algebra::deserialize<G1, FormatG1Compr>(e)
    }

    public fun serialize_g2(e: &Element<G2>): vector<u8> {
        crypto_algebra::serialize<G2, FormatG2Compr>(e)
    }

    public fun deserialize_g2(e: &vector<u8>): Option<Element<G2>> {
        crypto_algebra::deserialize<G2, FormatG2Compr>(e)
    }


    #[test(s = @std)]
    fun test_R(s: &signer) {
        enable_cryptography_algebra_natives(s);
        let r = option::destroy_some(crypto_algebra::deserialize<Fr, FormatFrLsb>(&R));
        let r2 = option::destroy_some(crypto_algebra::deserialize<Fr, FormatFrLsb>(&R2));
        let r3 = option::destroy_some(crypto_algebra::deserialize<Fr, FormatFrLsb>(&R3));
        assert!(crypto_algebra::eq(&crypto_algebra::mul(&r2, &r), &r2), 1);
        let result = crypto_algebra::mul(&r2, &r3);
        let bytes = crypto_algebra::serialize<Fr, FormatFrLsb>(&result);
        assert!(bytes == x"4000bfb4e1d8945eb8b6fb1cbe9c482aedcf9fa164c63c897c65cc7f4b59f80c", 100);
    }

    #[test(s = @std)]
    fun test_from_u512_le(s: &signer) {
        enable_cryptography_algebra_natives(s);
        let a = vector[
            37u8, 210, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let result = fr_from_u512_le(&a, &a);
        assert!(
            crypto_algebra::serialize<Fr, FormatFrLsb>(
                &result
            ) == x"7041af4f6757e4eeb972641893ed9c8c7293d18118f87392c803b0ede9d38606",
            100
        );
    }
}
