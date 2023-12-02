module halo2_verifier::bn254_utils {
    use std::bn254_algebra::{Fr, G1, FormatFrLsb, FormatG1Compr, G2, FormatG2Compr, FormatG1Uncompr, Fq};
    use std::option::{Self, Option};
    use std::vector;

    use aptos_std::crypto_algebra::{Self, Element};

    #[test_only]
    use aptos_std::crypto_algebra::enable_cryptography_algebra_natives;

    const S_OF_FR: u8 = 28;

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

    /// GENERATOR^t where t * 2^s + 1 = r
    /// with t odd. In other words, this
    /// is a 2^s root of unity.
    const ROOT_OF_UNITY_OF_FR: vector<u8> = x"9c7cc360d91e4fd3c82993d36dcf1532741fd33da95e8698b7186d16f5b9dd03";
    /// GENERATOR^{2^s} where t * 2^s + 1 = r with t odd. In other words, this is a t root of unity.
    const DELTA_OF_FR: vector<u8> = x"a2e933e5bb560e87253f965e8e895f5b716ec8d4aa26ec64caf0c6226e6b2209";

    /// get the 2^{k}'th root of unity (i.e. n'th root of unity)
    public fun root_of_unity(k: u8): Element<Fr> {
        let times = S_OF_FR - k;
        let i = 0;
        let result = option::destroy_some(crypto_algebra::deserialize<Fr, FormatFrLsb>(& ROOT_OF_UNITY_OF_FR));
        while (i < times) {
            result = crypto_algebra::sqr(&result);
            i = i+1;
        };
        result
    }

    public fun delta_of_fr(): Element<Fr> {
        option::destroy_some(crypto_algebra::deserialize<Fr, FormatFrLsb>(& DELTA_OF_FR))
    }

    public fun pow_u32<F>(self: &Element<F>, num: u32): Element<F> {
        let result = crypto_algebra::one<F>();
        let i = 32u8;
        // if we never meet bit with 1, don't bother to sqr.
        let meet_one = false;
        loop {
            i = i-1;
            if(meet_one) {
                result = crypto_algebra::sqr(&result);
            };
            // the i bit is 1
            if(((num >> i) & 1) == 1) {
                result = crypto_algebra::mul(&result, self);
                meet_one = true;
            };

            if (i == 0) {
                return result
            }
        }
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

    /// as halo2 use different serialzation for curve point, we need to handle that.
    public fun deserialize_g1_from_halo2(e: vector<u8>): Option<Element<G1>> {
        let last_u8 = vector::pop_back(&mut e);
        last_u8 = swap_bit(last_u8, 6, 7);
        vector::push_back(&mut e, last_u8);
        crypto_algebra::deserialize<G1, FormatG1Compr>(&e)
    }

    inline fun swap_bit(x: u8, i: u8, j: u8): u8 {
        // Move i'th to rightmost side
        let i_bit = (x>>i) & 1;
        // Move j'th to rightmost side
        let j_bit = (x>>j) & 1;
        // XOR the two bits
        let n = i_bit ^ j_bit;
        // Put the xor bit back to their original positions
        n = (n << i) | (n << j);
        // XOR 'x' with the original number so that the two sets are swapped
        x ^ n
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

    #[test(s = @std)]
    fun test_pow_u64(s: &signer) {
        enable_cryptography_algebra_natives(s);
        let f = crypto_algebra::from_u64<Fr>(3);
        let i = 1;
        let previous_pow_i = crypto_algebra::one<Fr>();
        while (i < 1000) {
            let pow_i = pow_u32(&f, i);

            assert!(crypto_algebra::eq(&pow_i, &crypto_algebra::mul(&previous_pow_i, &f)), (i as u64));
            previous_pow_i = pow_i;
            i = i+1;
        }
    }
    #[test]
    fun test_swap_bit() {
        // 0b1100_0000
        assert!(swap_bit(0xc0, 7,5) == 0x60,1);
    }
}
