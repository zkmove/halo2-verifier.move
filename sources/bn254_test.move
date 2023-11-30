#[test_only]
module halo2_verifier::bn254_test {
    use aptos_std::crypto_algebra;
    use aptos_std::crypto_algebra::enable_cryptography_algebra_natives;
    use aptos_std::bn254_algebra::Fr;
    use std::bn254_algebra::{G1, FormatG1Compr, FormatG1Uncompr};
    use std::vector;


    #[test(s=@std)]
    public fun test_fr(s: &signer) {
        enable_cryptography_algebra_natives(s);
        let one = crypto_algebra::from_u64<Fr>(1);
        assert!(crypto_algebra::eq(&one, &crypto_algebra::one<Fr>()), 1);
    }

    #[test(s=@std)]
    public fun test_g1(s: &signer) {
        enable_cryptography_algebra_natives(s);
        let one = crypto_algebra::one<G1>();
        let b = crypto_algebra::serialize<G1, FormatG1Compr>(&one);
        assert!(vector::length(&b) == 32, 1);
        let b = crypto_algebra::serialize<G1, FormatG1Uncompr>(&one);
        assert!(vector::length(&b) == 64, 1);
    }
}
