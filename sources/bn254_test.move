#[test_only]
module halo2_verifier::bn254_test {
    use aptos_std::crypto_algebra;
    use aptos_std::crypto_algebra::enable_cryptography_algebra_natives;
    use aptos_std::bn254_algebra::Fr;


    #[test(s=@std)]
    public fun test_fr(s: &signer) {
        enable_cryptography_algebra_natives(s);
        let one = crypto_algebra::from_u64<Fr>(1);
        assert!(crypto_algebra::eq(&one, &crypto_algebra::one<Fr>()), 1);
    }
}
