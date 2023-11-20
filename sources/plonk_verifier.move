module halo2_verifier::plonk_verifier {
    use halo2_verifier::params::Params;
    use halo2_verifier::plonk_proof;
    use halo2_verifier::protocol::Protocol;
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::transcript;
    use halo2_verifier::verify_key::VerifyingKey;

    public fun verify(
        params: &Params,
        vk: &VerifyingKey,
        protocol: &Protocol,
        instances: vector<vector<vector<Scalar>>>,
        proof: vector<u8>
    ): bool {
        let transcript = transcript::read(proof);
        let plonk_proof = plonk_proof::read(params, vk, protocol, instances, transcript);

        // todo: add verify code
        false
    }
}
