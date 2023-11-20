module halo2_verifier::pcs {
    use halo2_verifier::params::Params;
    use halo2_verifier::protocol::Protocol;
    use halo2_verifier::transcript::Transcript;

    struct Proof has copy, drop {}

    public fun read_proof(params: &Params, protocol: &Protocol, transcript: &mut Transcript): Proof {
        abort 100
    }
}
