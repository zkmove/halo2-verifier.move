module halo2_verifier::protocol {
    use halo2_verifier::Domain::Domain;
    use halo2_verifier::scalar::Scalar;

    struct Protocol {
        domain: Domain,
        //num_instance: u64,

        /// Number of witness polynomials in each phase.
        num_advice_in_phase: vector<u64>,
        advice_index: vector<u64>,
        advice_phase: vector<u8>,
        /// Number of challenges to squeeze from transcript after each phase.
        num_challenge_in_phase: vector<u64>,
        challenge_index: vector<u64>,
        challenge_phase: vector<u8>,
    }

    public fun transcript_initial_state(protocol: &Protocol): Scalar {
        abort 100
    }

    public fun num_instance(protocol: &Protocol): u64 {
        abort 100
    }
    public fun num_witness(protocol: &Protocol): u64 {
        abort 100
    }
    public fun num_challenges(protocol: &Protocol): u64 {
        abort 100
    }
    public fun num_instance_columns(protocol: &Protocol): u64 {
        abort 100
    }
    public fun num_advice_columns(protocol: &Protocol): u64 {
        abort 100
    }

    // return advice num of each phase
    public fun num_advice_in_phase(protocol: &Protocol): &vector<u64> {
        abort 100
    }
    // return advice's index in each phase
    public fun advice_index(protocol: &Protocol): &vector<u64> {
        abort 100
    }
    // return advice's phase
    public fun advice_phase(protocol: &Protocol): &vector<u8> {
        abort 100
    }

    public fun num_challenge_in_phase(protocol: &Protocol): &vector<u64> {
        abort 100
    }
    public fun challenge_index(protocol: &Protocol): &vector<u64> {
        abort 100
    }
    public fun challenge_phase(protocol: &Protocol): &vector<u8> {
        abort 100
    }

    public fun num_chunks_of_quotient(protocol: &Protocol): u64 {
        abort 100
    }
}
