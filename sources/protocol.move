module halo2_verifier::protocol {
    use halo2_verifier::Domain::Domain;
    use halo2_verifier::scalar::Scalar;

    struct Protocol {
        domain: Domain,
    }

    public fun transcript_initial_state(protocol: &Protocol): Scalar {
        abort 100
    }
}
