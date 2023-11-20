module halo2_verifier::domain {
    use halo2_verifier::rotation::Rotation;
    use halo2_verifier::scalar::Scalar;

    struct Domain has store {}

    public fun rotate_omega(domain: &Domain, x: &Scalar, rotation: &Rotation): Scalar {
        abort 100
    }
    public fun quotient_poly_degree(domain: &Domain): u64 {
        abort 100
    }
}