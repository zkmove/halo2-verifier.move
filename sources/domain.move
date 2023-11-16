module halo2_verifier::domain {
    use halo2_verifier::rotation::Rotation;
    use halo2_verifier::scalar::Scalar;

    struct Domain {}

    public fun rotate_omega(domain: &Domain, x: &Scalar, rotation: &Rotation): Scalar {
        abort 100
    }
}