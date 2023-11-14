module halo2_verifier::scalar {
    struct Scalar {}
    public fun one(): Scalar {
        abort 100
    }
    public fun square(x: &Scalar): Scalar {
        abort 100
    }
    public fun mul(a: &Scalar, b: &Scalar): Scalar {
        abort 100
    }
    public fun add(a: &Scalar, b: &Scalar): Scalar {
        abort 100
    }
    public fun sub(a: &Scalar, b: &Scalar): Scalar {
        abort 100
    }
    public fun neg(a: &Scalar): Scalar {
        abort 100
    }
}
