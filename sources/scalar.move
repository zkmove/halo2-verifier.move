module halo2_verifier::scalar {
    struct Scalar has copy, drop,store {}
    public fun one(): Scalar {
        abort 100
    }
    public fun zero(): Scalar {
        abort 100
    }
    public fun delta(): Scalar {
        abort 100
    }
    public fun invert(x: &Scalar): Scalar {
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
    public fun pow(a: &Scalar, p: u64):Scalar {
        abort 100
    }
}
