module halo2_verifier::point {
    struct Point has copy, drop, store {}

    public fun default(): Point {
        abort 100
    }
}
