module halo2_verifier::params {
    struct Params {}

    public fun k(params: &Params): u32 {
        abort 100
    }

    public fun n(params: &Params): u64 {
        abort 100
    }
}