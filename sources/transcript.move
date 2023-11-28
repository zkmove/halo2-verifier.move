module halo2_verifier::transcript {
    use aptos_std::crypto_algebra::{Element};
    use halo2_verifier::bn254_types::{G1, Fr};

    struct Transcript has copy, drop {}

    /// create a transcript_read
    public fun read(_bytes: vector<u8>): Transcript {
        abort 100
    }

    public fun common_scalar(_transcript: &mut Transcript, _scalar: Element<Fr>) {
        abort 100
    }

    public fun common_point(_transcript: &mut Transcript, _point: Element<G1>) {
        abort 100
    }

    public fun read_point(_transcript: &mut Transcript): Element<G1> {
        abort 100
    }

    public fun read_n_point(_transcript: &mut Transcript, _n: u64): vector<Element<G1>> {
        abort 100
    }

    public fun read_scalar(_transcript: &mut Transcript): Element<Fr> {
        abort 100
    }

    public fun read_n_scalar(_transcript: &mut Transcript, _n: u64): vector<Element<Fr>> {
        abort 100
    }

    public fun squeeze_challenge(_transcript: &mut Transcript): Element<Fr> {
        abort 100
    }

    public fun squeeze_n_challenges(_transcript: &mut Transcript, _n: u64): vector<Element<Fr>> {
        abort 100
    }
}
