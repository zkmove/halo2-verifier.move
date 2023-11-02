module halo2_verifier::transcript {
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::point::Point;

    struct Transcript {}

    public fun common_scalar(transcript: &mut Transcript, scalar: Scalar) {
        abort 100
    }

    public fun common_point(transcript: &mut Transcript, point: Point) {
        abort 100
    }

    public fun read_point(transcript: &mut Transcript): Point {
        abort 100
    }
    public fun read_n_point(transcript: &mut Transcript, n: u64): vector<Point> {
        abort 100
    }
    public fun read_scalar(transcript: &mut Transcript): Scalar {
        abort 100
    }
    public fun read_n_scalar(transcript: &mut Transcript, n:u64): vector<Scalar> {
        abort 100
    }

    public fun squeeze_challenge(transcript: &mut Transcript): Scalar {
        abort 100
    }
    public fun squeeze_n_challenges(transcript: &mut Transcript, n:u64): vector<Scalar> {
        abort 100
    }
}
