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

    public fun read_scalar(transcript: &mut Transcript): Scalar {
        abort 100
    }
}
