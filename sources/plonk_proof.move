module halo2_verifier::plonk_proof {
    use halo2_verifier::protocol::{Protocol, transcript_initial_state};
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::transcript::{Transcript, common_scalar};
    use std::vector;
    use halo2_verifier::protocol;
    use halo2_verifier::transcript;
    use halo2_verifier::point::Point;

    const INVALID_INSTANCES: u64 = 100;

    struct PlonkProof {}


    public fun read(protocol: &Protocol, instances: vector<vector<Scalar>>, transcript: Transcript): PlonkProof {
        let scalar = transcript_initial_state(protocol);
        common_scalar(&mut transcript, scalar);
        // check_instances(&instances, protocol::num_instance(protocol));
        // TODO: read committed_instances

        // TODO: 2. read advice commitments and challenges


        let (advice_column_commitments, challenges) = read_commitment_and_challenges(
            &mut transcript,
            protocol::num_advice_in_phase(protocol),
            protocol::num_challenge_in_phase(protocol)
        );

        let quotients = transcript::read_n_point(&mut transcript, protocol::num_chunks_of_quotient(protocol));
        let z = transcript::squeeze_challenge(&mut transcript);
        // TODO: calculate the eval len.
        let evaluation_len = 0;
        let evaluations = transcript::read_n_scalar(&mut transcript, evaluation_len);
        abort 100
    }

    fun check_instances(instances: &vector<vector<Scalar>>, num: u64) {
        let i = 0;
        let len = vector::length(instances);
        while (i < len) {
            assert!(vector::length(vector::borrow(instances, i)) == num, INVALID_INSTANCES);
            i = i + 1;
        }
    }

    fun read_commitment_and_challenges(
        transcript: &mut Transcript,
        num_in_phase: &vector<u64>,
        num_challenge_in_phase: &vector<u64>
    ): (vector<vector<Point>>, vector<vector<Scalar>>) {
        let phase_len = vector::length(num_in_phase);
        let i = 0;
        let commitments = vector[];
        let challenges = vector[];
        while (i < phase_len) {
            vector::push_back(&mut commitments, transcript::read_n_point(transcript, *vector::borrow(num_in_phase, i)));
            vector::push_back(
                &mut challenges,
                transcript::squeeze_n_challenges(transcript, *vector::borrow(num_challenge_in_phase, i))
            );
            i = i + 1;
        };
        (commitments, challenges)
    }
}
