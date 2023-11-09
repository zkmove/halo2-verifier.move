module halo2_verifier::plonk_proof {
    use halo2_verifier::protocol::{Protocol, transcript_initial_state, evaluations_len};
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::transcript::{Transcript};
    use std::vector;
    use halo2_verifier::protocol;
    use halo2_verifier::transcript;
    use halo2_verifier::point::Point;

    const INVALID_INSTANCES: u64 = 100;

    struct PlonkProof {}


    public fun read(protocol: &Protocol, instances: vector<vector<vector<Scalar>>>, transcript: Transcript): PlonkProof {
        let scalar = transcript_initial_state(protocol);
        transcript::common_scalar(&mut transcript, scalar);
        // check_instances(&instances, protocol::num_instance(protocol));
        // TODO: read committed_instances
        let num_proof = vector::length(&instances);
        // - read advice commitments and challenges
        let (witness_commitments, challenges) = read_commitment_and_challenges(
            &mut transcript,
            &protocol::num_witness(protocol, num_proof),
            &protocol::num_challenge(protocol),
        );

        // - read commitments of H(x) which is (h_1,h_2,.., h_d)
        let quotients = transcript::read_n_point(&mut transcript, protocol::num_chunks_of_quotient(protocol, num_proof));
        // - eval at point: z
        let z = transcript::squeeze_challenge(&mut transcript);
        let evaluation_len = evaluations_len(protocol, num_proof);
        // read evaluations of polys at z.
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
        num_challenge_in_phase: &vector<u64>,
    ): (vector<Point>, vector<Scalar>) {
        let phase_len = vector::length(num_in_phase);
        let i = 0;
        let commitments = vector[];
        let challenges = vector[];
        while (i < phase_len) {
            vector::append(&mut commitments, transcript::read_n_point(transcript, *vector::borrow(num_in_phase, i)));
            vector::append(
                &mut challenges,
                transcript::squeeze_n_challenges(transcript, *vector::borrow(num_challenge_in_phase, i))
            );
            i = i + 1;
        };
        (commitments, challenges)
    }
}
