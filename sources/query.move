module halo2_verifier::query {
    use std::option::{Self, Option};

    use halo2_verifier::bn254_types::G1;
    use halo2_verifier::msm::{Self, MSM};
    use halo2_verifier::point::Point;
    use halo2_verifier::scalar::Scalar;

    struct VerifierQuery has copy, drop {
        point: Scalar,
        eval: Scalar,
        commitment: CommitmentReference
    }

    struct CommitmentReference has copy, drop {
        commitment: Option<Point<G1>>,
        msm: Option<MSM>
    }

    public fun new_commitment(commtiment: Point<G1>, point: Scalar, eval: Scalar): VerifierQuery {
        VerifierQuery {
            point, eval,
            commitment: CommitmentReference {
                commitment: option::some(commtiment),
                msm: option::none()
            }
        }
    }

    public fun new_msm(msm: MSM, point: Scalar, eval: Scalar): VerifierQuery {
        VerifierQuery {
            point, eval,
            commitment: CommitmentReference {
                commitment: option::none(),
                msm: option::some(msm),
            }
        }
    }

    public fun point(self: &VerifierQuery): &Scalar {
        &self.point
    }

    public fun eval(self: &VerifierQuery): &Scalar {
        &self.eval
    }

    public fun commitment(self: &VerifierQuery): &CommitmentReference {
        &self.commitment
    }

    public fun multiply(ref: &CommitmentReference, v: &Scalar): MSM {
        if (option::is_some(&ref.commitment)) {
            let c = option::borrow(&ref.commitment);
            let m = msm::empty_msm();
            msm::append_term(&mut m, *v, *c);
            m
        } else {
            let m = *option::borrow(&ref.msm);
            msm::scale(&mut m, v);
            m
        }
    }
}
