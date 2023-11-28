module halo2_verifier::query {
    use std::option::{Self, Option};
    use aptos_std::crypto_algebra::{Element};

    use halo2_verifier::bn254_types::{G1, Fr};
    use halo2_verifier::msm::{Self, MSM};

    struct VerifierQuery has copy, drop {
        point: Element<Fr>,
        eval: Element<Fr>,
        commitment: CommitmentReference
    }

    struct CommitmentReference has copy, drop {
        commitment: Option<Element<G1>>,
        msm: Option<MSM>
    }

    public fun new_commitment(commtiment: Element<G1>, point: Element<Fr>, eval: Element<Fr>): VerifierQuery {
        VerifierQuery {
            point, eval,
            commitment: CommitmentReference {
                commitment: option::some(commtiment),
                msm: option::none()
            }
        }
    }

    public fun new_msm(msm: MSM, point: Element<Fr>, eval: Element<Fr>): VerifierQuery {
        VerifierQuery {
            point, eval,
            commitment: CommitmentReference {
                commitment: option::none(),
                msm: option::some(msm),
            }
        }
    }

    public fun point(self: &VerifierQuery): &Element<Fr> {
        &self.point
    }

    public fun eval(self: &VerifierQuery): &Element<Fr> {
        &self.eval
    }

    public fun commitment(self: &VerifierQuery): &CommitmentReference {
        &self.commitment
    }

    public fun multiply(ref: &CommitmentReference, v: &Element<Fr>): MSM {
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
