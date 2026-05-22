// Copyright (c) zkMove Authors

module halo2_common::query {
    use sui::bn254;
    use sui::group_ops::{Self, Element};
    use halo2_common::msm::{Self, MSM};

    public struct VerifierQuery has copy, drop {
        point: Element<bn254::Scalar>,
        eval: Element<bn254::Scalar>,
        commitment: CommitmentReference,
    }

    public struct CommitmentReference has copy, drop {
        commitment: Option<Element<bn254::G1>>,
        msm: Option<MSM>,
    }

    public fun new_commitment(
        commitment: Element<bn254::G1>,
        point: Element<bn254::Scalar>,
        eval: Element<bn254::Scalar>,
    ): VerifierQuery {
        VerifierQuery {
            point,
            eval,
            commitment: CommitmentReference {
                commitment: option::some(commitment),
                msm: option::none(),
            },
        }
    }

    public fun new_msm(
        msm: MSM,
        point: Element<bn254::Scalar>,
        eval: Element<bn254::Scalar>,
    ): VerifierQuery {
        VerifierQuery {
            point,
            eval,
            commitment: CommitmentReference {
                commitment: option::none(),
                msm: option::some(msm),
            },
        }
    }

    public fun point(self: &VerifierQuery): &Element<bn254::Scalar> {
        &self.point
    }

    public fun eval(self: &VerifierQuery): &Element<bn254::Scalar> {
        &self.eval
    }

    public fun commitment(self: &VerifierQuery): &CommitmentReference {
        &self.commitment
    }

    public fun multiply(ref: &CommitmentReference, v: &Element<bn254::Scalar>): MSM {
        if (option::is_some(&ref.commitment)) {
            let c = option::borrow(&ref.commitment);
            let mut m = msm::empty_msm();
            msm::append_term(&mut m, *v, *c);
            m
        } else {
            let mut m = *option::borrow(&ref.msm);
            msm::scale(&mut m, v);
            m
        }
    }

    public fun eq_commit_reference(self: &CommitmentReference, other: &CommitmentReference): bool {
        if (option::is_some(&self.commitment)) {
            if (option::is_none(&other.commitment)) {
                false
            } else {
                let e1 = option::borrow(&self.commitment);
                let e2 = option::borrow(&other.commitment);
                group_ops::equal(e1, e2)
            }
        } else {
            if (option::is_none(&other.msm)) {
                false
            } else {
                msm::eq(option::borrow(&self.msm), option::borrow(&other.msm))
            }
        }
    }
}
