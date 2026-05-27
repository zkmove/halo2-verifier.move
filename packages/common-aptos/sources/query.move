module halo2_common::query {
    use std::option::{Self, Option};
    use aptos_std::crypto_algebra::{Self, Element};

    use aptos_std::bn254_algebra::{G1, Fr};
    use halo2_common::msm::{Self, MSM};

    use std::string::String;

    use aptos_std::string_utils;
    use halo2_common::bn254_utils::{serialize_fr, serialize_g1_uncompressed};

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


    public fun format(self: &VerifierQuery): String {
        string_utils::format3(&b"{} {} {}", serialize_fr(&self.point), serialize_fr(&self.eval), format_commit_reference(&self.commitment))
    }

    fun format_commit_reference(self: &CommitmentReference): String {
        if (option::is_some(&self.commitment)) {
            string_utils::format1(&b"cm: {}", serialize_g1_uncompressed(option::borrow(&self.commitment)))
        } else {
            let m = option::borrow(&self.msm);

            string_utils::format1(&b"sm: {}", serialize_g1_uncompressed(&msm::eval(m)))
        }
    }

    public fun eq_commit_reference(self: &CommitmentReference, other: &CommitmentReference): bool {
        if (option::is_some(&self.commitment)) {
            if(option::is_none(&other.commitment)) {
                false
            }
            else {
                let e1 = option::borrow(&self.commitment);
                let e2 = option::borrow(&other.commitment);
                crypto_algebra::eq(e1, e2)
            }
        } else {
            if(option::is_none(&other.msm)) {
                false
            }
            else {
                option::borrow(&self.msm) == option::borrow(&other.msm)
            }
        }
    }
}
