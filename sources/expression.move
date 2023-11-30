module halo2_verifier::expression {
    use std::vector;
    use aptos_std::crypto_algebra::{Element};
    use aptos_std::bn254_algebra::{Fr};
    use halo2_verifier::multivariate_poly::{Self, MultiVariatePoly};

    struct Expression {
        poly: MultiVariatePoly,
    }

    public fun evaluate(
        self: &Expression,
        advice_evals: &vector<Element<Fr>>,

        fixed_evals: &vector<Element<Fr>>,
        instance_evals: &vector<Element<Fr>>,
        challenges: &vector<Element<Fr>>
    ): Element<Fr> {
        let advice_len = vector::length(advice_evals);
        let fixed_len = vector::length(fixed_evals);
        let instance_len = vector::length(instance_evals);
        let challenge_len = vector::length(challenges);

        let advice_range = advice_len;
        let fixed_range = advice_range+fixed_len;
        let instance_range = fixed_range + instance_len;
        let challenge_range = instance_range + challenge_len;


        multivariate_poly::evaluate(&self.poly, |idx| {
            if (idx < advice_range) {
                vector::borrow(advice_evals, idx)
            } else if (idx < fixed_range) {
                vector::borrow(fixed_evals, idx - advice_range)
            } else if (idx < instance_range) {
                vector::borrow(instance_evals, idx - fixed_range)
            } else if (idx < challenge_range) {
                vector::borrow(challenges, idx - instance_range)
            } else {
                abort 100
            }
        })
    }

}
