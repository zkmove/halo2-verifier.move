module halo2_verifier::vec_utils {
    use std::vector;
    use std::error;
    const ZERO: u64 = 0;
    public fun repeat<T: copy>(x: T, times: u64): vector<T> {
        let result = vector::empty();
        assert!(times != 0,error::invalid_argument(ZERO));

        let i = 1;
        while (i < times) {
            vector::push_back(&mut result, x);
            i = i+1;
        };
        vector::push_back(&mut result, x);
        result
    }

    #[test]
    fun test_repeat() {
        let r = repeat(1u8, 10);
        assert!(vector::length(&r) == 10, 1);
        assert!(*vector::borrow(&r, 9) == 1u8, 2);
        assert!(*vector::borrow(&r, 0) == 1u8, 2);
    }

}
