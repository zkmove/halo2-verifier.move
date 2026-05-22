// Copyright (c) zkMove Authors

module halo2_common::vec_utils {
    const ZERO: u64 = 0;

    public fun repeat<T: copy>(x: T, times: u64): vector<T> {
        let mut result = vector[];
        assert!(times != 0, ZERO);

        let mut i = 1;
        while (i < times) {
            vector::push_back(&mut result, x);
            i = i + 1;
        };
        vector::push_back(&mut result, x);
        result
    }
}
