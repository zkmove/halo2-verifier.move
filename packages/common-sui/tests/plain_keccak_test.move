// Copyright (c) zkMove Authors

#[test_only]
module halo2_common::plain_keccak_test {
    use halo2_common::plain_keccak;

    #[test]
    fun test_empty_hash() {
        let mut state = plain_keccak::new();
        assert!(
            plain_keccak::finalize(&mut state)
                == x"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        );
    }

    #[test]
    fun test_single_update_hash() {
        let mut state = plain_keccak::new();
        plain_keccak::update(&mut state, b"hello world!");
        assert!(
            plain_keccak::finalize(&mut state)
                == x"57caa176af1ac0433c5df30e8dabcd2ec1af1e92a26eced5f719b88458777cd6",
        );
    }

    #[test]
    fun test_multiple_updates_match_single_update() {
        let mut split_state = plain_keccak::new();
        plain_keccak::update(&mut split_state, b"hello ");
        plain_keccak::update(&mut split_state, b"world!");

        let mut single_state = plain_keccak::new();
        plain_keccak::update(&mut single_state, b"hello world!");

        assert!(plain_keccak::finalize(&mut split_state) == plain_keccak::finalize(&mut single_state));
    }

    #[test]
    fun test_copied_state_can_diverge() {
        let mut base = plain_keccak::new();
        plain_keccak::update(&mut base, b"Halo2-Transcript");

        let mut left = base;
        let mut right = base;
        plain_keccak::update(&mut left, vector[0]);
        plain_keccak::update(&mut right, vector[1]);

        assert!(plain_keccak::finalize(&mut left) != plain_keccak::finalize(&mut right));
    }
}
