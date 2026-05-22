// Copyright (c) zkMove Authors

/// Keccak256 transcript used by the Halo2 verifier.
module halo2_verifier::transcript {
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::bn254_utils;
    use halo2_common::plain_keccak::{Self, PlainKeccak};

    const U256_BYTE_LEN: u64 = 32;

    /// Prefix to a prover's message soliciting a challenge.
    const KECCAK256_PREFIX_CHALLENGE: u8 = 0;
    /// First prefix to a prover's message soliciting a challenge.
    /// This prefix is not included in the growing state.
    const KECCAK256_PREFIX_CHALLENGE_LO: u8 = 10;
    /// Second prefix to a prover's message soliciting a challenge.
    /// This prefix is not included in the growing state.
    const KECCAK256_PREFIX_CHALLENGE_HI: u8 = 11;
    /// Prefix to a prover's message containing a curve point.
    const KECCAK256_PREFIX_POINT: u8 = 1;
    /// Prefix to a prover's message containing a scalar.
    const KECCAK256_PREFIX_SCALAR: u8 = 2;

    public struct Read has copy, drop {
        buf: vector<u8>,
        offset: u64,
    }

    public struct Transcript has copy, drop {
        state: PlainKeccak,
        reader: Read,
    }

    /// Initializes a transcript with a proof input buffer.
    ///
    /// Sui reserves `init` for module initializers, so the Sui verifier uses
    /// `new` for this constructor.
    public fun new(input: vector<u8>): Transcript {
        let mut state = plain_keccak::new();
        plain_keccak::update(&mut state, b"Halo2-Transcript");
        Transcript {
            state,
            reader: Read { buf: input, offset: 0 },
        }
    }

    public fun proof_remaining_len(self: &Transcript): u64 {
        self.reader.buf.length() - self.reader.offset
    }

    /// Writes a common scalar to the transcript without consuming proof bytes.
    public fun common_scalar(self: &mut Transcript, s: Element<bn254::Scalar>) {
        common_scalar_serialized(self, bn254_utils::serialize_fr(&s));
    }

    /// Writes a common point to the transcript without consuming proof bytes.
    public fun common_point(self: &mut Transcript, point: Element<bn254::G1>) {
        plain_keccak::update(&mut self.state, vector[KECCAK256_PREFIX_POINT]);

        // Uncompressed G1 is [x.repr, y.repr_with_flag]. Halo2 transcript
        // expects the last two flag bits to be cleared before hashing.
        let mut le_repr = bn254_utils::serialize_g1_uncompressed(&point);
        let bits = vector::pop_back(&mut le_repr);
        vector::push_back(&mut le_repr, (bits << 2) >> 2);
        plain_keccak::update(&mut self.state, le_repr);
    }

    /// Reads a scalar from the proof and absorbs it into the transcript.
    public fun read_scalar(self: &mut Transcript): Element<bn254::Scalar> {
        let buf = read_exact(&mut self.reader, U256_BYTE_LEN);
        let scalar = option::destroy_some(bn254_utils::deserialize_fr(&buf));
        common_scalar_serialized(self, buf);
        scalar
    }

    public fun read_n_scalar(transcript: &mut Transcript, n: u64): vector<Element<bn254::Scalar>> {
        let mut res = vector[];
        let mut i = 0;
        while (i < n) {
            vector::push_back(&mut res, read_scalar(transcript));
            i = i + 1;
        };
        res
    }

    /// Reads a compressed G1 point from the proof and absorbs it into the transcript.
    public fun read_point(self: &mut Transcript): Element<bn254::G1> {
        let buf = read_exact(&mut self.reader, U256_BYTE_LEN);
        let point = option::destroy_some(bn254_utils::deserialize_g1(&buf));
        common_point(self, point);
        point
    }

    public fun read_n_point(transcript: &mut Transcript, n: u64): vector<Element<bn254::G1>> {
        let mut res = vector[];
        let mut i = 0;
        while (i < n) {
            vector::push_back(&mut res, read_point(transcript));
            i = i + 1;
        };
        res
    }

    /// Squeezes an encoded verifier challenge from the transcript.
    public fun squeeze_challenge(self: &mut Transcript): Element<bn254::Scalar> {
        plain_keccak::update(&mut self.state, vector[KECCAK256_PREFIX_CHALLENGE]);

        let mut state_lo = self.state;
        let mut state_hi = self.state;
        plain_keccak::update(&mut state_lo, vector[KECCAK256_PREFIX_CHALLENGE_LO]);
        plain_keccak::update(&mut state_hi, vector[KECCAK256_PREFIX_CHALLENGE_HI]);

        let result_lo = plain_keccak::finalize(&mut state_lo);
        let result_hi = plain_keccak::finalize(&mut state_hi);
        bn254_utils::fr_from_u512_le(&result_lo, &result_hi)
    }

    public fun squeeze_n_challenges(transcript: &mut Transcript, n: u64): vector<Element<bn254::Scalar>> {
        let mut res = vector[];
        let mut i = 0;
        while (i < n) {
            vector::push_back(&mut res, squeeze_challenge(transcript));
            i = i + 1;
        };
        res
    }

    fun common_scalar_serialized(self: &mut Transcript, bytes: vector<u8>) {
        plain_keccak::update(&mut self.state, vector[KECCAK256_PREFIX_SCALAR]);
        plain_keccak::update(&mut self.state, bytes);
    }

    fun read_exact(read: &mut Read, len: u64): vector<u8> {
        assert!(read.offset + len <= read.buf.length(), 101);

        let mut buf = vector[];
        let offset = read.offset;
        let mut i = 0;
        while (i < len) {
            vector::push_back(&mut buf, read.buf[offset + i]);
            i = i + 1;
        };
        read.offset = offset + i;

        buf
    }
}
