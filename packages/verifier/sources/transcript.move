/// Transcript with keecak256 hash.
/// Had to deal with the different serialization of curve point between halo2 and arkworks.
module halo2_verifier::transcript {
    use std::vector;
    use std::option;
    use aptos_std::crypto_algebra::Element;
    use aptos_std::bn254_algebra::{Fr, G1};

    use halo2_common::bn254_utils;
    use halo2_common::plain_keccak::{Self};
    use halo2_common::plain_keccak::PlainKeccak;

    const U256_BYTE_LEN: u64 = 32;
    /// Prefix to a prover's message soliciting a challenge
    const KECCAK256_PREFIX_CHALLENGE: u8 = 0;
    /// First prefix to a prover's message soliciting a challenge
    /// Not included in the growing state!
    const KECCAK256_PREFIX_CHALLENGE_LO: u8 = 10;
    /// Second prefix to a prover's message soliciting a challenge
    /// Not included in the growing state!
    const KECCAK256_PREFIX_CHALLENGE_HI: u8 = 11;
    /// Prefix to a prover's message containing a curve point
    const KECCAK256_PREFIX_POINT: u8 = 1;
    /// Prefix to a prover's message containing a scalar
    const KECCAK256_PREFIX_SCALAR: u8 = 2;

    struct Read has copy, drop {
        buf: vector<u8>,
        offset: u64,
    }
    struct Transcript has copy, drop {
        state: PlainKeccak,
        reader: Read,
    }

    /// Initialize a transcript given an input buffer.
    public fun init(input: vector<u8>): Transcript {
        
        let state = plain_keccak::new();
        plain_keccak::update(&mut state, b"Halo2-Transcript");
        Transcript {
            state,
            reader: Read {
                buf: input,
                offset: 0,
            },
        }
    }

    public fun proof_remaining_len(self: &Transcript): u64 {
        vector::length(&self.reader.buf) - self.reader.offset
    }

    /// Writing the scalar to the transcript without writing it to the proof,
    /// treating it as a common input.
    public fun common_scalar(self: &mut Transcript, s: Element<Fr>) {
        common_scalar_serialized(self, bn254_utils::serialize_fr(&s));
    }
    fun common_scalar_serialized(self: &mut Transcript, bytes: vector<u8>) {
        plain_keccak::update(&mut self.state, vector::singleton(KECCAK256_PREFIX_SCALAR));
        plain_keccak::update(&mut self.state,bytes);
    }

    /// Writing the point to the transcript without writing it to the proof,
    /// treating it as a common input.
    public fun common_point(self: &mut Transcript, point: Element<G1>) {
        plain_keccak::update(&mut self.state, vector::singleton(KECCAK256_PREFIX_POINT));
        // because uncompressed serialize of g1 are [x.repr, y.repr_with_flag]
        // we can just erase the last 2 bits flags.
        let le_repr = bn254_utils::serialize_g1_uncompressed(&point);
        let bits = vector::pop_back(&mut le_repr);
        let flag_erased_bits = (bits << 2) >> 2;
        vector::push_back(&mut le_repr, flag_erased_bits);
        plain_keccak::update(&mut self.state, le_repr);
    }

    fun read_exact(read: &mut Read, len: u64) : vector<u8> {
        assert!(read.offset + len <= vector::length(&read.buf), 101);

        let buf = vector::empty();
        let offset = read.offset;
        let i = 0;
        while(i < len) {
            vector::push_back(&mut buf, *vector::borrow(&read.buf, offset + i));
            i = i + 1;
        };
        // update offset within Read
        read.offset = offset + i;

        buf
    }

    /// Read a curve scalar from the prover.
    public fun read_scalar(self: &mut Transcript): Element<Fr> {
        let buf = read_exact(&mut self.reader, U256_BYTE_LEN);
        let scalar = option::destroy_some( bn254_utils::deserialize_fr(&buf));
        // use serialzied bytes directly to save on op of serialization.
        common_scalar_serialized(self, buf);
        scalar
    }
    public fun read_n_scalar(transcript: &mut Transcript, n:u64): vector<Element<Fr>> {
        let res = vector::empty();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut res, read_scalar(transcript));
            i = i + 1;
        };
        res
    }

    /// Read a curve point from the proof.
    /// need to handle the difference of halo2 and arkworks
    public fun read_point(self: &mut Transcript): Element<G1> {
        let buf = read_exact(&mut self.reader, U256_BYTE_LEN);
        let point = option::destroy_some(bn254_utils::deserialize_g1(&buf));
        common_point(self, point);
        point 
    }
    public fun read_n_point(transcript: &mut Transcript, n: u64): vector<Element<G1>> {
        let res = vector::empty();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut res, read_point(transcript));
            i = i + 1;
        };
        res
    }

    /// Squeeze an encoded verifier challenge from the transcript.
    public fun squeeze_challenge(self:  &mut Transcript) : Element<Fr> {
        plain_keccak::update(&mut self.state, vector::singleton(KECCAK256_PREFIX_CHALLENGE)); 

        let state_lo : PlainKeccak = self.state;
        let state_hi : PlainKeccak = self.state;
        plain_keccak::update(&mut state_lo, vector::singleton(KECCAK256_PREFIX_CHALLENGE_LO));
        plain_keccak::update(&mut state_hi, vector::singleton(KECCAK256_PREFIX_CHALLENGE_HI));

        let result_lo = plain_keccak::finalize(&mut state_lo);
        let result_hi = plain_keccak::finalize(&mut state_hi);
        let result = vector::empty();
        vector::append(&mut result, result_lo);
        vector::append(&mut result, result_hi);
        bn254_utils::fr_from_u512_le(&result_lo, &result_hi)
    }
    public fun squeeze_n_challenges(transcript: &mut Transcript, n:u64): vector<Element<Fr>> {
        let res = vector::empty();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut res, squeeze_challenge(transcript));
            i = i + 1;
        };
        res
    }
}
