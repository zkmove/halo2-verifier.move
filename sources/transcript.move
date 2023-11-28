module halo2_verifier::transcript {
    use std::vector;
    use aptos_std::crypto_algebra::Element;

    use halo2_verifier::bn254_arithmetic;
    use halo2_verifier::bn254_types::{FormatG1Compr, Fr, G1};
    use halo2_verifier::hasher::{Self, Hasher};

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
        state: Hasher,
        reader: Read,
    }

    /// Initialize a transcript given an input buffer.
    public fun init(input: vector<u8>): Transcript {
        let state = hasher::new();
        hasher::update(&mut state, b"Halo2-Transcript");
        Transcript {
            state,
            reader: Read {
                buf: input,
                offset: 0,
            },
        }
    }

    /// Writing the scalar to the transcript without writing it to the proof,
    /// treating it as a common input.
    public fun common_scalar(self: &mut Transcript, s: Element<Fr>) {
        hasher::update(&mut self.state, vector::singleton(KECCAK256_PREFIX_SCALAR));
        hasher::update(&mut self.state, bn254_arithmetic::to_repr(&s));
    }

    /// Writing the point to the transcript without writing it to the proof,
    /// treating it as a common input.
    public fun common_point(self: &mut Transcript, point: Element<G1>) {
        hasher::update(&mut self.state, vector::singleton(KECCAK256_PREFIX_POINT));

        // Fixme. here need write coordinate x and y seperately?
        let p = bn254_arithmetic::to_bytes<G1, FormatG1Compr>(&point);
        hasher::update(&mut self.state, p)
        // let (x, y) = point::coordinates(&point);
        // hasher::update(&mut self.state, x);
        // hasher::update(&mut self.state, y);
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
        // Fixme. assumed len fixed. defined instant here and change in future.
        // let len = vector::length(&bn254_arithmetic::to_repr(&crypto_algebra::zero()));
        let len = 32;
        let buf = read_exact(&mut self.reader, len);
        let scalar = bn254_arithmetic::from_repr(buf);
        common_scalar(self, scalar);
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

    /// Read a curve point from the prover.
    public fun read_point(self: &mut Transcript): Element<G1> {
        // Fixme. assumed len fixed. defined instant here and change in future.
        // let len = vector::length(&bn254_arithmetic::to_bytes<G1, FormatG1Compr>(&crypto_algebra::zero()));
        let len = 32;
        let buf = read_exact(&mut self.reader, len);
        let point = bn254_arithmetic::from_bytes<G1, FormatG1Compr>(buf);
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
        hasher::update(&mut self.state, vector::singleton(KECCAK256_PREFIX_CHALLENGE)); 

        let state_lo : Hasher = self.state;
        let state_hi : Hasher = self.state;
        hasher::update(&mut state_lo, vector::singleton(KECCAK256_PREFIX_CHALLENGE_LO));
        hasher::update(&mut state_hi, vector::singleton(KECCAK256_PREFIX_CHALLENGE_HI));

        let result_lo = hasher::finalize(&mut state_lo);
        let result_hi = hasher::finalize(&mut state_hi);
        let result = vector::empty();
        vector::append(&mut result, result_lo);
        vector::append(&mut result, result_hi);
        bn254_arithmetic::from_repr(result)
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
