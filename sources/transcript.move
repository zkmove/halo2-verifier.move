module halo2_verifier::transcript {
    use std::vector;

    use halo2_verifier::bn254_types::{FormatFrLsb, G1};
    use halo2_verifier::challenge255;
    use halo2_verifier::hasher::{Self, Hasher};
    use halo2_verifier::point::{Self, Point};
    use halo2_verifier::scalar::{Self, Scalar};

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
    public fun common_scalar(self: &mut Transcript, s: Scalar) {
        let v = vector::empty();
        vector::push_back(&mut v, KECCAK256_PREFIX_SCALAR);
        hasher::update(&mut self.state, v);

        hasher::update(&mut self.state, scalar::to_repr(&s));
    }

    /// Writing the point to the transcript without writing it to the proof,
    /// treating it as a common input.
    public fun common_point(self: &mut Transcript, point: Point<G1>) {
        let v = vector::empty();
        vector::push_back(&mut v, KECCAK256_PREFIX_POINT);
        hasher::update(&mut self.state, v);

        // Fixme. here need write coordinate x and y seperately?
        let p = point::to_bytes<G1, FormatFrLsb>(&point);
        hasher::update(&mut self.state, p)
        // let (x, y) = point::coordinates(&point);
        // hasher::update(&mut self.state, x);
        // hasher::update(&mut self.state, y);
    }

    fun read_exact(read: &mut Read, len: u64): vector<u8> {
        let buf_len = vector::length(&read.buf);
        let res = vector::empty();
        let i = 0;
        let offset = read.offset;
        while(i < len && offset < buf_len) {
            vector::push_back(&mut res, *vector::borrow(&read.buf, offset));
            i = i + 1;
            offset = offset + 1;
        };
        // update offset within Read
        read.offset = offset;
        res
    }

    /// Read a curve scalar from the prover.
    public fun read_scalar(self: &mut Transcript): Scalar {
        let len = vector::length(&scalar::to_repr(&scalar::zero()));
        let buf = read_exact(&mut self.reader, len);
        let scalar = scalar::from_repr(buf);
        common_scalar(self, scalar);
        scalar
    }
    public fun read_n_scalar(transcript: &mut Transcript, n:u64): vector<Scalar> {
        let res = vector::empty();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut res, read_scalar(transcript));
        };
        res
    }

    /// Read a curve point from the prover.
    public fun read_point(self: &mut Transcript): Point<G1> {
        let len = vector::length(&point::to_bytes<G1, FormatFrLsb>(&point::zero()));
        let buf = read_exact(&mut self.reader, len);
        let point = point::from_bytes<G1, FormatFrLsb>(buf);
        common_point(self, point);
        point 
    }
    public fun read_n_point(transcript: &mut Transcript, n: u64): vector<Point<G1>> {
        let res = vector::empty();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut res, read_point(transcript));
            i = i + 1;
        };
        res
    }

    /// Squeeze an encoded verifier challenge from the transcript.
    public fun squeeze_challenge(self:  &mut Transcript) : Scalar {
        let v = vector::empty();
        vector::push_back(&mut v, KECCAK256_PREFIX_CHALLENGE);
        hasher::update(&mut self.state, v);
        let state = self.state;
        
        let output = vector::empty<u8>();
        let i = 0;
        // keccak output lenght is fixed.
        while (i < 32) {
            vector::push_back(&mut output, 0);
            i = i + 1;
        };
        hasher::finalize(&mut state, &mut output);
        challenge255::new(output)
    }
    public fun squeeze_n_challenges(transcript: &mut Transcript, n:u64): vector<Scalar> {
        let res = vector::empty();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut res, squeeze_challenge(transcript));
            i = i + 1;
        };
        res
    }
}

// API for Challenge255
module halo2_verifier::challenge255 {
    use halo2_verifier::scalar::{Self, Scalar};
 
    // struct Challenge255 has copy, drop {repr: vector<u8>}

    // public fun new(challenge_input: vector<u8>): Challenge255 {
    //     Challenge255{repr: challenge_input}
    // }
    // public fun inner(self: &Challenge255): vector<u8> {
    //     self.repr
    // }
    // public fun get_scalar(self: &Challenge255): Scalar {
    //     scalar::from_repr(self.repr)
    // }

    // Scalar used here.
    public fun new(input: vector<u8>): Scalar {
        scalar::from_repr(input)
    }
}