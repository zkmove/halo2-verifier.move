/// Refer to tiny-keccak: https://github.com/debris/tiny-keccak
/// Keccak256: see https://keccak.team/keccak.html
/// b: 1600; r: 1088; c: 512; W=64; 
/// L = log_2^W = log_2^64 = 6;
/// n_r = 12 + 2L = 12 + 2*6 = 24
/// rate = 200 - bits / 4;
module halo2_verifier::hasher {
    use halo2_verifier::keccakstate::{Self, KeccakState};

    const DELIM: u8 = 0x01;
    const RATE: u64 = 136;

    const DEFAULT_HASH: vector<u8> = vector<u8>[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    struct Hasher has copy, drop {
        state: KeccakState,
    }

    public fun new(): Hasher {
        // for Keccak256, bits is 256
        // rate = 200 - bits / 4
        Hasher{state: keccakstate::new(RATE, DELIM)}
    }

    public fun update(self: &mut Hasher, input: vector<u8>) {
        keccakstate::update(&mut self.state, input);
    }

    public fun finalize(self: &mut Hasher) : vector<u8> {
        let output = DEFAULT_HASH;
        keccakstate::finalize(&mut self.state, &mut output);
        output
    }

    #[test]
    public fun test_keccak() {
        let keccak = new();
        let expected = b"\x47\x17\x32\x85\xa8\xd7\x34\x1e\x5e\x97\x2f\xc6\x77\x28\x63\x84\xf8\x02\xf8\xef\x42\xa5\xec\x5f\x03\xbb\xfa\x25\x4c\xb0\x1f\xad";
        update(&mut keccak, b"hello");
        update(&mut keccak, b" ");
        update(&mut keccak, b"world");
        let output = finalize(&mut keccak);
        assert!(output == expected, 101);
    }   

    #[test]
    public fun empty_keccak() {
        let keccak = new();
        let expected = b"\xc5\xd2\x46\x01\x86\xf7\x23\x3c\x92\x7e\x7d\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6\x53\xca\x82\x27\x3b\x7b\xfa\xd8\x04\x5d\x85\xa4\x70";

        let output = finalize(&mut keccak);
        assert!(output == expected, 102);
    }
}

module halo2_verifier::keccakstate {
    use std::error;
    use std::vector;

    use halo2_verifier::keccakbuffer::{Self, Buffer};

    const WORDS: u64 = 25;

    // mode for keccak state
    const ABSORBING: u8 = 0;
    const SQUEEZING: u8 = 1;

    // error definition
    const INVALID_PARAMETER : u64 = 1;

    struct KeccakState has copy, drop {
        buffer: Buffer,
        offset: u64,
        rate: u64,
        delim: u8,
        mode: u8,
    }

    public fun new(rate: u64, delim: u8): KeccakState {
        assert!(rate != 0, error::invalid_argument(INVALID_PARAMETER));
        KeccakState {
            buffer: keccakbuffer::default(),
            offset: 0,
            rate,
            delim,
            mode: ABSORBING,
        }
    }

    fun keccak(self: &mut KeccakState) {
         keccakbuffer::keccak(&mut self.buffer);
    }

    public fun update(self: &mut KeccakState, input: vector<u8>) {
        if (SQUEEZING == self.mode) {
            self.mode = ABSORBING;
            fill_block(self);
        };

        //first foldp
        let ip = 0;
        let l = vector::length(&input);
        let rate = self.rate - self.offset;
        let offset = self.offset;
        while (l >= rate) {
            keccakbuffer::xorin(&mut self.buffer, &input, ip, offset, rate);
            keccak(self);
            ip = ip + rate;
            l = l - rate;
            rate = self.rate;
            offset = 0;
        };

        keccakbuffer::xorin(&mut self.buffer, &input, ip, offset, l);
        self.offset = offset + l;
    }

    fun pad(self: &mut KeccakState) {
        keccakbuffer::pad(&mut self.buffer, self.offset, self.delim, self.rate);
    }

    fun fill_block(self: &mut KeccakState) {
        keccak(self);
        self.offset = 0;
    }

    fun squeeze(self: &mut KeccakState, output: &mut vector<u8>) {
        if (ABSORBING == self.mode) {
            self.mode = SQUEEZING;
            pad(self);
            fill_block(self);
        };

        // second foldp
        let op = 0;
        let l = vector::length(output);
        let rate = self.rate - self.offset;
        let offset = self.offset;
        while (l >= rate) {
            keccakbuffer::setout(&self.buffer, output, op, offset, rate);
            keccak(self);
            op = op + rate;
            l = l - rate;
            rate = self.rate;
            offset = 0;
        };

        keccakbuffer::setout(&self.buffer, output, op, offset, l);
        self.offset = offset + l;
    }

    public fun finalize(self: &mut KeccakState, output: &mut vector<u8>) {
        squeeze(self, output);
    }

    public fun reset(self: &mut KeccakState) {
        self.buffer = keccakbuffer::default();
        self.offset = 0;
        self.mode = ABSORBING;
    }
}

module halo2_verifier::keccakbuffer {
    use std::bcs;
    use std::math64::min;
    use std::vector;
    use std::error;

    const WORDS: u8 = 25;
    const ROUNDS: u8 = 24;
    const U64_MAX: u64 = 0xffffffffffffffffu64;
    const RHO: vector<u8> = vector[
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const PI: vector<u8> = vector[
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];
    const RC: vector<u64> = vector[
        1u64,
        0x8082u64,
        0x800000000000808au64,
        0x8000000080008000u64,
        0x808bu64,
        0x80000001u64,
        0x8000000080008081u64,
        0x8000000000008009u64,
        0x8au64,
        0x88u64,
        0x80008009u64,
        0x8000000au64,
        0x8000808bu64,
        0x800000000000008bu64,
        0x8000000000008089u64,
        0x8000000000008003u64,
        0x8000000000008002u64,
        0x8000000000000080u64,
        0x800au64,
        0x800000008000000au64,
        0x8000000080008081u64,
        0x8000000000008080u64,
        0x80000001u64,
        0x8000000080008008u64,
    ];

    const BUF_DEFAULT: vector<u64> = vector<u64>[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // error definition
    const INVALID_PARAMETER: u64 = 1;

    struct Buffer has copy, drop {
        // [u64; WORDS]
        buf: vector<u64>,
    }
    public fun words(self: &Buffer) : & vector<u64> {
        & self.buf
    }

    public fun default() : Buffer {
        let buf = BUF_DEFAULT;
        Buffer{buf}
    }

    // data layout
    // v: u64 = 0xefcdab8967452301;
    // data = bcs::to_bytes<u64>(&v);  
    // data  {01,23,45,67,89,ab,cd,ef}
    public fun setout(self: &Buffer, dst: &mut vector<u8>, dst_offset: u64, offset: u64, len: u64) {
        let ip : u64 = offset;
        let op : u64 = dst_offset;
        let l : u64 = len;

        // ip is not 8 bytes align
        if(0 != (ip % 8)) {
            let unaligned_len = 8 - ip % 8;
            let v: u64 = *vector::borrow(&self.buf, ip / 8);
            let data : vector<u8> = bcs::to_bytes<u64>(&v);
            let i = 0;
            while (i < min(l, unaligned_len)) {
               *vector::borrow_mut(dst, op + i) =   *vector::borrow(&data, (ip % 8) + i);
               i = i + 1;
            };

            ip = ip + i;
            op = op + i;
            l = l - i;
        };

        let i = 0;
        while(i < (l / 8)) {
            let v: u64 = *vector::borrow(&self.buf, ip / 8);
            let data : vector<u8> = bcs::to_bytes<u64>(&v);
            let j = 0;
            while (j < 8) {
               *vector::borrow_mut(dst, op + j) =   *vector::borrow(&data, j);
               j = j + 1;
            };
            ip = ip + 8; 
            op = op + 8;

            i = i + 1;
        };
        l = l - 8 * i;

        // end(ip + len) is not 8 bytes align
        if(l > 0) { 
            let v: u64 = *vector::borrow(&self.buf, ip / 8);
            let data = bcs::to_bytes<u64>(&v);
            let i = 0;
            while (i < l) {
                *vector::borrow_mut(dst, op + i) = *vector::borrow(&data, i);
                i = i + 1;
            };
        };
    }

    public fun xorin(self: &mut Buffer, src: &vector<u8>, src_offset: u64, offset: u64, len: u64) {
        let start = offset;
        let ip = src_offset;
        let l : u64 = len;
        assert!(l <= (vector::length(src) - ip), error::invalid_argument(INVALID_PARAMETER));

        // start is not 8 bytes align
        if(0 != (start % 8)) {
            let unaligned_len = 8 - start % 8;

            // read from buf
            let data : vector<u8> = bcs::to_bytes<u64>(vector::borrow(&self.buf, start / 8));
            let i = 0;
            let length = min(unaligned_len, l);
            while (i < length) {
                let input = *vector::borrow(src, ip + i);
                let tmp = *vector::borrow(&data, (start % 8) + i) ^ input;
                *vector::borrow_mut(&mut data, (start % 8) + i) = tmp;
                i = i + 1;
            };
            // write back buf
            vector::reverse(&mut data);
            *vector::borrow_mut(&mut self.buf, start / 8) = vector::fold(data, 0u64, |acc, v| acc * 256 + (v as u64));

            start = start + length;
            ip = ip + length;
            l = l - length;
        };

        let i = 0;
        while(i < (l / 8)) {
            // read 8 bytes from src
            let data = vector::empty<u8>();
            let j = 0;
            while (j < 8) {
                vector::push_back(&mut data, *vector::borrow(src, ip + j));
                j = j + 1;
            };
            vector::reverse(&mut data);
            let tmp : u64 = vector::fold(data, 0u64, |acc, v| acc * 256 + (v as u64));
            // change value in buf
            let value: u64 = *vector::borrow(&self.buf, start / 8);
            *vector::borrow_mut(&mut self.buf, start / 8) = value ^ tmp;
            start = start + 8;
            ip = ip + 8;

            i = i + 1;
        };
        l = l - 8 * i;

        // end is not 8 bytes align
        if(l > 0) {
            // src offset
            // read from buf
            let data : vector<u8> = bcs::to_bytes<u64>(vector::borrow(&self.buf, start / 8));
            let i = 0;
            while (i < l) {
                let tmp :u8 = *vector::borrow(&data, i) ^ *vector::borrow(src, ip + i);
                *vector::borrow_mut(&mut data, i) = tmp;
                i = i + 1;
            };
            // write into buf 
            vector::reverse(&mut data);
            let tmp : u64 = vector::fold(data, 0u64, |acc, v| acc * 256u64 + (v as u64));
            *vector::borrow_mut(&mut self.buf, start / 8) = tmp;
        };
    }

    public fun pad(self: &mut Buffer, offset: u64, delim: u8, rate: u64) {
        // self.execute(offset, 1, |buff| buff[0] ^= delim);
        let data : vector<u8> = bcs::to_bytes<u64>(vector::borrow<u64>(&self.buf, offset / 8));
        *vector::borrow_mut<u8>(&mut data, offset % 8) = *vector::borrow<u8>(&data, offset % 8) ^ delim;
        vector::reverse(&mut data);
        let tmp : u64 = vector::fold(data, 0u64, |acc, v| (acc as u64) * 256u64 + (v as u64));
        *vector::borrow_mut<u64>(&mut self.buf, offset / 8) = tmp;

        // self.execute(rate - 1, 1, |buff| buff[0] ^= 0x80);
        let data : vector<u8> = bcs::to_bytes<u64>(vector::borrow<u64>(&self.buf, (rate - 1) / 8));
        *vector::borrow_mut<u8>(&mut data, (rate - 1) % 8) = *vector::borrow<u8>(&data, (rate - 1) % 8) ^ 0x80;
        vector::reverse(&mut data);
        let tmp : u64 = vector::fold(data, 0u64, |acc, v| (acc as u64)* 256u64 + (v as u64));
        *vector::borrow_mut<u64>(&mut self.buf, (rate - 1) / 8) = tmp;
    }

    // refer to function keccak_function within file:
    // https://github.com/debris/tiny-keccak/blob/master/src/lib.rs
    public fun keccak(self: &mut Buffer) {
        let i = 0;
        while (i < ROUNDS) {
            // array: [u64; 5] = [0; 5];
            let array = vector<u64>[0, 0, 0, 0, 0];

            // Theta
            let x = 0;
            while (x < 5) {
                let y_count = 0;
                while (y_count < 5) {
                    let y = y_count * 5;
                    // array[x] ^= a[x + y];
                    *vector::borrow_mut(&mut array, x) = *vector::borrow(&array, x) ^ *vector::borrow(&self.buf, x + y);
                    y_count = y_count + 1;
                };
                x = x + 1;
            };

            let x = 0;
            while (x < 5) {
                let y_count = 0;
                while (y_count < 5) {
                    let y = y_count * 5;
                    // a[y + x] ^= array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
                    let tmp = rotate_left(*vector::borrow(&array, (x + 1) % 5), 1); 
                    let tmp = *vector::borrow(&array, (x + 4) % 5) ^ tmp;
                    *vector::borrow_mut(&mut self.buf, y + x) = *vector::borrow(&self.buf, y + x) ^ tmp;
                    y_count = y_count + 1;
                };
                x = x + 1;
            };

            // Rho and pi
            // let mut last = a[1];
            let last = *vector::borrow(&self.buf, 1);
            let x = 0;
            while (x < 24) {
                // array[0] = a[$crate::PI[x]];
                let pi = *vector::borrow(&PI, x); 
                *vector::borrow_mut(&mut array, 0) = *vector::borrow(&self.buf, (pi as u64));
                // a[$crate::PI[x]] = last.rotate_left($crate::RHO[x]);
                let rho = *vector::borrow(&RHO, x);
                *vector::borrow_mut(&mut self.buf, (pi as u64)) = rotate_left(last, rho);
                // last = array[0];
                last = *vector::borrow(&array, 0);

                x = x + 1;
            };

            // Chi
            let y_step = 0;
            while (y_step < 5) {
                let y = y_step * 5;
                let x = 0;
                while (x < 5) {
                    // array[x] = a[y + x];
                    *vector::borrow_mut(&mut array, x) = *vector::borrow(&self.buf, y + x);
                    x = x + 1;
                };
                x = 0; 
                while (x < 5) {
                    // a[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
                    let op1 = U64_MAX - *vector::borrow(&array, (x + 1) % 5);
                    let op2 = *vector::borrow(&array, (x + 2) % 5);
                    *vector::borrow_mut(&mut self.buf, y + x) = *vector::borrow(&array, x) ^ (op1 & op2);
                    x = x + 1;
                };

                y_step = y_step + 1;
            };

            // Iota
            // a[0] ^= $rc[i];
            let rc : u64 = *vector::borrow<u64>(&mut RC, (i as u64));
            *vector::borrow_mut<u64>(&mut self.buf, 0) = *vector::borrow<u64>(&mut self.buf, 0) ^ rc;

            i = i + 1;
        };
    }

    fun rotate_left(data: u64, shift_bits: u8) : u64 {
        data << shift_bits | data >> (64- shift_bits)
    }
}