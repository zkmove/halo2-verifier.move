module halo2_verifier::i32 {

    use std::error;

    const MAX_I32_AS_U32: u32 = (1 << 31) - 1;
    const U32_WITH_FIRST_BIT_SET: u32 = 1 << 31;

    const EQUAL: u8 = 0;
    const LESS_THAN: u8 = 1;
    const GREATER_THAN: u8 = 2;

    const ECONVERSION_FROM_U32_OVERFLOW: u64 = 0;
    const ECONVERSION_TO_U32_UNDERFLOW: u64 = 1;

    struct I32 has copy, drop, store {
        bits: u32
    }

    public fun zero(): I32 {
        I32 { bits: 0 }
    }

    public fun from(x: u32): I32 {
        assert!(x <= MAX_I32_AS_U32, error::invalid_argument(ECONVERSION_FROM_U32_OVERFLOW));
        I32 { bits: x }
    }

    public fun neg_from(x: u32): I32 {
        let ret = from(x);
        if (ret.bits > 0) *&mut ret.bits = ret.bits | (1 << 31);
        ret
    }

    public fun new(next: bool, x: u32): I32 {
        if (next) from(x)
        else neg_from(x)
    }

    public fun is_neg(x: &I32): bool {
        x.bits > U32_WITH_FIRST_BIT_SET
    }

    public fun value(x: &I32): u32 {
        assert!(x.bits < U32_WITH_FIRST_BIT_SET, error::invalid_argument(ECONVERSION_TO_U32_UNDERFLOW));
        x.bits
    }

    public fun neg(x: &I32): I32 {
        if (x.bits == 0) return *x;
        I32 { bits: if (x.bits < U32_WITH_FIRST_BIT_SET) x.bits | (1 << 31) else x.bits - (1 << 31) }
    }

    public fun add(a: &I32, b: &I32): I32 {
        if (a.bits >> 31 == 0) {
            // A is positive
            if (b.bits >> 31 == 0) {
                // B is positive
                return I32 { bits: a.bits + b.bits }
            } else {
                // B is negative
                if (b.bits - (1 << 31) <= a.bits) return I32 { bits: a.bits - (b.bits - (1 << 31)) }; // Return positive
                return I32 { bits: b.bits - a.bits } // Return negative
            }
        } else {
            // A is negative
            if (b.bits >> 31 == 0) {
                // B is positive
                if (a.bits - (1 << 31) <= b.bits) return I32 { bits: b.bits - (a.bits - (1 << 31)) }; // Return positive
                return I32 { bits: a.bits - b.bits } // Return negative
            } else {
                // B is negative
                return I32 { bits: a.bits + (b.bits - (1 << 31)) }
            }
        }
    }

    public fun sub(a: &I32, b: &I32): I32 {
        if (a.bits >> 31 == 0) {
            // A is positive
            if (b.bits >> 31 == 0) {
                // B is positive
                if (a.bits >= b.bits) return I32 { bits: a.bits - b.bits }; // Return positive
                return I32 { bits: (1 << 31) | (b.bits - a.bits) } // Return negative
            } else {
                // B is negative
                return I32 { bits: a.bits + (b.bits - (1 << 31)) } // Return negative
            }
        } else {
            // A is negative
            if (b.bits >> 31 == 0) {
                // B is positive
                return I32 { bits: a.bits + b.bits } // Return negative
            } else {
                // B is negative
                if (b.bits >= a.bits) return I32 { bits: b.bits - a.bits }; // Return positive
                return I32 { bits: a.bits - (b.bits - (1 << 31)) } // Return negative
            }
        }
    }

    public fun mul(a: &I32, b: &I32): I32 {
        if (a.bits >> 31 == 0) {
            // A is positive
            if (b.bits >> 31 == 0) {
                // B is positive
                return I32 { bits: a.bits * b.bits } // Return positive
            } else {
                // B is negative
                return I32 { bits: (1 << 31) | (a.bits * (b.bits - (1 << 31))) } // Return negative
            }
        } else {
            // A is negative
            if (b.bits >> 31 == 0) {
                // B is positive
                return I32 { bits: (1 << 31) | (b.bits * (a.bits - (1 << 31))) } // Return negative
            } else {
                // B is negative
                return I32 { bits: (a.bits - (1 << 31)) * (b.bits - (1 << 31)) } // Return positive
            }
        }
    }

    public fun div(a: &I32, b: &I32): I32 {
        if (a.bits >> 31 == 0) {
            // A is positive
            if (b.bits >> 31 == 0) {
                // B is positive
                return I32 { bits: a.bits / b.bits } // Return positive
            } else {
                // B is negative
                return I32 { bits: (1 << 31) | (a.bits / (b.bits - (1 << 31))) } // Return negative
            }
        } else {
            // A is negative
            if (b.bits >> 31 == 0) {
                // B is positive
                return I32 { bits: (1 << 31) | ((a.bits - (1 << 31)) / b.bits) } // Return negative
            } else {
                // B is negative
                return I32 { bits: (a.bits - (1 << 31)) / (b.bits - (1 << 31)) } // Return positive
            }
        }
    }

    public fun abs(x: &I32): u32 {
        if (x.bits < U32_WITH_FIRST_BIT_SET) x.bits
        else x.bits - (1 << 31)
    }

    public fun get_next(x: &I32): I32 {
        add(x, &from(1))
    }
 
    public fun compare(a: &I32, b: &I32): u8 {
        if (a.bits == b.bits) return EQUAL;
        if (a.bits < U32_WITH_FIRST_BIT_SET) {
            // A is positive
            if (b.bits < U32_WITH_FIRST_BIT_SET) {
                // B is positive
                return if (a.bits > b.bits) GREATER_THAN else LESS_THAN
            } else {
                // B is negative
                return GREATER_THAN
            }
        } else {
            // A is negative
            if (b.bits < U32_WITH_FIRST_BIT_SET) {
                // B is positive
                return LESS_THAN
            } else {
                // B is negative
                return if (a.bits > b.bits) LESS_THAN else GREATER_THAN
            }
        }
    }
}
