module halo2_verifier::i32 {

    use std::error;

    const MAX_I32_AS_U32: u32 = (1 << 31) - 1;
    const U32_WITH_FIRST_BIT_SET: u32 = 1 << 31;

    const EQUAL: u8 = 0;
    const LESS_THAN: u8 = 1;
    const GREATER_THAN: u8 = 2;

    const ECONVERSION_FROM_U32_OVERFLOW: u64 = 0;
    const ECONVERSION_TO_U32_UNDERFLOW: u64 = 1;

    /// @notice Struct representing a signed 32-bit integer.
    struct I32 has copy, drop, store {
        bits: u32
    }

    /// @notice Creates a new `I32` with value 0.
    public fun zero(): I32 {
        I32 { bits: 0 }
    }

    /// @notice Casts an `I32` to a `u32`.
    public fun as_u32(x: &I32): u32 {
        assert!(x.bits < U32_WITH_FIRST_BIT_SET, error::invalid_argument(ECONVERSION_TO_U32_UNDERFLOW));
        x.bits
    }

    /// @notice Casts a `u32` to an `I32`.
    public fun from(x: u32): I32 {
        assert!(x <= MAX_I32_AS_U32, error::invalid_argument(ECONVERSION_FROM_U32_OVERFLOW));
        I32 { bits: x }
    }

    /// @notice Flips the sign of `x`.
    public fun neg_from(x: u32): I32 {
        let ret = from(x);
        if (ret.bits > 0) *&mut ret.bits = ret.bits | (1 << 31);
        ret
    }

    /// @notice Create I32 value from next sign and x value.
    public fun new(next: bool, x: u32): I32 {
        if (next) from(x)
        else neg_from(x)
    }

    /// @notice Flips the sign of `x`.
    public fun neg(x: &I32): I32 {
        if (x.bits == 0) return *x;
        I32 { bits: if (x.bits < U32_WITH_FIRST_BIT_SET) x.bits | (1 << 31) else x.bits - (1 << 31) }
    }

    /// @notice Whether or not `x` is equal to 0.
    public fun is_zero(x: &I32): bool {
        x.bits == 0
    }

    /// @notice Whether or not `x` is negative.
    public fun is_neg(x: &I32): bool {
        x.bits > U32_WITH_FIRST_BIT_SET
    }

    /// @notice Absolute value of `x`.
    public fun abs(x: &I32): u32 {
        if (x.bits < U32_WITH_FIRST_BIT_SET) x.bits
        else x.bits - (1 << 31)
    }
 
    /// @notice Compare `a` and `b`.
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

    /// @notice Add `a + b`.
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

    /// @notice Subtract `a - b`.
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

    /// @notice Multiply `a * b`.
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

    /// @notice Divide `a / b`.
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
}
