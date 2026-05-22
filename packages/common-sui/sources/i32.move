// Copyright (c) zkMove Authors

module halo2_common::i32 {
    const MAX_I32_AS_U32: u32 = (1 << 31) - 1;
    const U32_WITH_FIRST_BIT_SET: u32 = 1 << 31;

    const EQUAL: u8 = 0;
    const LESS_THAN: u8 = 1;
    const GREATER_THAN: u8 = 2;

    const ECONVERSION_FROM_U32_OVERFLOW: u64 = 0;
    const ECONVERSION_TO_U32_UNDERFLOW: u64 = 1;

    /// Struct representing a signed 32-bit integer.
    public struct I32 has copy, drop, store {
        bits: u32,
    }

    /// Creates a new `I32` with value 0.
    public fun zero(): I32 {
        I32 { bits: 0 }
    }

    /// Casts an `I32` to a `u32`.
    public fun as_u32(x: &I32): u32 {
        assert!(x.bits < U32_WITH_FIRST_BIT_SET, ECONVERSION_TO_U32_UNDERFLOW);
        x.bits
    }

    /// Casts a `u32` to an `I32`.
    public fun from(x: u32): I32 {
        assert!(x <= MAX_I32_AS_U32, ECONVERSION_FROM_U32_OVERFLOW);
        I32 { bits: x }
    }

    /// Flips the sign of `x`.
    public fun neg_from(x: u32): I32 {
        let mut ret = from(x);
        if (ret.bits > 0) {
            ret.bits = ret.bits | (1 << 31);
        };
        ret
    }

    /// Creates an `I32` from a sign flag and absolute value.
    public fun new(next: bool, x: u32): I32 {
        if (next) from(x) else neg_from(x)
    }

    /// Flips the sign of `x`.
    public fun neg(x: &I32): I32 {
        if (x.bits == 0) return *x;
        I32 { bits: if (x.bits < U32_WITH_FIRST_BIT_SET) x.bits | (1 << 31) else x.bits - (1 << 31) }
    }

    /// Returns true if `x` is equal to 0.
    public fun is_zero(x: &I32): bool {
        x.bits == 0
    }

    /// Returns true if `x` is negative.
    public fun is_neg(x: &I32): bool {
        x.bits > U32_WITH_FIRST_BIT_SET
    }

    /// Returns the absolute value of `x`.
    public fun abs(x: &I32): u32 {
        if (x.bits < U32_WITH_FIRST_BIT_SET) x.bits else x.bits - (1 << 31)
    }

    /// Compares `a` and `b`.
    public fun compare(a: &I32, b: &I32): u8 {
        if (a.bits == b.bits) return EQUAL;
        if (a.bits < U32_WITH_FIRST_BIT_SET) {
            if (b.bits < U32_WITH_FIRST_BIT_SET) {
                return if (a.bits > b.bits) GREATER_THAN else LESS_THAN
            } else {
                return GREATER_THAN
            }
        } else {
            if (b.bits < U32_WITH_FIRST_BIT_SET) {
                return LESS_THAN
            } else {
                return if (a.bits > b.bits) LESS_THAN else GREATER_THAN
            }
        }
    }

    /// Adds `a + b`.
    public fun add(a: &I32, b: &I32): I32 {
        if (a.bits >> 31 == 0) {
            if (b.bits >> 31 == 0) {
                return I32 { bits: a.bits + b.bits }
            } else {
                if (b.bits - (1 << 31) <= a.bits) return I32 { bits: a.bits - (b.bits - (1 << 31)) };
                return I32 { bits: b.bits - a.bits }
            }
        } else {
            if (b.bits >> 31 == 0) {
                if (a.bits - (1 << 31) <= b.bits) return I32 { bits: b.bits - (a.bits - (1 << 31)) };
                return I32 { bits: a.bits - b.bits }
            } else {
                return I32 { bits: a.bits + (b.bits - (1 << 31)) }
            }
        }
    }

    /// Subtracts `a - b`.
    public fun sub(a: &I32, b: &I32): I32 {
        if (a.bits >> 31 == 0) {
            if (b.bits >> 31 == 0) {
                if (a.bits >= b.bits) return I32 { bits: a.bits - b.bits };
                return I32 { bits: (1 << 31) | (b.bits - a.bits) }
            } else {
                return I32 { bits: a.bits + (b.bits - (1 << 31)) }
            }
        } else {
            if (b.bits >> 31 == 0) {
                return I32 { bits: a.bits + b.bits }
            } else {
                if (b.bits >= a.bits) return I32 { bits: b.bits - a.bits };
                return I32 { bits: a.bits - (b.bits - (1 << 31)) }
            }
        }
    }

    /// Multiplies `a * b`.
    public fun mul(a: &I32, b: &I32): I32 {
        if (a.bits >> 31 == 0) {
            if (b.bits >> 31 == 0) {
                I32 { bits: a.bits * b.bits }
            } else {
                I32 { bits: (1 << 31) | (a.bits * (b.bits - (1 << 31))) }
            }
        } else {
            if (b.bits >> 31 == 0) {
                I32 { bits: (1 << 31) | (b.bits * (a.bits - (1 << 31))) }
            } else {
                I32 { bits: (a.bits - (1 << 31)) * (b.bits - (1 << 31)) }
            }
        }
    }

    /// Divides `a / b`.
    public fun div(a: &I32, b: &I32): I32 {
        if (a.bits >> 31 == 0) {
            if (b.bits >> 31 == 0) {
                I32 { bits: a.bits / b.bits }
            } else {
                I32 { bits: (1 << 31) | (a.bits / (b.bits - (1 << 31))) }
            }
        } else {
            if (b.bits >> 31 == 0) {
                I32 { bits: (1 << 31) | ((a.bits - (1 << 31)) / b.bits) }
            } else {
                I32 { bits: (a.bits - (1 << 31)) / (b.bits - (1 << 31)) }
            }
        }
    }
}
