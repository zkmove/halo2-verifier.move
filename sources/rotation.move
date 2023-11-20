module halo2_verifier::rotation {
    struct Rotation has copy, drop, store {
        rotation: u32,
        next: bool,
    }

    public fun cur(): Rotation {
        Rotation {
            rotation: 0,
            next: true
        }
    }

    public fun next(rotation: u32): Rotation {
        Rotation {
            rotation,
            next: true
        }
    }

    public fun prev(rotation: u32): Rotation {
        Rotation {
            rotation,
            next: false
        }
    }
}
