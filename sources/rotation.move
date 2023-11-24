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
    public fun is_neg(rotation: &Rotation): bool {
        !rotation.next
    }
    public fun value(rotation: &Rotation): u32 {
        rotation.rotation
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

    public fun reverse(r: &Rotation): Rotation {
        Rotation {
            rotation: r.rotation,
            next: !r.next
        }
    }
    
    public fun get_next(self: &Rotation): Rotation {
        if (self.next) {
            Rotation {
                rotation: self.rotation+1,
                next: true
            }
        } else {
            if (self.rotation == 1) {
                Rotation {
                    rotation: 0,
                    next: true
                }
            } else {
                Rotation {
                    rotation: self.rotation - 1,
                    next: false
                }
            }
        }
    }

    public fun gt(a: &Rotation, b: &Rotation): bool {
        if (a.next) {
            if (b.next) {
                if (a.rotation > b.rotation) true
                else false
            } else false
        } else {
            if (!b.next) {
                if (a.rotation < b.rotation) true
                else false
            } else false
        }
    }
}
