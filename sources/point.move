module halo2_verifier::point {
    use std::vector;
    use aptos_std::crypto_algebra::{Self, Element};

    use halo2_verifier::bn254_types::Fr;
    use halo2_verifier::scalar::{Self, Scalar};

    struct Point<phantom G> has copy, drop { e: Element<G> }

    public fun underlying<G>(self: &Point<G>): &Element<G> {
        &self.e
    }

    public fun default<G>(): Point<G> {
        abort 100
    }

    public fun from_bytes<G, Format>(compressed: vector<u8>): Point<G> {
        let e = std::option::extract(&mut crypto_algebra::deserialize<G, Format>(&compressed));
        Point<G> { e }
    }

    public fun to_bytes<G, Format>(self: &Point<G>): vector<u8> {
        crypto_algebra::serialize<G, Format>(&self.e)
    }

    public fun one<G>(): Point<G> {
        Point<G> { e: crypto_algebra::one<G>() }
    }

    public fun zero<G>(): Point<G> {
        Point<G> { e: crypto_algebra::zero<G>() }
    }

    public fun order<G>(): vector<u8> {
        crypto_algebra::order<G>()
    }

    public fun scalar_mul<G>(point: &Point<G>, scalar: &Scalar): Point<G> {
        Point<G> { e: crypto_algebra::scalar_mul<G, Fr>(&point.e, &scalar::inner(scalar)) }
    }

    public fun multi_scalar_mul<G>(points: &vector<Point<G>>, scalars: &vector<Scalar>): Point<G> {
        let points = vector::map_ref(points, |p| {
            let p: &Point<G> = p;
            p.e
        });
        let scalars = vector::map_ref(scalars, |p| {
            let p: &Scalar = p;
            scalar::inner(p)
        });

        Point<G> { e: crypto_algebra::multi_scalar_mul<G, Fr>(&points, &scalars) }
    }

    public fun double<G>(a: &Point<G>): Point<G> {
        Point<G> { e: crypto_algebra::double<G>(&a.e) }
    }

    public fun add<G>(a: &Point<G>, b: &Point<G>): Point<G> {
        Point<G> { e: crypto_algebra::add<G>(&a.e, &b.e) }
    }

    public fun sub<G>(a: &Point<G>, b: &Point<G>): Point<G> {
        Point<G> { e: crypto_algebra::sub<G>(&a.e, &b.e) }
    }

    public fun neg<G>(a: &Point<G>): Point<G> {
        Point<G> { e: crypto_algebra::neg<G>(&a.e) }
    }
}
