// rust
use ark_bn254::{g1::G1Affine, Fq};
use ark_ec::AffineRepr;
use ark_ff::BigInteger;
use ark_ff::{BigInteger256, PrimeField};
use ark_serialize::CanonicalDeserialize;

use group::prime::PrimeCurveAffine;
use group::Curve;
use group::GroupEncoding;
use halo2curves::bn256::G1Affine as Halo2G1Affine;
use halo2curves::CurveAffine;
use hex::{encode, FromHex};
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- arkworks ---");
    test_arkworks()?;
    println!("\n--- halo2curves ---");
    test_halo2curves()?;
    Ok(())
}

fn test_arkworks() -> Result<(), Box<dyn std::error::Error>> {
    let le_hex = "a7c40e6e753cfd404ff8e10e1352a3eb77c8e0495bf1d9b7c67410ce4f2a5a18";
    let mut bytes = Vec::from_hex(le_hex)?;
    let mut rdr = &bytes[..];
    let p = G1Affine::deserialize_compressed(&mut rdr)?;
    if p.is_zero() {
        println!("point at infinity");
        return Ok(());
    }
    let x = p.x;
    let y = p.y;
    let x_le = x.into_bigint().to_bytes_le();
    let y_le = y.into_bigint().to_bytes_le();
    let mut uncompressed_le = Vec::with_capacity(64);
    uncompressed_le.extend_from_slice(&x_le);
    uncompressed_le.extend_from_slice(&y_le);

    println!("x (le)           = 0x{}", hex::encode(&x_le));
    println!("y (le)           = 0x{}", hex::encode(&y_le));
    println!("uncompressed (le)= 0x{}", hex::encode(&uncompressed_le));
    Ok(())
}

fn read<R: io::Read>(reader: &mut R) -> io::Result<Halo2G1Affine> {
    let mut compressed = <Halo2G1Affine as GroupEncoding>::Repr::default();
    reader.read_exact(compressed.as_mut())?;
    Option::from(Halo2G1Affine::from_bytes(&compressed))
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid point encoding in proof"))
}

fn test_halo2curves() -> Result<(), Box<dyn std::error::Error>> {
    let le_hex = "a7c40e6e753cfd404ff8e10e1352a3eb77c8e0495bf1d9b7c67410ce4f2a5a98";
    let mut bytes = <Vec<u8>>::from_hex(le_hex)?;
    if bytes.len() != 32 {
        return Err("Invalid byte length".into());
    }

    let mut rdr = &bytes[..];
    let p = read(&mut rdr)?;

    let x_le = p.x.to_bytes().to_vec();
    let y_le = p.y.to_bytes().to_vec();
    let mut uncompressed_le = Vec::with_capacity(64);
    uncompressed_le.extend_from_slice(&x_le);
    uncompressed_le.extend_from_slice(&y_le);

    println!("x (le)           = 0x{}", encode(&x_le));
    println!("y (le)           = 0x{}", encode(&y_le));
    println!("uncompressed (le)= 0x{}", encode(&uncompressed_le));

    let compressed = p.to_bytes();
    println!("compressed      = 0x{}", encode(&compressed));
    let p_affine: Halo2G1Affine =
        Option::from(Halo2G1Affine::from_bytes(&compressed)).ok_or("Invalid point encoding")?;
    let x_le_2 = p_affine.x.to_bytes().to_vec();
    let y_le_2 = p_affine.y.to_bytes().to_vec();
    println!("x (le)_2           = 0x{}", encode(&x_le_2));
    println!("y (le)_2           = 0x{}", encode(&y_le_2));
    Ok(())
}
