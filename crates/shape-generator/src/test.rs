#[cfg(test)]
mod tests {
    use ark_bn254::g1::G1Affine;
    use ark_ec::AffineRepr;
    use ark_ff::BigInteger;
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalDeserialize;

    use group::GroupEncoding;
    use halo2curves::bn256::G1Affine as Halo2G1Affine;
    use hex::{encode, FromHex};
    use std::io::{self};

    #[test]
    fn test_arkworks() -> Result<(), Box<dyn std::error::Error>> {
        let le_hex = "a7c40e6e753cfd404ff8e10e1352a3eb77c8e0495bf1d9b7c67410ce4f2a5a98";
        let bytes = Vec::from_hex(le_hex)?;
        let mut rdr = &bytes[..];
        let p = G1Affine::deserialize_compressed(&mut rdr).expect("deserialize failed");
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
            .ok_or_else(|| io::Error::other("Invalid point encoding in proof"))
    }

    #[test]
    fn test_halo2curves() -> Result<(), Box<dyn std::error::Error>> {
        let le_hex = "a7c40e6e753cfd404ff8e10e1352a3eb77c8e0495bf1d9b7c67410ce4f2a5a98";
        let bytes = <Vec<u8>>::from_hex(le_hex)?;
        if bytes.len() != 32 {
            return Err("Invalid byte length".into());
        }

        let mut rdr = &bytes[..];
        let affine = read(&mut rdr)?;

        let x_le = affine.x.to_bytes().to_vec();
        let y_le = affine.y.to_bytes().to_vec();
        let mut uncompressed_le = Vec::with_capacity(64);
        uncompressed_le.extend_from_slice(&x_le);
        uncompressed_le.extend_from_slice(&y_le);

        println!("x (le)           = 0x{}", encode(&x_le));
        println!("y (le)           = 0x{}", encode(&y_le));
        println!("uncompressed (le)= 0x{}", encode(&uncompressed_le));

        Ok(())
    }
}
