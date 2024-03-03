use std::fs::File;
use std::str::FromStr;
use std::{env::set_var, marker::PhantomData};

use halo2_base::halo2_proofs::arithmetic::{Field, FieldExt};
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;

use ark_serialize::Read;
use cfdkim::{resolve_public_key, DkimPublicKey};
use halo2_zk_email::{default_config_params, DefaultEmailVerifyCircuit, EMAIL_VERIFY_CONFIG_ENV};
use rsa::traits::PublicKeyParts;
use snark_verifier_sdk::CircuitExt;
use tokio::runtime::Runtime;

use num_bigint::BigUint;

pub fn get_example_circuit<F: PrimeField<Repr = [u8; 32]> + FieldExt>(
) -> (DefaultEmailVerifyCircuit<F>, Vec<Vec<F>>) {
    set_var(
        EMAIL_VERIFY_CONFIG_ENV,
        "./zkemail/configs/default_app.config",
    );

    let email_bytes = {
        let mut f = File::open("./zkemail/test_data/test_email1.eml").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let runtime = Runtime::new().unwrap();
    let public_key = runtime
        .block_on(async { resolve_public_key(&logger, &email_bytes).await })
        .unwrap();
    let public_key = match public_key {
        DkimPublicKey::Rsa(pk) => pk,
        _ => panic!("not supportted public key type."),
    };
    let public_key_n = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();

    let circuit = DefaultEmailVerifyCircuit::<F>::new(email_bytes, public_key_n);
    let instances = circuit.instances();
    (circuit, instances)
}
