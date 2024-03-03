use std::env::set_var;
use std::fs::File;
use std::str::FromStr;

use ark_serialize::Read;
use cfdkim::{resolve_public_key, DkimPublicKey};
use halo2_base::utils::PrimeField;
use halo2_zk_email::{default_config_params, DefaultEmailVerifyCircuit, EMAIL_VERIFY_CONFIG_ENV};
use rsa::traits::PublicKeyParts;
use tokio::runtime::Runtime;

use num_bigint::BigUint;

pub fn get_example_circuit<F: PrimeField>() -> (DefaultEmailVerifyCircuit<F>, Vec<F>) {
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
    println!("{:?}", email_bytes);

    let circuit = DefaultEmailVerifyCircuit::<F>::new(
        email_bytes,
        BigUint::from_str("3").unwrap_or_default(),
    );

    // Prepare the private and public inputs to the circuit!
    let constant = F::from(7);
    let a = F::from(2);
    let b = F::from(3);
    let instances = vec![constant, a, b];

    (circuit, instances)
}

// fn main() {
//     use halo2_proofs::dev::MockProver;
//     use halo2curves::pasta::Fp;
//
//     // ANCHOR: test-circuit
//     // The number of rows in our circuit cannot exceed 2^k. Since our example
//     // circuit is very small, we can pick a very small value here.
//     let k = 4;
//
//     // Prepare the private and public inputs to the circuit!
//     let constant = Fp::from(7);
//     let a = Fp::from(2);
//     let b = Fp::from(3);
//     let c = constant * a.square() * b.square();
//
//     // Instantiate the circuit with the private inputs.
//     let circuit = MyCircuit {
//         constant,
//         a: Value::known(a),
//         b: Value::known(b),
//     };
//
//     // Arrange the public input. We expose the multiplication result in row 0
//     // of the instance column, so we position it there in our public inputs.
//     let mut public_inputs = vec![c];
//
//     // Given the correct public input, our circuit will verify.
//     let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
//     assert_eq!(prover.verify(), Ok(()));
//
//     // If we try some other public input, the proof will fail!
//     public_inputs[0] += Fp::one();
//     let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
//     assert!(prover.verify().is_err());
//     // ANCHOR_END: test-circuit
// }
