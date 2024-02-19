use std::marker::PhantomData;

use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2_zk_email::DefaultEmailVerifyCircuit;
use num_bigint::BigUint;
use rsa::{PublicKeyParts, RsaPrivateKey};
use std::{
    fs::File,
    io::{prelude::*, BufReader, BufWriter},
    path::Path,
};
use tokio::runtime::Runtime;

pub fn get_example_circuit<F: PrimeField>() -> DefaultEmailVerifyCircuit<F> {
    let regex_bodyhash_decomposed: DecomposedRegexConfig =
        serde_json::from_reader(File::open("./zkemail/test_data/bodyhash_defs.json").unwrap())
            .unwrap();
    regex_bodyhash_decomposed
        .gen_regex_files(
            &Path::new("./zkemail/test_data/bodyhash_allstr.txt").to_path_buf(),
            &[Path::new("./zkemail/test_data/bodyhash_substr_0.txt").to_path_buf()],
        )
        .unwrap();
    let regex_from_decomposed: DecomposedRegexConfig =
        serde_json::from_reader(File::open("./zkemail/test_data/from_defs.json").unwrap()).unwrap();
    regex_from_decomposed
        .gen_regex_files(
            &Path::new("./zkemail/test_data/from_allstr.txt").to_path_buf(),
            &[Path::new("./zkemail/test_data/from_substr_0.txt").to_path_buf()],
        )
        .unwrap();
    let regex_to_decomposed: DecomposedRegexConfig =
        serde_json::from_reader(File::open("./zkemail/test_data/to_defs.json").unwrap()).unwrap();
    regex_to_decomposed
        .gen_regex_files(
            &Path::new("./zkemail/test_data/to_allstr.txt").to_path_buf(),
            &[Path::new("./zkemail/test_data/to_substr_0.txt").to_path_buf()],
        )
        .unwrap();
    let regex_subject_decomposed: DecomposedRegexConfig =
        serde_json::from_reader(File::open("./zkemail/test_data/subject_defs.json").unwrap())
            .unwrap();
    regex_subject_decomposed
        .gen_regex_files(
            &Path::new("./zkemail/test_data/subject_allstr.txt").to_path_buf(),
            &[
                Path::new("./zkemail/test_data/subject_substr_0.txt").to_path_buf(),
                Path::new("./zkemail/test_data/subject_substr_1.txt").to_path_buf(),
                Path::new("./zkemail/test_data/subject_substr_2.txt").to_path_buf(),
            ],
        )
        .unwrap();
    let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(
        File::open("./zkemail/test_data/test_ex1_email_body_defs.json").unwrap(),
    )
    .unwrap();
    regex_body_decomposed
        .gen_regex_files(
            &Path::new("./zkemail/test_data/test_ex1_email_body_allstr.txt").to_path_buf(),
            &[
                Path::new("./zkemail/test_data/test_ex1_email_body_substr_0.txt").to_path_buf(),
                Path::new("./zkemail/test_data/test_ex1_email_body_substr_1.txt").to_path_buf(),
                Path::new("./zkemail/test_data/test_ex1_email_body_substr_2.txt").to_path_buf(),
            ],
        )
        .unwrap();
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
        cfdkim::DkimPublicKey::Rsa(pk) => pk,
        _ => panic!("not supportted public key type."),
    };
    let public_key_n = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let circuit = DefaultEmailVerifyCircuit::new(email_bytes, public_key_n);

    circuit
}
