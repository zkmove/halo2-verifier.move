extern crate core;

use clap::{value_parser, Parser, Subcommand, ValueEnum};
use shape_generator::generate_circuit_info;
use shape_generator::serialize::serialize;

use ark_serialize::CanonicalSerialize;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::halo2curves::group::GroupEncoding;
use halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env::current_dir;
use std::fmt;
use std::path::PathBuf;
use vk_gen_examples::examples::{
    circuit_layout, serialization, shuffle, simple_example, two_chip, vector_mul,
};

use vk_gen_examples::proof::{prove_with_keccak256, KZG};
use vk_gen_examples::to_ark::IntoArk;

/// the consts correspond to the definition of `verifier_api.move`.
const PUBLISH_CIRCUIT: &str = "publish_circuit";
const VERIFY: &str = "verify_proof";
const VERIFIER_API: &str = "verifier_api";

#[derive(Parser)]
struct Cli {
    #[arg(long = "verifier-address", default_value = "0x1")]
    verifier_address: String,
    #[arg(long = "verifier-module", default_value = VERIFIER_API)]
    verifier_module: String,
    #[arg(long = "publish-vk-func", default_value = PUBLISH_CIRCUIT)]
    publish_vk_func: String,
    #[arg(long, default_value = VERIFY)]
    verify_func: String,
    #[arg(long)]
    param_path: PathBuf,
    #[arg(short)]
    k: Option<u8>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ViewParam,
    BuildPublishVkAptosTxn(BuildPublishVkAptosTxn),
    BuildVerifyProofAptosTxn(BuildVerifyProofTxn),
}

#[derive(Parser)]
struct BuildPublishVkAptosTxn {
    #[arg(long = "example", value_enum)]
    example: Examples,
    #[arg(long = "output", short = 'o', value_parser = value_parser ! (PathBuf))]
    output_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Examples {
    CircuitLayout,
    Serialization,
    Shuffle,
    SimpleExample,
    TwoChip,
    VectorMul,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KZGVariant {
    GWC,
    SHPLONK,
}

#[derive(Parser)]
struct BuildVerifyProofTxn {
    #[arg(long = "example", value_enum)]
    example: Examples,

    #[arg(long = "output", short = 'o', value_parser = value_parser ! (PathBuf))]
    output_dir: Option<PathBuf>,
    #[arg(long)]
    param_address: String,
    #[arg(long)]
    circuit_address: String,

    #[arg(long = "kzg", value_enum)]
    variant: KZGVariant,
}

fn main() -> anyhow::Result<()> {
    let cli: Cli = Cli::parse();
    let mut param_file = std::fs::File::open(cli.param_path.as_path())?;

    let mut params = ParamsKZG::<Bn256>::read(&mut param_file)?;
    if let Some(k) = cli.k {
        params.downsize(k as u32);
    }

    let g = params.get_g().first().unwrap();
    let g2 = params.g2();
    let s_g2 = params.s_g2();
    match cli.command {
        Commands::ViewParam => {
            println!("param info:");
            println!(
                "halo2 encoding, \nk: {} \ng: {} \ng2: {} \ns_g2: {}\n",
                params.k(),
                hex::encode(g.to_bytes()),
                hex::encode(g2.to_bytes()),
                hex::encode(s_g2.to_bytes())
            );

            let g = g.to_ark();
            let mut g_bytes = vec![];
            CanonicalSerialize::serialize_compressed(&g, &mut g_bytes).unwrap();
            let g2 = g2.to_ark();
            let mut g2_bytes = vec![];
            CanonicalSerialize::serialize_compressed(&g2, &mut g2_bytes).unwrap();
            let s_g2 = s_g2.to_ark();
            let mut s_g2_bytes = vec![];
            CanonicalSerialize::serialize_compressed(&s_g2, &mut s_g2_bytes).unwrap();
            println!(
                "arkworks encoding, \nk: {} \ng: {} \ng2: {} \ns_g2: {}\n",
                params.k(),
                hex::encode(g_bytes),
                hex::encode(g2_bytes),
                hex::encode(s_g2_bytes)
            );
        }
        Commands::BuildPublishVkAptosTxn(BuildPublishVkAptosTxn {
            example,
            output_dir,
        }) => {
            let circuit_info = match example {
                Examples::CircuitLayout => {
                    let circuit = circuit_layout::get_example_circuit::<Fr>();

                    generate_circuit_info(&params, &circuit.0)?
                }
                Examples::Serialization => {
                    let circuit = serialization::get_example_circuit();
                    generate_circuit_info(&params, &circuit.0)?
                }
                Examples::Shuffle => {
                    let circuit = shuffle::get_example_circuit();
                    generate_circuit_info(&params, &circuit.0)?
                }
                Examples::SimpleExample => {
                    let circuit = simple_example::get_example_circuit();
                    generate_circuit_info(&params, &circuit.0)?
                }
                Examples::TwoChip => {
                    let circuit = two_chip::get_example_circuit();
                    generate_circuit_info(&params, &circuit.0)?
                }
                Examples::VectorMul => {
                    let circuit = vector_mul::get_example_circuit();
                    generate_circuit_info(&params, &circuit.0)?
                }
            };
            let data = serialize(circuit_info.into())?;

            let args: Vec<_> = data
                .into_iter()
                .map(|arg| ArgWithTypeJSON {
                    arg_type: "hex".to_string(),
                    value: json!(arg
                        .into_iter()
                        .map(|i| HexEncodedBytes(i).to_string())
                        .collect::<Vec<_>>()),
                })
                .collect();
            let json = EntryFunctionArgumentsJSON {
                function_id: format!(
                    "{}::{}::{}",
                    cli.verifier_address, cli.verifier_module, cli.publish_vk_func
                ),
                type_args: vec![],
                args,
            };
            let output = serde_json::to_string_pretty(&json)?;
            let output_path = output_dir.unwrap_or_else(|| current_dir().unwrap());
            std::fs::create_dir_all(output_path.as_path())?;

            std::fs::write(
                output_path
                    .join(format!("{:?}-publish-circuit", example))
                    .with_extension("json"),
                output,
            )?;
        }
        Commands::BuildVerifyProofAptosTxn(BuildVerifyProofTxn {
            example,
            output_dir,
            param_address,
            circuit_address,
            variant,
        }) => {
            let kzg = match variant {
                KZGVariant::GWC => KZG::GWC,
                KZGVariant::SHPLONK => KZG::SHPLONK,
            };
            let (proof, instances) = match example {
                Examples::CircuitLayout => {
                    let (circuit, instances) = circuit_layout::get_example_circuit::<Fr>();
                    let vk = keygen_vk(&params, &circuit).unwrap();
                    let pk = keygen_pk(&params, vk, &circuit).unwrap();
                    let proof = prove_with_keccak256(circuit, &[&instances], &params, pk, kzg);
                    (proof, instances)
                }
                Examples::Serialization => {
                    let (circuit, instances) = serialization::get_example_circuit();
                    let vk = keygen_vk(&params, &circuit).unwrap();
                    let pk = keygen_pk(&params, vk, &circuit).unwrap();
                    let proof = prove_with_keccak256(circuit, &[&instances], &params, pk, kzg);
                    (proof, instances)
                }
                Examples::Shuffle => {
                    let (circuit, instances) = shuffle::get_example_circuit::<Fr>();
                    let vk = keygen_vk(&params, &circuit).unwrap();
                    let pk = keygen_pk(&params, vk, &circuit).unwrap();
                    let proof = prove_with_keccak256(circuit, &[&instances], &params, pk, kzg);
                    (proof, instances)
                }
                Examples::SimpleExample => {
                    let (circuit, instances) = simple_example::get_example_circuit::<Fr>();
                    let vk = keygen_vk(&params, &circuit).unwrap();
                    let pk = keygen_pk(&params, vk, &circuit).unwrap();
                    let proof = prove_with_keccak256(circuit, &[&instances], &params, pk, kzg);
                    (proof, instances)
                }
                Examples::TwoChip => {
                    let (circuit, instances) = two_chip::get_example_circuit::<Fr>();
                    let vk = keygen_vk(&params, &circuit).unwrap();
                    let pk = keygen_pk(&params, vk, &circuit).unwrap();
                    let proof = prove_with_keccak256(circuit, &[&instances], &params, pk, kzg);
                    (proof, instances)
                }
                Examples::VectorMul => {
                    let (circuit, instances) = vector_mul::get_example_circuit::<Fr>();
                    let vk = keygen_vk(&params, &circuit).unwrap();
                    let pk = keygen_pk(&params, vk, &circuit).unwrap();
                    let proof = prove_with_keccak256(circuit, &[&instances], &params, pk, kzg);
                    (proof, instances)
                }
            };
            let instances: Vec<_> = instances.iter().map(|fr| fr.to_bytes().to_vec()).collect();
            let json = EntryFunctionArgumentsJSON {
                function_id: format!(
                    "{}::{}::{}",
                    cli.verifier_address, cli.verifier_module, cli.verify_func
                ),
                type_args: vec![],
                args: vec![
                    ArgWithTypeJSON {
                        arg_type: "address".to_string(),
                        value: json!(param_address),
                    },
                    ArgWithTypeJSON {
                        arg_type: "address".to_string(),
                        value: json!(circuit_address),
                    },
                    ArgWithTypeJSON {
                        arg_type: "hex".to_string(),
                        value: json!(vec![instances
                            .into_iter()
                            .map(|i| HexEncodedBytes(i).to_string())
                            .collect::<Vec<_>>()]),
                    },
                    ArgWithTypeJSON {
                        arg_type: "hex".to_string(),
                        value: json!(HexEncodedBytes(proof.clone()).to_string()),
                    },
                ],
            };

            let output = serde_json::to_string_pretty(&json)?;
            let output_path = output_dir.unwrap_or_else(|| current_dir().unwrap());
            std::fs::create_dir_all(output_path.as_path())?;

            std::fs::write(
                output_path
                    .join(format!("{:?}-verify-proof-{}", example, kzg))
                    .with_extension("json"),
                output,
            )?;
        }
    }

    Ok(())
}

#[derive(Deserialize, Serialize)]
/// JSON file format for function arguments.
pub struct ArgWithTypeJSON {
    #[serde(rename = "type")]
    pub(crate) arg_type: String,
    pub(crate) value: serde_json::Value,
}

#[derive(Deserialize, Serialize)]
/// JSON file format for entry function arguments.
pub struct EntryFunctionArgumentsJSON {
    pub(crate) function_id: String,
    pub(crate) type_args: Vec<String>,
    pub(crate) args: Vec<ArgWithTypeJSON>,
}

/// Hex encoded bytes to allow for having bytes represented in JSON
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexEncodedBytes(pub Vec<u8>);

impl fmt::Display for HexEncodedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))?;
        Ok(())
    }
}
