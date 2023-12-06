extern crate core;

use circuit_info_generator::generate_circuit_info;
use circuit_info_generator::serialize::serialize;
use clap::{value_parser, Parser, Subcommand, ValueEnum};

use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env::current_dir;
use std::fmt;
use std::path::PathBuf;
use vk_gen_examples::examples::{
    circuit_layout, serialization, shuffle, simple_example, two_chip, vector_mul,
};

#[derive(Parser)]
struct Cli {
    #[arg(long = "verifier-module", default_value = "halo2_verifier")]
    verifier_module: String,
    #[arg(long = "verifier-address")]
    verifier_address: String,
    #[arg(long = "publish-vk-func", default_value = "publish_vk")]
    publish_vk_func: String,
    #[arg(short, default_value = "10")]
    k: u8,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    BuildPublishVkAptosTxn(BuildPublishVkAptosTxn),
    BuildVerifyProofAptosTxn(BuildQuery),
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

#[derive(Parser)]
struct BuildQuery {
    #[arg(long)]
    function_id: String,
    #[arg(long)]
    args: Vec<String>,
    #[arg(long)]
    type_args: Vec<String>,
    #[arg(long = "agger")]
    agger_address: String,
}

fn main() -> anyhow::Result<()> {
    let cli: Cli = Cli::parse();
    let params = ParamsKZG::<Bn256>::new(cli.k as u32);
    match cli.command {
        Commands::BuildPublishVkAptosTxn(BuildPublishVkAptosTxn {
            example,
            output_dir,
        }) => {
            let circuit_info = match example {
                Examples::CircuitLayout => {
                    let circuit = circuit_layout::get_example_circuit::<Fr>();

                    generate_circuit_info(&params, &circuit)?
                }
                Examples::Serialization => {
                    let circuit = serialization::get_example_circuit();
                    generate_circuit_info(&params, &circuit)?
                }
                Examples::Shuffle => {
                    let circuit = shuffle::get_example_circuit();
                    generate_circuit_info(&params, &circuit)?
                }
                Examples::SimpleExample => {
                    let circuit = simple_example::get_example_circuit();
                    generate_circuit_info(&params, &circuit)?
                }
                Examples::TwoChip => {
                    let circuit = two_chip::get_example_circuit();
                    generate_circuit_info(&params, &circuit)?
                }
                Examples::VectorMul => {
                    let circuit = vector_mul::get_example_circuit();
                    generate_circuit_info(&params, &circuit)?
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
                    .join(format!("{:?}", example))
                    .with_extension("json"),
                output,
            )?;
        }
        Commands::BuildVerifyProofAptosTxn(_vp) => {}
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
