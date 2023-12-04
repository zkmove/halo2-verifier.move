use clap::{Parser, Subcommand, ValueEnum};



#[derive(Parser)]
struct Cli {
    #[arg(short, long = "verifier-module")]
    verifier_module: String,
    #[arg(long = "verifier-address")]
    verifier_address: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    BuildPublishVkAptosTxn(BuildAptosDeployment),
    BuildVerifyProofAptosTxn(BuildQuery),
}

#[derive(Parser)]
struct BuildAptosDeployment {
    #[arg(long = "example", value_enum)]
    example: Examples,
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

    match cli.command {
        Commands::BuildPublishVkAptosTxn(_d) => {}
        _ => {}
    }

    Ok(())
}
