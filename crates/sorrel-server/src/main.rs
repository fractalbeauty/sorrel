use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Cli {
    /// Configuration files to use. Later files override earlier ones.
    #[arg(short, long)]
    config: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    sorrel_server::run(cli.config).await
}
