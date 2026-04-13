use anyhow::{Context, Result};
use clap::Args;
use std::{fs, path::PathBuf};

#[derive(Clone, Debug, Args)]
pub struct CertArgs {
    #[arg(long, default_value = "server.crt")]
    pub cert: PathBuf,
    #[arg(long, default_value = "server.key")]
    pub key: PathBuf,
    #[arg(long = "name", num_args = 1.., value_delimiter = ',')]
    pub names: Vec<String>,
}

pub fn run(args: CertArgs) -> Result<()> {
    if args.names.is_empty() {
        anyhow::bail!("certificate names are required; pass --name or set them in --config");
    }
    let certified = rcgen::generate_simple_self_signed(args.names.clone())
        .context("failed to generate self-signed certificate")?;

    fs::write(&args.cert, certified.cert.pem())
        .with_context(|| format!("failed to write {}", args.cert.display()))?;
    fs::write(&args.key, certified.key_pair.serialize_pem())
        .with_context(|| format!("failed to write {}", args.key.display()))?;

    println!(
        "generated certificate at {} and key at {}",
        args.cert.display(),
        args.key.display()
    );
    Ok(())
}
