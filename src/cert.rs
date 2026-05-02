use anyhow::{Context, Result};
use clap::Args;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

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
    write_private_key_file(&args.key, &certified.key_pair.serialize_pem())
        .with_context(|| format!("failed to write {}", args.key.display()))?;

    println!(
        "generated certificate at {} and key at {}",
        args.cert.display(),
        args.key.display()
    );
    Ok(())
}

fn write_private_key_file(path: &Path, contents: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let mut file = options.open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(contents.as_bytes())?;
        file.flush()?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn private_key_file_is_written_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "runnel-key-perms-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        write_private_key_file(&path, "secret\n").expect("key should be written");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let contents = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(mode, 0o600);
        assert_eq!(contents, "secret\n");
    }
}
