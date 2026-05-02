use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::x25519::{PublicKey, StaticSecret};
use clap::Args;
use serde::Serialize;

use super::parse_key;

#[derive(Clone, Debug, Args)]
pub struct WgKeygenArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct WgKeyMaterial {
    pub(crate) private_key: String,
    pub(crate) public_key: String,
}

pub fn run_keygen(args: WgKeygenArgs) -> Result<()> {
    let material = generate_key_material()?;
    print_key_material(&material, args.json)?;
    Ok(())
}

pub(crate) fn generate_key_material() -> Result<WgKeyMaterial> {
    let mut private_key = [0_u8; super::WG_KEY_LEN];
    getrandom::fill(&mut private_key)?;
    let public_key = *PublicKey::from(&StaticSecret::from(private_key)).as_bytes();
    Ok(WgKeyMaterial {
        private_key: STANDARD.encode(private_key),
        public_key: STANDARD.encode(public_key),
    })
}

pub(crate) fn public_key_from_private_key(encoded_private_key: &str) -> Result<String> {
    let private_key = parse_key("wg private_key", encoded_private_key)?;
    let public_key = *PublicKey::from(&StaticSecret::from(private_key)).as_bytes();
    Ok(STANDARD.encode(public_key))
}

fn print_key_material(material: &WgKeyMaterial, as_json: bool) -> Result<()> {
    if as_json {
        println!("{}", serde_json::to_string_pretty(material)?);
    } else {
        println!("private_key={}", material.private_key);
        println!("public_key={}", material.public_key);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{generate_key_material, public_key_from_private_key};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use boringtun::x25519::{PublicKey, StaticSecret};

    #[test]
    fn keygen_outputs_parseable_base64_keypair() {
        let material = generate_key_material().unwrap();
        let private_key = STANDARD
            .decode(&material.private_key)
            .expect("private key should decode");
        let public_key = STANDARD
            .decode(&material.public_key)
            .expect("public key should decode");

        assert_eq!(private_key.len(), 32);
        assert_eq!(public_key.len(), 32);
        assert_eq!(
            material.public_key,
            public_key_from_private_key(&material.private_key).unwrap()
        );
    }

    #[test]
    fn pubkey_derives_expected_public_key() {
        let private_key = STANDARD.encode([7u8; 32]);
        let expected = STANDARD.encode(PublicKey::from(&StaticSecret::from([7u8; 32])).as_bytes());
        assert_eq!(public_key_from_private_key(&private_key).unwrap(), expected);
    }

    #[test]
    fn pubkey_rejects_invalid_private_key() {
        let err = public_key_from_private_key("not-base64")
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to decode"), "{err}");
    }
}
