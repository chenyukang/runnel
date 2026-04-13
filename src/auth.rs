use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct AuthProof {
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

impl AuthProof {
    pub fn sign(password: &str, method: &str, path: &str, target: &str) -> Result<Self> {
        let timestamp = unix_timestamp()?;
        let nonce = random_nonce();
        let signature = sign(password, method, path, target, timestamp, &nonce)?;
        Ok(Self {
            timestamp,
            nonce,
            signature,
        })
    }
}

#[derive(Debug)]
pub struct ReplayProtector {
    ttl: Duration,
    seen: Mutex<HashMap<String, i64>>,
}

impl ReplayProtector {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            seen: Mutex::new(HashMap::new()),
        }
    }

    pub fn validate(
        &self,
        password: &str,
        method: &str,
        path: &str,
        target: &str,
        proof: &AuthProof,
    ) -> Result<()> {
        let now = unix_timestamp()?;
        let skew = now.abs_diff(proof.timestamp);
        if skew > self.ttl.as_secs() {
            bail!("timestamp outside allowed window");
        }

        let mut seen = self.seen.lock().expect("replay cache poisoned");
        let oldest = now - self.ttl.as_secs() as i64;
        seen.retain(|_, ts| *ts >= oldest);

        if seen.contains_key(&proof.nonce) {
            bail!("nonce already used");
        }

        let expected = sign(
            password,
            method,
            path,
            target,
            proof.timestamp,
            &proof.nonce,
        )?;
        let actual = URL_SAFE_NO_PAD
            .decode(proof.signature.as_bytes())
            .context("invalid signature encoding")?;
        let expected = URL_SAFE_NO_PAD
            .decode(expected.as_bytes())
            .context("invalid locally generated signature encoding")?;

        if actual != expected {
            bail!("signature mismatch");
        }

        seen.insert(proof.nonce.clone(), proof.timestamp);
        Ok(())
    }
}

pub fn sign(
    password: &str,
    method: &str,
    path: &str,
    target: &str,
    timestamp: i64,
    nonce: &str,
) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(password.as_bytes()).context("invalid HMAC key")?;
    mac.update(signature_input(method, path, target, timestamp, nonce).as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn signature_input(method: &str, path: &str, target: &str, timestamp: i64, nonce: &str) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n",
        method.to_ascii_uppercase(),
        path,
        target,
        timestamp,
        nonce
    )
}

fn unix_timestamp() -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?;
    Ok(now.as_secs() as i64)
}

fn random_nonce() -> String {
    let mut nonce = [0_u8; 16];
    OsRng.fill_bytes(&mut nonce);
    URL_SAFE_NO_PAD.encode(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_round_trip_and_replay_protection() {
        let validator = ReplayProtector::new(Duration::from_secs(120));
        let proof = AuthProof::sign("secret", "POST", "/connect", "example.com:443").unwrap();

        validator
            .validate("secret", "POST", "/connect", "example.com:443", &proof)
            .unwrap();

        let err = validator
            .validate("secret", "POST", "/connect", "example.com:443", &proof)
            .unwrap_err();
        assert!(err.to_string().contains("nonce already used"));
    }
}
