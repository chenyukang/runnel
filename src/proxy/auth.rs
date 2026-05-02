use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type HmacSha256 = Hmac<Sha256>;

pub const AUTH_FAILURE_BODY: &str =
    "authentication failed; check that client and server passwords match\n";
pub const AUTH_FAILURE_HINT: &str = "client and server passwords may not match";

#[derive(Clone, Debug)]
pub struct AuthProof {
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

impl AuthProof {
    pub fn sign(password: &str, method: &str, path: &str, target: &str) -> Result<Self> {
        let timestamp = unix_timestamp()?;
        let nonce = random_nonce()?;
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
    seen: Mutex<ReplayState>,
}

#[derive(Debug, Default)]
struct ReplayState {
    seen: HashMap<String, i64>,
    order: VecDeque<(String, i64)>,
}

impl ReplayProtector {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            seen: Mutex::new(ReplayState::default()),
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
        while let Some((_, ts)) = seen.order.front() {
            if *ts >= oldest {
                break;
            }
            let (nonce, ts) = seen.order.pop_front().expect("front element must exist");
            if seen.seen.get(&nonce).copied() == Some(ts) {
                seen.seen.remove(&nonce);
            }
        }

        if seen.seen.contains_key(&proof.nonce) {
            bail!("nonce already used");
        }

        let actual = URL_SAFE_NO_PAD
            .decode(proof.signature.as_bytes())
            .context("invalid signature encoding")?;
        verify(
            password,
            method,
            path,
            target,
            proof.timestamp,
            &proof.nonce,
            &actual,
        )?;

        seen.order.push_back((proof.nonce.clone(), proof.timestamp));
        seen.seen.insert(proof.nonce.clone(), proof.timestamp);
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
    Ok(URL_SAFE_NO_PAD.encode(sign_bytes(
        password, method, path, target, timestamp, nonce,
    )?))
}

fn sign_bytes(
    password: &str,
    method: &str,
    path: &str,
    target: &str,
    timestamp: i64,
    nonce: &str,
) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(password.as_bytes()).context("invalid HMAC key")?;
    update_signature_input(&mut mac, method, path, target, timestamp, nonce);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify(
    password: &str,
    method: &str,
    path: &str,
    target: &str,
    timestamp: i64,
    nonce: &str,
    actual: &[u8],
) -> Result<()> {
    let mut mac = HmacSha256::new_from_slice(password.as_bytes()).context("invalid HMAC key")?;
    update_signature_input(&mut mac, method, path, target, timestamp, nonce);
    mac.verify_slice(actual)
        .map_err(|_| anyhow::anyhow!("signature mismatch"))
}

fn update_signature_input(
    mac: &mut HmacSha256,
    method: &str,
    path: &str,
    target: &str,
    timestamp: i64,
    nonce: &str,
) {
    match method.bytes().any(|byte| byte.is_ascii_lowercase()) {
        true => {
            let uppercase = method.to_ascii_uppercase();
            mac.update(uppercase.as_bytes());
        }
        false => mac.update(method.as_bytes()),
    }

    let timestamp = timestamp.to_string();
    for part in [
        path.as_bytes(),
        target.as_bytes(),
        timestamp.as_bytes(),
        nonce.as_bytes(),
    ] {
        mac.update(b"\n");
        mac.update(part);
    }
    mac.update(b"\n");
}

fn unix_timestamp() -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?;
    Ok(now.as_secs() as i64)
}

fn random_nonce() -> Result<String> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).context("failed to generate auth nonce")?;
    Ok(URL_SAFE_NO_PAD.encode(nonce))
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
