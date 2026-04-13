use anyhow::Error;

const NOISY_PATTERNS: &[&str] = &[
    "peer closed connection without sending TLS close_notify",
    "Broken pipe (os error 32)",
    "Connection reset by peer (os error 54)",
    "Connection reset by peer (os error 104)",
];

pub fn is_noisy_disconnect(err: &Error) -> bool {
    err.chain().any(|cause| {
        let text = cause.to_string();
        NOISY_PATTERNS.iter().any(|pattern| text.contains(pattern))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noisy_disconnect_matches_wrapped_broken_pipe() {
        let err = Error::new(std::io::Error::from_raw_os_error(32)).context("direct relay failed");
        assert!(is_noisy_disconnect(&err));
    }

    #[test]
    fn noisy_disconnect_matches_close_notify_message() {
        let err = anyhow::anyhow!(
            "failed to read server response: peer closed connection without sending TLS close_notify"
        );
        assert!(is_noisy_disconnect(&err));
    }

    #[test]
    fn timeouts_stay_actionable() {
        let err = anyhow::anyhow!("direct connect timed out");
        assert!(!is_noisy_disconnect(&err));
    }
}
