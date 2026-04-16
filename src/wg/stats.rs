use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use tracing::debug;

use crate::telemetry;

use super::{WgDeviceStats, read_device_stats};

const STATS_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) fn start_stats_poller(role: &'static str, socket_path: PathBuf) {
    let _ = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(STATS_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous = None;

        loop {
            ticker.tick().await;
            let path = socket_path.clone();
            let sample = tokio::task::spawn_blocking(move || read_device_stats(&path)).await;

            match sample {
                Ok(Ok(current)) => {
                    if let Some((uploaded, downloaded)) = traffic_delta(previous, current) {
                        emit_sample(role, uploaded, downloaded);
                    }
                    previous = Some(current);
                }
                Ok(Err(error)) => {
                    debug!(
                        uapi_socket = %socket_path.display(),
                        error = %error,
                        "failed to poll wg stats"
                    );
                }
                Err(error) => {
                    debug!(
                        uapi_socket = %socket_path.display(),
                        error = %error,
                        "wg stats poll task failed"
                    );
                }
            }
        }
    });
}

fn traffic_delta(previous: Option<WgDeviceStats>, current: WgDeviceStats) -> Option<(u64, u64)> {
    let previous = previous?;
    if current.rx_bytes < previous.rx_bytes || current.tx_bytes < previous.tx_bytes {
        return None;
    }

    let downloaded = current.rx_bytes - previous.rx_bytes;
    let uploaded = current.tx_bytes - previous.tx_bytes;
    (uploaded > 0 || downloaded > 0).then_some((uploaded, downloaded))
}

fn emit_sample(role: &str, uploaded: u64, downloaded: u64) {
    let mut fields = BTreeMap::new();
    fields.insert("target".to_owned(), "wireguard".to_owned());
    fields.insert("link".to_owned(), "wg://wireguard".to_owned());
    fields.insert("route".to_owned(), role.to_owned());
    fields.insert("mode".to_owned(), "wg".to_owned());
    fields.insert("aggregate".to_owned(), "true".to_owned());
    fields.insert("uploaded".to_owned(), uploaded.to_string());
    fields.insert("downloaded".to_owned(), downloaded.to_string());
    telemetry::emit("INFO", "traffic sample", fields);
}

#[cfg(test)]
mod tests {
    use super::traffic_delta;
    use crate::wg::WgDeviceStats;

    #[test]
    fn traffic_delta_uses_tx_as_uploaded_and_rx_as_downloaded() {
        assert_eq!(
            traffic_delta(
                Some(WgDeviceStats {
                    rx_bytes: 100,
                    tx_bytes: 200,
                }),
                WgDeviceStats {
                    rx_bytes: 175,
                    tx_bytes: 260,
                },
            ),
            Some((60, 75))
        );
    }

    #[test]
    fn traffic_delta_ignores_initial_zero_and_counter_resets() {
        assert_eq!(
            traffic_delta(
                None,
                WgDeviceStats {
                    rx_bytes: 175,
                    tx_bytes: 260,
                },
            ),
            None
        );
        assert_eq!(
            traffic_delta(
                Some(WgDeviceStats {
                    rx_bytes: 175,
                    tx_bytes: 260,
                }),
                WgDeviceStats {
                    rx_bytes: 100,
                    tx_bytes: 200,
                },
            ),
            None
        );
    }

    #[test]
    fn traffic_delta_drops_empty_samples() {
        let sample = WgDeviceStats {
            rx_bytes: 100,
            tx_bytes: 200,
        };

        assert_eq!(traffic_delta(Some(sample), sample), None);
    }
}
