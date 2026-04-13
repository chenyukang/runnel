use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    time::{MissedTickBehavior, interval},
};

use crate::telemetry;

#[derive(Clone, Debug, Default)]
pub struct RelayLabels {
    pub target: String,
    pub route: Option<String>,
    pub mode: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RelayStats {
    pub uploaded: u64,
    pub downloaded: u64,
    pub sampled: bool,
}

pub async fn relay_with_telemetry<A, B>(
    left: A,
    right: B,
    labels: RelayLabels,
) -> io::Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut left_reader, mut left_writer) = tokio::io::split(left);
    let (mut right_reader, mut right_writer) = tokio::io::split(right);

    let uploaded = Arc::new(AtomicU64::new(0));
    let downloaded = Arc::new(AtomicU64::new(0));
    let sampled = Arc::new(AtomicBool::new(false));
    let (stop_tx, stop_rx) = watch::channel(false);

    let sampler = tokio::spawn(sample_traffic(
        labels,
        uploaded.clone(),
        downloaded.clone(),
        sampled.clone(),
        stop_rx,
    ));

    let transfer = tokio::try_join!(
        copy_one_direction(&mut left_reader, &mut right_writer, uploaded.clone()),
        copy_one_direction(&mut right_reader, &mut left_writer, downloaded.clone()),
    );

    let _ = stop_tx.send(true);
    let _ = sampler.await;

    transfer?;

    Ok(RelayStats {
        uploaded: uploaded.load(Ordering::Relaxed),
        downloaded: downloaded.load(Ordering::Relaxed),
        sampled: sampled.load(Ordering::Relaxed),
    })
}

async fn copy_one_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    total: Arc<AtomicU64>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buf[..read]).await?;
        total.fetch_add(read as u64, Ordering::Relaxed);
    }
}

async fn sample_traffic(
    labels: RelayLabels,
    uploaded: Arc<AtomicU64>,
    downloaded: Arc<AtomicU64>,
    sampled: Arc<AtomicBool>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut last_uploaded = 0_u64;
    let mut last_downloaded = 0_u64;
    let mut ticker = interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                emit_delta(
                    &labels,
                    &uploaded,
                    &downloaded,
                    &sampled,
                    &mut last_uploaded,
                    &mut last_downloaded,
                );
            }
            changed = stop_rx.changed() => {
                if changed.is_ok() && *stop_rx.borrow() {
                    emit_delta(
                        &labels,
                        &uploaded,
                        &downloaded,
                        &sampled,
                        &mut last_uploaded,
                        &mut last_downloaded,
                    );
                    return;
                }
            }
        }
    }
}

fn emit_delta(
    labels: &RelayLabels,
    uploaded: &AtomicU64,
    downloaded: &AtomicU64,
    sampled: &AtomicBool,
    last_uploaded: &mut u64,
    last_downloaded: &mut u64,
) {
    let current_uploaded = uploaded.load(Ordering::Relaxed);
    let current_downloaded = downloaded.load(Ordering::Relaxed);
    let delta_uploaded = current_uploaded.saturating_sub(*last_uploaded);
    let delta_downloaded = current_downloaded.saturating_sub(*last_downloaded);

    *last_uploaded = current_uploaded;
    *last_downloaded = current_downloaded;

    if delta_uploaded == 0 && delta_downloaded == 0 {
        return;
    }

    sampled.store(true, Ordering::Relaxed);
    let mut fields = BTreeMap::new();
    fields.insert("target".to_owned(), labels.target.clone());
    fields.insert("uploaded".to_owned(), delta_uploaded.to_string());
    fields.insert("downloaded".to_owned(), delta_downloaded.to_string());
    if let Some(route) = &labels.route {
        fields.insert("route".to_owned(), route.clone());
    }
    if let Some(mode) = &labels.mode {
        fields.insert("mode".to_owned(), mode.clone());
    }
    telemetry::emit("INFO", "traffic sample", fields);
}
