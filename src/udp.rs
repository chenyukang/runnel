use anyhow::{Context, Result, bail};
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_UDP_FRAME_SIZE: usize = u16::MAX as usize;

pub async fn read_frame<R>(reader: &mut R, max_size: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 2];
    reader
        .read_exact(&mut prefix)
        .await
        .context("failed to read UDP frame length")?;
    let length = u16::from_be_bytes(prefix) as usize;
    if length > max_size {
        bail!("UDP frame exceeded {max_size} bytes");
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .context("failed to read UDP frame payload")?;
    Ok(payload)
}

pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_UDP_FRAME_SIZE {
        bail!("UDP payload exceeded {} bytes", MAX_UDP_FRAME_SIZE);
    }
    writer
        .write_all(&(payload.len() as u16).to_be_bytes())
        .await
        .context("failed to write UDP frame length")?;
    writer
        .write_all(payload)
        .await
        .context("failed to write UDP frame payload")?;
    writer.flush().await.context("failed to flush UDP frame")?;
    Ok(())
}

pub fn is_eof(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == ErrorKind::UnexpectedEof)
    })
}

#[cfg(test)]
mod tests {
    use super::{read_frame, write_frame};
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_round_trip_works() {
        let (mut writer, mut reader) = duplex(64);
        write_frame(&mut writer, b"hello").await.unwrap();
        let payload = read_frame(&mut reader, 16).await.unwrap();
        assert_eq!(payload, b"hello");
    }
}
