use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_LEN: usize = 16 * 1024;

#[derive(Debug, Deserialize, Serialize)]
pub struct AgentHello {
    pub version: u16,
    pub machine_id: String,
    pub agent_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AgentHelloResponse {
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OpenStreamRequest {
    pub version: u16,
    pub target: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OpenStreamResponse {
    pub ok: bool,
    pub error: Option<String>,
}

impl AgentHelloResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }

    pub fn reject(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
        }
    }
}

impl OpenStreamResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }

    pub fn reject(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
        }
    }
}

pub async fn write_json_line<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut frame = serde_json::to_vec(value).context("failed to serialize protocol frame")?;
    frame.push(b'\n');
    writer
        .write_all(&frame)
        .await
        .context("failed to write protocol frame")?;
    writer
        .flush()
        .await
        .context("failed to flush protocol frame")
}

pub async fn read_json_line<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut frame = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    loop {
        let n = reader
            .read(&mut byte)
            .await
            .context("failed to read protocol frame")?;
        if n == 0 {
            bail!("connection closed while reading protocol frame");
        }
        if byte[0] == b'\n' {
            break;
        }
        frame.push(byte[0]);
        if frame.len() > MAX_FRAME_LEN {
            bail!("protocol frame exceeds {MAX_FRAME_LEN} bytes");
        }
    }

    serde_json::from_slice(&frame).context("failed to parse protocol frame")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    #[tokio::test]
    async fn round_trips_json_line_frame() {
        let (mut client, mut server) = duplex(1024);
        let hello = AgentHello {
            version: PROTOCOL_VERSION,
            machine_id: "mch_01".to_string(),
            agent_token: "01234567890123456789012345678901".to_string(),
        };

        write_json_line(&mut client, &hello).await.unwrap();
        let parsed: AgentHello = read_json_line(&mut server).await.unwrap();

        assert_eq!(parsed.version, PROTOCOL_VERSION);
        assert_eq!(parsed.machine_id, "mch_01");
        assert_eq!(parsed.agent_token, "01234567890123456789012345678901");
    }

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let (mut client, mut server) = duplex(MAX_FRAME_LEN + 2);
        client
            .write_all(&vec![b'a'; MAX_FRAME_LEN + 1])
            .await
            .unwrap();
        client.write_all(b"\n").await.unwrap();

        let err = read_json_line::<_, AgentHello>(&mut server)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }
}
