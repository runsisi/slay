use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_yamux::config::Config as YamuxConfig;
use tokio_yamux::session::Session as YamuxSession;
use tokio_yamux::stream::StreamHandle;
use tracing::{debug, info, warn};

use crate::agent_protocol::{
    AgentHello, AgentHelloResponse, OpenStreamRequest, OpenStreamResponse, PROTOCOL_VERSION,
    read_json_line, write_json_line,
};
use crate::config::AgentConfig;
use crate::tls;

pub async fn run_agent(config: AgentConfig) -> Result<()> {
    loop {
        match connect_once(config.clone()).await {
            Ok(()) => warn!("agent connection closed"),
            Err(err) => warn!(error = %err, "agent connection failed"),
        }
        tokio::time::sleep(Duration::from_secs(config.reconnect_secs)).await;
    }
}

async fn connect_once(config: AgentConfig) -> Result<()> {
    let tcp = TcpStream::connect(&config.relay_addr)
        .await
        .with_context(|| format!("failed to connect relay {}", config.relay_addr))?;
    let stream = if config.relay_ca_cert.is_some() {
        let client_config = tls::client_config(config.relay_ca_cert.as_deref())?;
        let connector = TlsConnector::from(client_config);
        let server_name = ServerName::try_from(config.relay_server_name()?)
            .context("invalid relay TLS server name")?;
        EitherStream::Tls(Box::new(
            connector
                .connect(server_name, tcp)
                .await
                .context("agent TLS handshake failed")?,
        ))
    } else {
        warn!("agent is connecting without TLS because relay_ca_cert is not configured");
        EitherStream::Plain(tcp)
    };

    run_authenticated_session(config, stream).await
}

async fn run_authenticated_session<S>(config: AgentConfig, mut stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let hello = AgentHello {
        version: PROTOCOL_VERSION,
        machine_id: config.machine_id.clone(),
        agent_token: config.agent_token.clone(),
    };
    write_json_line(&mut stream, &hello).await?;
    let response: AgentHelloResponse = read_json_line(&mut stream).await?;
    if !response.ok {
        bail!(
            "relay rejected agent: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        );
    }
    info!(machine_id = %config.machine_id, "agent authenticated");

    let mut session = YamuxSession::new_server(stream, YamuxConfig::default());
    while let Some(result) = session.next().await {
        match result {
            Ok(stream) => {
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_stream(config, stream).await {
                        debug!(error = %err, "agent stream ended");
                    }
                });
            }
            Err(err) => {
                return Err(err).context("yamux session error");
            }
        }
    }
    Ok(())
}

async fn handle_stream(config: AgentConfig, mut relay_stream: StreamHandle) -> Result<()> {
    let request: OpenStreamRequest = read_json_line(&mut relay_stream).await?;
    if request.version != PROTOCOL_VERSION {
        write_json_line(
            &mut relay_stream,
            &OpenStreamResponse::reject("unsupported protocol version"),
        )
        .await?;
        bail!("unsupported stream protocol version {}", request.version);
    }
    if request.target != config.target {
        write_json_line(
            &mut relay_stream,
            &OpenStreamResponse::reject("target is not allowed by agent config"),
        )
        .await?;
        bail!("relay requested disallowed target {}", request.target);
    }

    let mut target = TcpStream::connect(&config.target)
        .await
        .with_context(|| format!("failed to connect local target {}", config.target))?;
    write_json_line(&mut relay_stream, &OpenStreamResponse::ok()).await?;
    tokio::io::copy_bidirectional(&mut relay_stream, &mut target)
        .await
        .context("agent stream copy failed")?;
    let _ = relay_stream.shutdown().await;
    let _ = target.shutdown().await;
    Ok(())
}

enum EitherStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for EitherStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for EitherStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}
