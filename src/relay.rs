use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use russh::keys::{Certificate, PublicKey, load_secret_key};
use russh::server::{self, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_yamux::Control;
use tokio_yamux::config::Config as YamuxConfig;
use tokio_yamux::session::Session as YamuxSession;
use tokio_yamux::stream::StreamHandle;
use tracing::{debug, info, warn};

use crate::agent_protocol::{
    AgentHello, AgentHelloResponse, OpenStreamRequest, OpenStreamResponse, PROTOCOL_VERSION,
    read_json_line, write_json_line,
};
use crate::config::RelayConfig;
use crate::tls;
use crate::token::verify_token;

#[derive(Clone)]
pub struct RelayState {
    config: RelayConfig,
    online_agents: Arc<RwLock<HashMap<String, AgentHandle>>>,
    next_connection_id: Arc<AtomicU64>,
}

#[derive(Clone)]
struct AgentHandle {
    machine_id: String,
    machine_alias: String,
    connection_id: u64,
    control: Control,
}

#[derive(Debug, thiserror::Error)]
pub enum RelayRouteError {
    #[error("unknown machine alias {0}")]
    UnknownMachine(String),
    #[error("user {user} is not allowed to access {machine_alias}")]
    Unauthorized { user: String, machine_alias: String },
    #[error("machine {0} is offline")]
    Offline(String),
    #[error("agent stream open failed: {0}")]
    AgentStream(String),
    #[error("agent rejected stream: {0}")]
    AgentRejected(String),
}

impl RelayState {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            online_agents: Arc::new(RwLock::new(HashMap::new())),
            next_connection_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    async fn register_agent(&self, machine_id: &str, control: Control) -> Result<AgentHandle> {
        let machine = self
            .config
            .machine_by_id(machine_id)
            .with_context(|| format!("unknown machine_id {machine_id}"))?;
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        let handle = AgentHandle {
            machine_id: machine.machine_id.clone(),
            machine_alias: machine.machine_alias.clone(),
            connection_id,
            control,
        };
        self.online_agents
            .write()
            .await
            .insert(machine.machine_alias.clone(), handle.clone());
        Ok(handle)
    }

    async fn unregister_agent(&self, handle: &AgentHandle) {
        let mut online = self.online_agents.write().await;
        if online
            .get(&handle.machine_alias)
            .is_some_and(|current| current.connection_id == handle.connection_id)
        {
            online.remove(&handle.machine_alias);
        }
    }

    pub async fn open_agent_stream(
        &self,
        user: &str,
        machine_alias: &str,
        port: u32,
    ) -> Result<StreamHandle, RelayRouteError> {
        if port != 22 {
            return Err(RelayRouteError::AgentRejected(format!(
                "port {port} is not allowed"
            )));
        }

        let machine = self
            .config
            .machine_by_alias(machine_alias)
            .ok_or_else(|| RelayRouteError::UnknownMachine(machine_alias.to_string()))?;
        if !self.config.user_can_access(user, machine_alias) {
            return Err(RelayRouteError::Unauthorized {
                user: user.to_string(),
                machine_alias: machine_alias.to_string(),
            });
        }

        let mut control = {
            let online = self.online_agents.read().await;
            online
                .get(machine_alias)
                .map(|agent| agent.control.clone())
                .ok_or_else(|| RelayRouteError::Offline(machine_alias.to_string()))?
        };

        let mut stream = control
            .open_stream()
            .await
            .map_err(|err| RelayRouteError::AgentStream(err.to_string()))?;
        let request = OpenStreamRequest {
            version: PROTOCOL_VERSION,
            target: machine.target.clone(),
        };
        write_json_line(&mut stream, &request)
            .await
            .map_err(|err| RelayRouteError::AgentStream(err.to_string()))?;
        let response: OpenStreamResponse = read_json_line(&mut stream)
            .await
            .map_err(|err| RelayRouteError::AgentStream(err.to_string()))?;
        if !response.ok {
            return Err(RelayRouteError::AgentRejected(
                response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string()),
            ));
        }

        Ok(stream)
    }
}

pub async fn run_relay_server(config: RelayConfig) -> Result<()> {
    let state = RelayState::new(config);
    let ssh = run_ssh_listener(state.clone());
    let agent = run_agent_listener(state);
    tokio::try_join!(ssh, agent)?;
    Ok(())
}

async fn run_ssh_listener(state: RelayState) -> Result<()> {
    let key = load_secret_key(&state.config.server.ssh_host_key, None).with_context(|| {
        format!(
            "failed to load SSH host key {}",
            state.config.server.ssh_host_key.display()
        )
    })?;
    let config = russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![key],
        ..Default::default()
    };
    let config = Arc::new(config);
    let listener = TcpListener::bind(state.config.server.ssh_listen)
        .await
        .with_context(|| {
            format!(
                "failed to bind SSH listener {}",
                state.config.server.ssh_listen
            )
        })?;
    info!("ssh listener bound to {}", state.config.server.ssh_listen);
    let mut server = SshRelayServer { state };
    server.run_on_socket(config, &listener).await?;
    Ok(())
}

async fn run_agent_listener(state: RelayState) -> Result<()> {
    let listener = TcpListener::bind(state.config.server.agent_listen)
        .await
        .with_context(|| {
            format!(
                "failed to bind agent listener {}",
                state.config.server.agent_listen
            )
        })?;
    info!(
        "agent listener bound to {}",
        state.config.server.agent_listen
    );

    let tls_acceptor = match (
        &state.config.server.agent_tls_cert,
        &state.config.server.agent_tls_key,
    ) {
        (Some(cert), Some(key)) => {
            let config = tls::server_config(cert, key)?;
            Some(tokio_rustls::TlsAcceptor::from(config))
        }
        _ => {
            warn!(
                "agent listener is running without TLS; configure agent_tls_cert and agent_tls_key before exposing it"
            );
            None
        }
    };

    loop {
        let (socket, peer) = listener.accept().await?;
        let state = state.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let result = async {
                if let Some(acceptor) = tls_acceptor {
                    let stream = acceptor
                        .accept(socket)
                        .await
                        .context("agent TLS handshake failed")?;
                    handle_agent_connection(state, stream).await
                } else {
                    handle_agent_connection(state, socket).await
                }
            }
            .await;
            if let Err(err) = result {
                warn!(%peer, error = %err, "agent connection ended with error");
            }
        });
    }
}

async fn handle_agent_connection<S>(state: RelayState, mut stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let hello: AgentHello = read_json_line(&mut stream).await?;
    if hello.version != PROTOCOL_VERSION {
        write_json_line(
            &mut stream,
            &AgentHelloResponse::reject("unsupported protocol version"),
        )
        .await?;
        bail!("agent used unsupported protocol version {}", hello.version);
    }

    let Some(machine) = state.config.machine_by_id(&hello.machine_id) else {
        write_json_line(
            &mut stream,
            &AgentHelloResponse::reject("unknown machine_id"),
        )
        .await?;
        bail!("unknown machine_id {}", hello.machine_id);
    };
    if !verify_token(&hello.agent_token, &machine.agent_token_hash) {
        write_json_line(
            &mut stream,
            &AgentHelloResponse::reject("authentication failed"),
        )
        .await?;
        bail!("agent authentication failed for {}", hello.machine_id);
    }
    write_json_line(&mut stream, &AgentHelloResponse::ok()).await?;

    let mut session = YamuxSession::new_client(stream, YamuxConfig::default());
    let handle = state
        .register_agent(&hello.machine_id, session.control())
        .await?;
    info!(
        machine_id = %handle.machine_id,
        machine_alias = %handle.machine_alias,
        connection_id = handle.connection_id,
        "agent registered"
    );

    while let Some(result) = session.next().await {
        match result {
            Ok(mut stream) => {
                warn!(
                    machine_alias = %handle.machine_alias,
                    stream_id = stream.id(),
                    "agent opened an unexpected inbound yamux stream; closing it"
                );
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
            }
            Err(err) => {
                warn!(
                    machine_alias = %handle.machine_alias,
                    error = %err,
                    "agent yamux session error"
                );
                break;
            }
        }
    }

    state.unregister_agent(&handle).await;
    info!(
        machine_id = %handle.machine_id,
        machine_alias = %handle.machine_alias,
        connection_id = handle.connection_id,
        "agent unregistered"
    );
    Ok(())
}

#[derive(Clone)]
struct SshRelayServer {
    state: RelayState,
}

impl server::Server for SshRelayServer {
    type Handler = SshRelaySession;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        SshRelaySession {
            state: self.state.clone(),
            authenticated_user: None,
            peer_addr,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        warn!(%error, "ssh session error");
    }
}

struct SshRelaySession {
    state: RelayState,
    authenticated_user: Option<String>,
    peer_addr: Option<std::net::SocketAddr>,
}

impl server::Handler for SshRelaySession {
    type Error = anyhow::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        _password: &str,
    ) -> Result<server::Auth, Self::Error> {
        warn!(user, peer = ?self.peer_addr, "password auth rejected");
        Ok(server::Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        if self.state.config.user_key_allowed(user, public_key) {
            Ok(server::Auth::Accept)
        } else {
            warn!(user, peer = ?self.peer_addr, "unknown public key offered");
            Ok(server::Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        if self.state.config.user_key_allowed(user, public_key) {
            self.authenticated_user = Some(user.to_string());
            info!(user, peer = ?self.peer_addr, "ssh relay user authenticated");
            Ok(server::Auth::Accept)
        } else {
            warn!(user, peer = ?self.peer_addr, "public key auth rejected");
            Ok(server::Auth::reject())
        }
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        _certificate: &Certificate,
    ) -> Result<server::Auth, Self::Error> {
        warn!(user, peer = ?self.peer_addr, "openssh certificate auth rejected");
        Ok(server::Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        warn!(
            user = ?self.authenticated_user,
            peer = ?self.peer_addr,
            "shell/session channel rejected"
        );
        Ok(false)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(user) = self.authenticated_user.as_deref() else {
            warn!(peer = ?self.peer_addr, "direct-tcpip rejected before auth");
            return Ok(false);
        };

        debug!(
            user,
            machine_alias = host_to_connect,
            port = port_to_connect,
            originator_address,
            originator_port,
            "direct-tcpip requested"
        );

        let stream = match self
            .state
            .open_agent_stream(user, host_to_connect, port_to_connect)
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                warn!(
                    user,
                    machine_alias = host_to_connect,
                    port = port_to_connect,
                    error = %err,
                    "direct-tcpip rejected"
                );
                return Ok(false);
            }
        };

        let machine_alias = host_to_connect.to_string();
        tokio::spawn(async move {
            if let Err(err) = relay_channel_to_agent(channel, stream).await {
                debug!(machine_alias, error = %err, "relay stream ended");
            }
        });
        Ok(true)
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        warn!(?channel, "unexpected handler-level data event");
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        _code: u32,
        _data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        warn!(?channel, "unexpected handler-level extended data event");
        Ok(())
    }
}

async fn relay_channel_to_agent(
    channel: Channel<Msg>,
    mut agent_stream: StreamHandle,
) -> Result<()> {
    let mut ssh_stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut ssh_stream, &mut agent_stream)
        .await
        .map(|_| ())
        .map_err(|err| anyhow!("stream copy failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_protocol::{OpenStreamRequest, OpenStreamResponse};
    use crate::token::hash_token;
    use russh::keys::{Algorithm, PrivateKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::sync::oneshot;

    fn relay_config() -> RelayConfig {
        let user_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let token_hash = hash_token("01234567890123456789012345678901").unwrap();
        let raw = format!(
            r#"
[server]
ssh_listen = "127.0.0.1:2222"
agent_listen = "127.0.0.1:4443"
ssh_host_key = "/tmp/slay-test-host-key"

[users.alice]
public_keys = ["{}"]
allowed_machines = ["alice-home-linux"]

[machines.alice_home]
machine_id = "mch_01"
machine_alias = "alice-home-linux"
display_name = "Alice Home"
agent_token_hash = "{}"
target = "127.0.0.1:22"
"#,
            user_key.public_key().to_openssh().unwrap(),
            token_hash
        );
        RelayConfig::from_toml_str(&raw).unwrap()
    }

    #[tokio::test]
    async fn opens_agent_stream_after_acl_check() {
        let state = RelayState::new(relay_config());
        let (relay_io, agent_io) = duplex(64 * 1024);
        let mut relay_session = YamuxSession::new_client(relay_io, YamuxConfig::default());
        let handle = state
            .register_agent("mch_01", relay_session.control())
            .await
            .unwrap();

        let relay_driver = tokio::spawn(async move {
            while let Some(result) = relay_session.next().await {
                result.unwrap();
            }
        });

        let (stop_tx, stop_rx) = oneshot::channel();
        let agent = tokio::spawn(async move {
            let mut agent_session = YamuxSession::new_server(agent_io, YamuxConfig::default());
            let mut stop_rx = Box::pin(stop_rx);

            loop {
                tokio::select! {
                    result = agent_session.next() => {
                        let mut stream = result.unwrap().unwrap();
                        tokio::spawn(async move {
                            let request: OpenStreamRequest = read_json_line(&mut stream).await.unwrap();
                            assert_eq!(request.target, "127.0.0.1:22");
                            write_json_line(&mut stream, &OpenStreamResponse::ok()).await.unwrap();

                            let mut buf = [0_u8; 4];
                            stream.read_exact(&mut buf).await.unwrap();
                            stream.write_all(&buf).await.unwrap();
                        });
                    }
                    _ = &mut stop_rx => break,
                }
            }
        });

        let mut stream = state
            .open_agent_stream("alice", "alice-home-linux", 22)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        let _ = stop_tx.send(());
        state.unregister_agent(&handle).await;
        relay_driver.abort();
        agent.await.unwrap();
    }

    #[tokio::test]
    async fn denies_unauthorized_agent_stream() {
        let state = RelayState::new(relay_config());
        let err = state
            .open_agent_stream("bob", "alice-home-linux", 22)
            .await
            .unwrap_err();
        assert!(matches!(err, RelayRouteError::Unauthorized { .. }));
    }
}
