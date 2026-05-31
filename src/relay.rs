use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use russh::keys::{Certificate, PublicKey};
use russh::server::{self, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::RelayConfig;

#[derive(Clone)]
pub struct RelayState {
    config: RelayConfig,
    online_agents: Arc<RwLock<HashMap<String, AgentHandle>>>,
    forward_routes: Arc<RwLock<HashMap<(String, u32), ForwardRegistration>>>,
    next_connection_id: Arc<AtomicU64>,
}

#[derive(Clone)]
struct AgentHandle {
    connection_id: u64,
    ssh: server::Handle,
}

#[derive(Clone, Debug)]
struct ForwardRegistration {
    agent_id: String,
    connection_id: u64,
}

impl ForwardRegistration {
    fn matches(&self, registration: &AgentRegistration) -> bool {
        self.agent_id == registration.agent_id && self.connection_id == registration.connection_id
    }
}

#[derive(Clone, Debug)]
struct AgentRegistration {
    agent_id: String,
    connection_id: u64,
}

#[derive(Clone, Debug)]
enum AuthRole {
    User(String),
    Agent(String),
}

#[derive(Debug, thiserror::Error)]
pub enum RelayRouteError {
    #[error("unknown forward target {public_name}:{port}")]
    UnknownForward { public_name: String, port: u32 },
    #[error("user {user} is not allowed to access {agent_id}")]
    Unauthorized { user: String, agent_id: String },
    #[error("agent {0} is offline")]
    Offline(String),
    #[error("agent SSH forwarded channel open failed: {0}")]
    AgentChannel(String),
}

impl RelayState {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            online_agents: Arc::new(RwLock::new(HashMap::new())),
            forward_routes: Arc::new(RwLock::new(HashMap::new())),
            next_connection_id: Arc::new(AtomicU64::new(1)),
        }
    }

    async fn register_agent(
        &self,
        agent_id: &str,
        ssh: server::Handle,
    ) -> Result<AgentRegistration> {
        self.config
            .agent_by_id(agent_id)
            .with_context(|| format!("unknown agent_id {agent_id}"))?;
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        let handle = AgentHandle { connection_id, ssh };
        self.online_agents
            .write()
            .await
            .insert(agent_id.to_string(), handle);
        self.forward_routes
            .write()
            .await
            .retain(|_, forward| forward.agent_id != agent_id);
        Ok(AgentRegistration {
            agent_id: agent_id.to_string(),
            connection_id,
        })
    }

    async fn unregister_agent(&self, registration: &AgentRegistration) {
        {
            let mut online = self.online_agents.write().await;
            if online
                .get(&registration.agent_id)
                .is_some_and(|current| current.connection_id == registration.connection_id)
            {
                online.remove(&registration.agent_id);
            }
        }
        self.forward_routes
            .write()
            .await
            .retain(|_, forward| !forward.matches(registration));
    }

    async fn register_agent_forward(
        &self,
        registration: &AgentRegistration,
        public_name: &str,
        port: u32,
    ) -> bool {
        if public_forward_name_for_agent(&registration.agent_id, public_name).is_none()
            || !valid_forward_port(port)
        {
            return false;
        }

        let route = (public_name.to_string(), port);
        let mut routes = self.forward_routes.write().await;
        if routes.contains_key(&route) {
            return false;
        }
        routes.insert(
            route,
            ForwardRegistration {
                agent_id: registration.agent_id.clone(),
                connection_id: registration.connection_id,
            },
        );
        true
    }

    async fn unregister_agent_forward(
        &self,
        registration: &AgentRegistration,
        public_name: &str,
        port: u32,
    ) {
        let route = (public_name.to_string(), port);
        let mut routes = self.forward_routes.write().await;
        if routes
            .get(&route)
            .is_some_and(|forward| forward.matches(registration))
        {
            routes.remove(&route);
        }
    }

    pub async fn open_agent_channel(
        &self,
        user: &str,
        public_name: &str,
        port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<Channel<Msg>, RelayRouteError> {
        let forward = self
            .forward_routes
            .read()
            .await
            .get(&(public_name.to_string(), port))
            .cloned()
            .ok_or_else(|| RelayRouteError::UnknownForward {
                public_name: public_name.to_string(),
                port,
            })?;
        if !self.config.user_can_access(user, &forward.agent_id) {
            return Err(RelayRouteError::Unauthorized {
                user: user.to_string(),
                agent_id: forward.agent_id.to_string(),
            });
        }

        let ssh = {
            let online = self.online_agents.read().await;
            online
                .get(&forward.agent_id)
                .filter(|agent| agent.connection_id == forward.connection_id)
                .map(|agent| agent.ssh.clone())
                .ok_or_else(|| RelayRouteError::Offline(forward.agent_id.to_string()))?
        };

        ssh.channel_open_forwarded_tcpip(
            public_name.to_string(),
            port,
            originator_address.to_string(),
            originator_port,
        )
        .await
        .map_err(|err| RelayRouteError::AgentChannel(err.to_string()))
    }
}

pub async fn run_relay_server(config: RelayConfig) -> Result<()> {
    let state = RelayState::new(config);
    run_listener(state).await
}

async fn run_listener(state: RelayState) -> Result<()> {
    let config = russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![state.config.relay.host_key.clone()],
        ..Default::default()
    };
    let config = Arc::new(config);
    let listener = TcpListener::bind(state.config.relay.listen)
        .await
        .with_context(|| format!("failed to bind listener {}", state.config.relay.listen))?;
    info!("listener bound to {}", state.config.relay.listen);
    let mut server = SshRelayServer { state };
    server.run_on_socket(config, &listener).await?;
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
            auth_role: None,
            agent_registration: None,
            agent_forwards: HashSet::new(),
            peer_addr,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        warn!(%error, "ssh session error");
    }
}

struct SshRelaySession {
    state: RelayState,
    auth_role: Option<AuthRole>,
    agent_registration: Option<AgentRegistration>,
    agent_forwards: HashSet<(String, u32)>,
    peer_addr: Option<std::net::SocketAddr>,
}

impl SshRelaySession {
    fn auth_role_for_key(&self, user: &str, public_key: &PublicKey) -> Option<AuthRole> {
        if self.state.config.user_key_allowed(user, public_key) {
            return Some(AuthRole::User(user.to_string()));
        }
        if self.state.config.agent_key_allowed(user, public_key) {
            return Some(AuthRole::Agent(user.to_string()));
        }
        None
    }
}

fn public_forward_name_for_agent<'a>(agent_id: &str, public_name: &'a str) -> Option<&'a str> {
    let prefix = format!("{agent_id}-");
    let name = public_name.strip_prefix(&prefix)?;
    valid_forward_name(name).then_some(name)
}

fn valid_forward_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn valid_forward_port(port: u32) -> bool {
    port > 0 && port <= u16::MAX as u32
}

impl Drop for SshRelaySession {
    fn drop(&mut self) {
        let Some(registration) = self.agent_registration.take() else {
            return;
        };
        let state = self.state.clone();
        tokio::spawn(async move {
            state.unregister_agent(&registration).await;
            info!(
                agent_id = %registration.agent_id,
                connection_id = registration.connection_id,
                "agent unregistered"
            );
        });
    }
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
        if self.auth_role_for_key(user, public_key).is_some() {
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
        if let Some(role) = self.auth_role_for_key(user, public_key) {
            self.auth_role = Some(role.clone());
            match role {
                AuthRole::User(user) => {
                    info!(user, peer = ?self.peer_addr, "ssh relay user authenticated")
                }
                AuthRole::Agent(agent_id) => {
                    info!(agent_id, peer = ?self.peer_addr, "ssh agent authenticated")
                }
            }
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

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(AuthRole::Agent(agent_id)) = self.auth_role.as_ref() else {
            warn!(peer = ?self.peer_addr, "tcpip-forward rejected for non-agent session");
            return Ok(false);
        };
        let agent_id = agent_id.clone();
        if public_forward_name_for_agent(&agent_id, address).is_none() || !valid_forward_port(*port)
        {
            warn!(
                agent_id,
                requested_address = address,
                requested_port = *port,
                "agent tcpip-forward rejected"
            );
            return Ok(false);
        }
        let route = (address.to_string(), *port);
        if self.agent_forwards.contains(&route) {
            warn!(
                agent_id,
                requested_address = address,
                requested_port = *port,
                "duplicate agent tcpip-forward rejected"
            );
            return Ok(false);
        }

        if self.agent_registration.is_none() {
            let registration = self
                .state
                .register_agent(&agent_id, session.handle())
                .await?;
            info!(
                agent_id = %registration.agent_id,
                connection_id = registration.connection_id,
                "agent registered"
            );
            self.agent_registration = Some(registration);
        }
        let registration = self
            .agent_registration
            .as_ref()
            .expect("agent is registered");
        if !self
            .state
            .register_agent_forward(registration, address, *port)
            .await
        {
            warn!(
                agent_id,
                requested_address = address,
                requested_port = *port,
                "agent tcpip-forward collided with an active forward"
            );
            return Ok(false);
        }
        self.agent_forwards.insert(route);
        info!(
            agent_id = %registration.agent_id,
            connection_id = registration.connection_id,
            public_name = address,
            forward_port = *port,
            "agent registered SSH reverse forwarding"
        );
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(registration) = self.agent_registration.as_ref() else {
            return Ok(false);
        };
        if !self.agent_forwards.remove(&(address.to_string(), port)) {
            return Ok(false);
        }
        let registration = registration.clone();
        self.state
            .unregister_agent_forward(&registration, address, port)
            .await;
        info!(
            agent_id = %registration.agent_id,
            connection_id = registration.connection_id,
            public_name = address,
            forward_port = port,
            "agent cancelled SSH reverse forwarding"
        );
        if self.agent_forwards.is_empty() {
            self.agent_registration = None;
            self.state.unregister_agent(&registration).await;
            info!(
                agent_id = %registration.agent_id,
                connection_id = registration.connection_id,
                "agent unregistered"
            );
        }
        Ok(true)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        warn!(
            role = ?self.auth_role,
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
        let Some(AuthRole::User(user)) = self.auth_role.as_ref() else {
            warn!(peer = ?self.peer_addr, "direct-tcpip rejected before user auth");
            return Ok(false);
        };

        debug!(
            user,
            public_name = host_to_connect,
            port = port_to_connect,
            originator_address,
            originator_port,
            "direct-tcpip requested"
        );

        let agent_channel = match self
            .state
            .open_agent_channel(
                user,
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
            )
            .await
        {
            Ok(channel) => channel,
            Err(err) => {
                warn!(
                    user,
                    public_name = host_to_connect,
                    port = port_to_connect,
                    error = %err,
                    "direct-tcpip rejected"
                );
                return Ok(false);
            }
        };

        let public_name = host_to_connect.to_string();
        tokio::spawn(async move {
            if let Err(err) = relay_user_channel_to_agent(channel, agent_channel).await {
                debug!(public_name, error = %err, "relay stream ended");
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
        _channel: ChannelId,
        _data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // russh delivers data to the Channel receiver and also calls this hook.
        // Accepted proxy channels are copied from Channel::into_stream(), so
        // there is nothing else to do here.
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

async fn relay_user_channel_to_agent(
    user_channel: Channel<Msg>,
    agent_channel: Channel<Msg>,
) -> Result<()> {
    let mut user_stream = user_channel.into_stream();
    let mut agent_stream = agent_channel.into_stream();
    tokio::io::copy_bidirectional(&mut user_stream, &mut agent_stream)
        .await
        .map(|_| ())
        .map_err(|err| anyhow!("stream copy failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};

    fn public_key_line() -> String {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        key.public_key().to_openssh().unwrap()
    }

    fn private_key_block() -> String {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        key.to_openssh(LineEnding::LF).unwrap().to_string()
    }

    fn relay_config() -> RelayConfig {
        let user_key = public_key_line();
        let agent_key_a = public_key_line();
        let agent_key_b = public_key_line();
        let host_key = private_key_block();
        let raw = format!(
            r#"
[relay]
listen = "127.0.0.1:2222"
host_key = '''{host_key}'''

[users.alice]
authorized_keys = ["{user_key}"]
allowed_agents = ["alice-home-linux"]

[agents.alice-home-linux]
agent_authorized_keys = ["{agent_key_a}"]

[agents.bob-home-linux]
agent_authorized_keys = ["{agent_key_b}"]
"#
        );
        RelayConfig::from_toml_str(&raw).unwrap()
    }

    async fn insert_forward_route(
        state: &RelayState,
        public_name: &str,
        port: u32,
        agent_id: &str,
    ) {
        state.forward_routes.write().await.insert(
            (public_name.to_string(), port),
            ForwardRegistration {
                agent_id: agent_id.to_string(),
                connection_id: 1,
            },
        );
    }

    #[tokio::test]
    async fn denies_unauthorized_agent_channel() {
        let state = RelayState::new(relay_config());
        insert_forward_route(&state, "bob-home-linux-ssh", 22, "bob-home-linux").await;
        let err = state
            .open_agent_channel("alice", "bob-home-linux-ssh", 22, "127.0.0.1", 5555)
            .await
            .unwrap_err();
        assert!(matches!(err, RelayRouteError::Unauthorized { .. }));
    }

    #[tokio::test]
    async fn authorized_agent_must_be_online() {
        let state = RelayState::new(relay_config());
        insert_forward_route(&state, "alice-home-linux-web", 8080, "alice-home-linux").await;
        let err = state
            .open_agent_channel("alice", "alice-home-linux-web", 8080, "127.0.0.1", 5555)
            .await
            .unwrap_err();
        assert!(matches!(err, RelayRouteError::Offline(_)));
    }

    #[tokio::test]
    async fn unregistered_forward_is_unknown() {
        let state = RelayState::new(relay_config());
        let err = state
            .open_agent_channel("alice", "alice-home-linux-web", 8080, "127.0.0.1", 5555)
            .await
            .unwrap_err();
        assert!(matches!(err, RelayRouteError::UnknownForward { .. }));
    }

    #[test]
    fn public_forward_name_must_belong_to_agent_namespace() {
        assert_eq!(
            public_forward_name_for_agent("alice-home-linux", "alice-home-linux-ssh"),
            Some("ssh")
        );
        assert_eq!(
            public_forward_name_for_agent("alice-home-linux", "bob-home-linux-ssh"),
            None
        );
        assert_eq!(
            public_forward_name_for_agent("alice-home-linux", "alice-home-linux-"),
            None
        );
    }
}
