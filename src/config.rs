use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use russh::keys::{HashAlg, PrivateKey, PublicKey, decode_secret_key};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfigFile {
    pub relay: RelayServerConfig,
    #[serde(default)]
    pub users: HashMap<String, RelayUserConfig>,
    #[serde(default)]
    pub agents: HashMap<String, RelayAgentConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayServerConfig {
    pub listen: SocketAddr,
    pub host_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayUserConfig {
    #[serde(default)]
    pub authorized_keys: Vec<String>,
    #[serde(default)]
    pub allowed_agents: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAgentConfig {
    #[serde(default)]
    pub agent_authorized_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentForwardTarget {
    pub name: String,
    pub port: u32,
    pub target: String,
}

#[derive(Clone)]
pub struct RelayConfig {
    pub relay: RuntimeRelayServerConfig,
    users: Arc<HashMap<String, RuntimeRelayUser>>,
    agents_by_id: Arc<HashMap<String, RuntimeAgent>>,
}

impl std::fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayConfig")
            .field("listen", &self.relay.listen)
            .field("users", &self.users.keys().collect::<Vec<_>>())
            .field("agents", &self.agents_by_id.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Clone)]
pub struct RuntimeRelayServerConfig {
    pub listen: SocketAddr,
    pub host_key: PrivateKey,
}

#[derive(Clone)]
struct RuntimeRelayUser {
    key_fingerprints: HashSet<String>,
    allowed_agents: HashSet<String>,
}

#[derive(Clone)]
struct RuntimeAgent {
    config: RelayAgentConfig,
    agent_key_fingerprints: HashSet<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub relay_addr: String,
    #[serde(default)]
    pub relay_known_hosts: Vec<String>,
    pub agent_id: String,
    pub agent_private_key: String,
    #[serde(default)]
    pub forward_targets: Vec<AgentForwardTarget>,
    #[serde(default = "default_reconnect_secs")]
    pub reconnect_secs: u64,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("relay_addr", &self.relay_addr)
            .field("relay_known_hosts", &self.relay_known_hosts)
            .field("agent_id", &self.agent_id)
            .field("agent_private_key", &"<redacted>")
            .field("forward_targets", &self.forward_targets)
            .field("reconnect_secs", &self.reconnect_secs)
            .finish()
    }
}

fn default_reconnect_secs() -> u64 {
    5
}

impl RelayConfig {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read relay config {}", path.display()))?;
        Self::from_toml_str(&raw)
    }

    pub fn from_toml_str(raw: &str) -> Result<Self> {
        let file: RelayConfigFile = toml::from_str(raw).context("failed to parse relay config")?;
        Self::from_file(file)
    }

    pub fn from_file(file: RelayConfigFile) -> Result<Self> {
        if file.users.is_empty() {
            bail!("relay config must define at least one user");
        }
        if file.agents.is_empty() {
            bail!("relay config must define at least one agent");
        }
        let host_key = parse_private_key(&file.relay.host_key).context("invalid relay host_key")?;

        let mut agents_by_id = HashMap::new();
        for (agent_id, agent) in file.agents {
            validate_identifier("agent_id", &agent_id)?;
            if agent.agent_authorized_keys.is_empty() {
                bail!("agent {agent_id} must have at least one agent authorized key");
            }
            let mut agent_key_fingerprints = HashSet::new();
            for public_key in &agent.agent_authorized_keys {
                let key = parse_public_key(public_key).with_context(|| {
                    format!("invalid agent authorized key for agent {agent_id}")
                })?;
                agent_key_fingerprints.insert(fingerprint(&key));
            }
            agents_by_id.insert(
                agent_id,
                RuntimeAgent {
                    config: agent,
                    agent_key_fingerprints,
                },
            );
        }

        let mut users = HashMap::new();
        for (name, user) in file.users {
            validate_identifier("user", &name)?;
            if agents_by_id.contains_key(&name) {
                bail!("relay user {name} conflicts with an agent_id");
            }
            if user.authorized_keys.is_empty() {
                bail!("user {name} must have at least one authorized key");
            }

            let mut key_fingerprints = HashSet::new();
            for public_key in user.authorized_keys {
                let key = parse_public_key(&public_key)
                    .with_context(|| format!("invalid authorized key for user {name}"))?;
                key_fingerprints.insert(fingerprint(&key));
            }

            let mut allowed_agents = HashSet::new();
            for agent_id in user.allowed_agents {
                if !agents_by_id.contains_key(&agent_id) {
                    bail!("user {name} references unknown agent id {agent_id}");
                }
                allowed_agents.insert(agent_id);
            }

            users.insert(
                name,
                RuntimeRelayUser {
                    key_fingerprints,
                    allowed_agents,
                },
            );
        }

        Ok(Self {
            relay: RuntimeRelayServerConfig {
                listen: file.relay.listen,
                host_key,
            },
            users: Arc::new(users),
            agents_by_id: Arc::new(agents_by_id),
        })
    }

    pub fn user_key_allowed(&self, user: &str, key: &PublicKey) -> bool {
        self.users
            .get(user)
            .is_some_and(|entry| entry.key_fingerprints.contains(&fingerprint(key)))
    }

    pub fn agent_key_allowed(&self, agent_id: &str, key: &PublicKey) -> bool {
        self.agents_by_id
            .get(agent_id)
            .is_some_and(|entry| entry.agent_key_fingerprints.contains(&fingerprint(key)))
    }

    pub fn user_can_access(&self, user: &str, agent_id: &str) -> bool {
        self.users
            .get(user)
            .is_some_and(|entry| entry.allowed_agents.contains(agent_id))
    }

    pub fn agent_by_id(&self, agent_id: &str) -> Option<&RelayAgentConfig> {
        self.agents_by_id.get(agent_id).map(|entry| &entry.config)
    }
}

impl AgentConfig {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read agent config {}", path.display()))?;
        let config: Self = toml::from_str(&raw).context("failed to parse agent config")?;
        config.validate()?;
        Ok(config)
    }

    pub fn relay_known_host_fingerprints(&self) -> Result<HashSet<String>> {
        known_host_fingerprints_for_addr(&self.relay_addr, &self.relay_known_hosts)
            .context("invalid relay_known_hosts")
    }

    pub fn validate(&self) -> Result<()> {
        if self.relay_addr.is_empty() {
            bail!("relay_addr cannot be empty");
        }
        if self.relay_known_hosts.is_empty() {
            bail!("relay_known_hosts cannot be empty");
        }
        self.relay_known_host_fingerprints()?;
        validate_identifier("agent_id", &self.agent_id)?;
        parse_private_key(&self.agent_private_key).context("invalid agent_private_key")?;
        if self.reconnect_secs == 0 {
            bail!("reconnect_secs must be at least 1");
        }
        if self.forward_targets.is_empty() {
            bail!("forward_targets cannot be empty");
        }
        let mut routes = HashSet::new();
        for target in &self.forward_targets {
            validate_forward_name("forward target name", &target.name)?;
            validate_forward_port("forward target port", target.port)?;
            parse_host_port("target", &target.target)?;
            if !routes.insert((target.name.clone(), target.port)) {
                bail!("duplicate forward target {}:{}", target.name, target.port);
            }
        }
        Ok(())
    }
}

pub fn parse_public_key(input: &str) -> Result<PublicKey> {
    PublicKey::from_openssh(input.trim()).map_err(Into::into)
}

pub fn parse_private_key(input: &str) -> Result<PrivateKey> {
    decode_secret_key(input.trim(), None).map_err(Into::into)
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub fn forward_public_name(agent_id: &str, name: &str) -> String {
    format!("{agent_id}-{name}")
}

pub fn render_known_host_entry(relay_addr: &str, public_key: &PublicKey) -> Result<String> {
    let (host, port) = parse_relay_addr(relay_addr)?;
    Ok(format!(
        "{} {}",
        known_host_pattern(&host, port),
        public_key.to_openssh()?
    ))
}

pub fn relay_listen_for_addr(relay_addr: &str) -> Result<String> {
    let (host, port) = parse_relay_addr(relay_addr)?;
    let listen_host = if host.contains(':') {
        "[::]"
    } else {
        "0.0.0.0"
    };
    Ok(format!("{listen_host}:{port}"))
}

fn known_host_fingerprints_for_addr(
    relay_addr: &str,
    known_hosts: &[String],
) -> Result<HashSet<String>> {
    let (host, port) = parse_relay_addr(relay_addr)?;
    let host_pattern = known_host_pattern(&host, port);
    let mut fingerprints = HashSet::new();

    for line in known_hosts {
        let Some((patterns, public_key)) = parse_known_host_line(line)? else {
            continue;
        };
        if patterns.split(',').any(|pattern| pattern == host_pattern) {
            fingerprints.insert(fingerprint(&public_key));
        }
    }

    if fingerprints.is_empty() {
        bail!("relay_known_hosts has no entry for {host_pattern}");
    }
    Ok(fingerprints)
}

fn parse_known_host_line(line: &str) -> Result<Option<(&str, PublicKey)>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }

    let parts = line.split_whitespace().collect::<Vec<_>>();
    let Some(key_type_index) = parts.iter().position(|part| is_ssh_public_key_type(part)) else {
        bail!("known_hosts line is missing an SSH public key type");
    };
    if key_type_index == 0 {
        bail!("known_hosts line is missing host patterns");
    }
    if key_type_index + 1 >= parts.len() {
        bail!("known_hosts line is missing SSH public key body");
    }

    let public_key = parse_public_key(&parts[key_type_index..].join(" "))?;
    Ok(Some((parts[0], public_key)))
}

fn is_ssh_public_key_type(key_type: &str) -> bool {
    matches!(
        key_type,
        "ssh-ed25519"
            | "ssh-rsa"
            | "rsa-sha2-256"
            | "rsa-sha2-512"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) || key_type.starts_with("ecdsa-sha2-")
}

fn parse_relay_addr(relay_addr: &str) -> Result<(String, u16)> {
    parse_host_port("relay_addr", relay_addr)
}

fn parse_host_port(label: &str, value: &str) -> Result<(String, u16)> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            bail!("{label} must be host:port or [ipv6]:port");
        };
        return Ok((host.to_string(), parse_port(label, port)?));
    }

    let Some((host, port)) = value.rsplit_once(':') else {
        bail!("{label} must include a port");
    };
    if host.is_empty() {
        bail!("{label} host cannot be empty");
    }
    if host.contains(':') {
        bail!("{label} IPv6 hosts must use [host]:port");
    }
    Ok((host.to_string(), parse_port(label, port)?))
}

fn parse_port(label: &str, port: &str) -> Result<u16> {
    port.parse::<u16>()
        .with_context(|| format!("invalid {label} port {port:?}"))
}

fn known_host_pattern(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

fn validate_identifier(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{label} cannot be empty");
    }
    let valid = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    if !valid {
        bail!("{label} {value:?} may only contain ASCII letters, digits, '_' and '-'");
    }
    Ok(())
}

fn validate_forward_name(label: &str, value: &str) -> Result<()> {
    validate_identifier(label, value)
}

fn validate_forward_port(label: &str, port: u32) -> Result<()> {
    if port == 0 || port > u16::MAX as u32 {
        bail!("{label} must be between 1 and 65535");
    }
    Ok(())
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

    fn base_config(agent_id: &str) -> String {
        let user_key = public_key_line();
        let agent_key = public_key_line();
        let host_key = private_key_block();
        format!(
            r#"
[relay]
listen = "127.0.0.1:2222"
host_key = '''{}'''

[users.alice]
authorized_keys = ["{}"]
allowed_agents = ["{}"]

[agents.{}]
agent_authorized_keys = ["{}"]
"#,
            host_key, user_key, agent_id, agent_id, agent_key
        )
    }

    #[test]
    fn validates_agent_id_acl() {
        let config = RelayConfig::from_toml_str(&base_config("alice-home-linux")).unwrap();
        assert!(config.user_can_access("alice", "alice-home-linux"));
        assert!(!config.user_can_access("alice", "alice-office-linux"));
    }

    #[test]
    fn rejects_acl_for_unknown_agent() {
        let raw = base_config("alice-home-linux").replace(
            "allowed_agents = [\"alice-home-linux\"]",
            "allowed_agents = [\"missing\"]",
        );
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("unknown agent id"));
    }

    #[test]
    fn empty_acl_allows_no_agents() {
        let raw = base_config("alice-home-linux").replace(
            "allowed_agents = [\"alice-home-linux\"]",
            "allowed_agents = []",
        );
        let config = RelayConfig::from_toml_str(&raw).unwrap();
        assert!(!config.user_can_access("alice", "alice-home-linux"));
    }

    #[test]
    fn rejects_relay_agent_forward_targets_field() {
        let raw = base_config("alice-home-linux").replace(
            "agent_authorized_keys = [",
            "forward_targets = [{ name = \"ssh\", port = 22 }]\nagent_authorized_keys = [",
        );
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn rejects_agent_without_agent_authorized_key() {
        let raw = base_config("alice-home-linux");
        let line = raw
            .lines()
            .find(|line| line.trim_start().starts_with("agent_authorized_keys = "))
            .unwrap()
            .to_string();
        let raw = raw.replace(&line, "agent_authorized_keys = []");
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("agent authorized key"));
    }

    #[test]
    fn rejects_unknown_relay_field() {
        let raw = base_config("alice-home-linux").replace(
            "listen = \"127.0.0.1:2222\"",
            "listen = \"127.0.0.1:2222\"\nunexpected_field = true",
        );
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn rejects_unknown_agent_field() {
        let relay_key = public_key_line();
        let raw = r#"
relay_addr = "relay.example.com:2222"
relay_known_hosts = ["[relay.example.com]:2222 RELAY_KEY"]
unexpected_field = true
agent_id = "alice-home-linux"
agent_private_key = '''PRIVATE_KEY'''
forward_targets = [
  { name = "ssh", port = 22, target = "127.0.0.1:22" }
]
"#
        .replace("RELAY_KEY", &relay_key)
        .replace("PRIVATE_KEY", &private_key_block());
        let err = toml::from_str::<AgentConfig>(&raw).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_old_agent_config_field_names() {
        let relay_key = public_key_line();
        let raw = r#"
relay_addr = "relay.example.com:2222"
relay_known_hosts = ["[relay.example.com]:2222 RELAY_KEY"]
agent_id = "alice-home-linux"
private_key = '''PRIVATE_KEY'''
target = "127.0.0.1:22"
"#
        .replace("RELAY_KEY", &relay_key)
        .replace("PRIVATE_KEY", &private_key_block());
        let err = toml::from_str::<AgentConfig>(&raw).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn rejects_old_agent_forward_target_field() {
        let relay_key = public_key_line();
        let raw = r#"
relay_addr = "relay.example.com:2222"
relay_known_hosts = ["[relay.example.com]:2222 RELAY_KEY"]
agent_id = "alice-home-linux"
agent_private_key = '''PRIVATE_KEY'''
forward_targets = [
  { name = "ssh", port = 22, forward_target = "127.0.0.1:22" }
]
"#
        .replace("RELAY_KEY", &relay_key)
        .replace("PRIVATE_KEY", &private_key_block());
        let err = toml::from_str::<AgentConfig>(&raw).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn rejects_old_relay_agent_target_field() {
        let raw = base_config("alice-home-linux").replace(
            "agent_authorized_keys = [",
            "target = \"127.0.0.1:22\"\nagent_authorized_keys = [",
        );
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn rejects_agent_user_name_conflict() {
        let raw =
            base_config("alice-home-linux").replace("[users.alice]", "[users.alice-home-linux]");
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("conflicts"));
    }

    #[test]
    fn rejects_agent_id_with_dot() {
        let raw =
            base_config("alice-home").replace("[agents.alice-home]", "[agents.\"alice.home\"]");
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("agent_id"));
    }

    #[test]
    fn rejects_zero_reconnect_delay() {
        let relay_key = public_key_line();
        let raw = r#"
relay_addr = "relay.example.com:2222"
relay_known_hosts = ["[relay.example.com]:2222 RELAY_KEY"]
agent_id = "mch_01"
agent_private_key = '''PRIVATE_KEY'''
forward_targets = [
  { name = "ssh", port = 22, target = "127.0.0.1:22" }
]
reconnect_secs = 0
"#
        .replace("RELAY_KEY", &relay_key)
        .replace("PRIVATE_KEY", &private_key_block());
        let config: AgentConfig = toml::from_str(&raw).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("reconnect_secs"));
    }

    #[test]
    fn validates_known_hosts_entry_for_relay_addr() {
        let relay_key = public_key_line();
        let raw = r#"
relay_addr = "relay.example.com:2222"
relay_known_hosts = ["[relay.example.com]:2222 RELAY_KEY"]
agent_id = "mch_01"
agent_private_key = '''PRIVATE_KEY'''
forward_targets = [
  { name = "ssh", port = 22, target = "127.0.0.1:22" },
  { name = "web", port = 8080, target = "127.0.0.1:8080" }
]
"#
        .replace("RELAY_KEY", &relay_key)
        .replace("PRIVATE_KEY", &private_key_block());
        let config: AgentConfig = toml::from_str(&raw).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_known_hosts_without_relay_addr_entry() {
        let relay_key = public_key_line();
        let raw = r#"
relay_addr = "relay.example.com:2222"
relay_known_hosts = ["[other.example.com]:2222 RELAY_KEY"]
agent_id = "mch_01"
agent_private_key = '''PRIVATE_KEY'''
forward_targets = [
  { name = "ssh", port = 22, target = "127.0.0.1:22" }
]
"#
        .replace("RELAY_KEY", &relay_key)
        .replace("PRIVATE_KEY", &private_key_block());
        let config: AgentConfig = toml::from_str(&raw).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("relay_known_hosts"));
    }

    #[test]
    fn derives_relay_listen_port_from_relay_addr() {
        assert_eq!(
            relay_listen_for_addr("relay.example.com:3333").unwrap(),
            "0.0.0.0:3333"
        );
        assert_eq!(
            relay_listen_for_addr("[2001:db8::10]:4444").unwrap(),
            "[::]:4444"
        );
    }

    #[test]
    fn parses_public_key_with_comment() {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let mut line = key.public_key().to_openssh().unwrap();
        line.push_str(" user@example");
        let parsed = parse_public_key(&line).unwrap();
        assert_eq!(fingerprint(&parsed), fingerprint(key.public_key()));
    }
}
