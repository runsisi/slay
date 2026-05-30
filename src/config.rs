use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use russh::keys::{HashAlg, PublicKey};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfigFile {
    pub server: RelayServerConfig,
    #[serde(default)]
    pub users: HashMap<String, RelayUserConfig>,
    #[serde(default)]
    pub agents: HashMap<String, RelayAgentConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayServerConfig {
    pub ssh_listen: SocketAddr,
    pub ssh_host_key: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayUserConfig {
    #[serde(default)]
    pub authorized_keys: Vec<String>,
    #[serde(default)]
    pub allowed_agents: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAgentConfig {
    #[serde(default)]
    pub agent_authorized_keys: Vec<String>,
    pub target: String,
}

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub server: RuntimeRelayServerConfig,
    users: Arc<HashMap<String, RuntimeRelayUser>>,
    agents_by_id: Arc<HashMap<String, RuntimeAgent>>,
}

#[derive(Clone, Debug)]
pub struct RuntimeRelayServerConfig {
    pub ssh_listen: SocketAddr,
    pub ssh_host_key: PathBuf,
}

#[derive(Clone, Debug)]
struct RuntimeRelayUser {
    key_fingerprints: HashSet<String>,
    allowed_agents: HashSet<String>,
}

#[derive(Clone, Debug)]
struct RuntimeAgent {
    config: RelayAgentConfig,
    agent_key_fingerprints: HashSet<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub relay_addr: String,
    pub relay_host_key: String,
    pub agent_id: String,
    pub agent_private_key: PathBuf,
    pub target: String,
    #[serde(default = "default_reconnect_secs")]
    pub reconnect_secs: u64,
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

        let mut agents_by_id = HashMap::new();
        for (agent_id, agent) in file.agents {
            validate_identifier("agent_id", &agent_id)?;
            if agent.agent_authorized_keys.is_empty() {
                bail!("agent {agent_id} must have at least one agent authorized key");
            }
            if agent.target != "127.0.0.1:22" {
                bail!("agent {agent_id} target must be 127.0.0.1:22 for the SSH-only MVP");
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
            server: RuntimeRelayServerConfig {
                ssh_listen: file.server.ssh_listen,
                ssh_host_key: file.server.ssh_host_key,
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

    pub fn relay_host_public_key(&self) -> Result<PublicKey> {
        parse_public_key(&self.relay_host_key).context("invalid relay_host_key")
    }

    pub fn validate(&self) -> Result<()> {
        if self.relay_addr.is_empty() {
            bail!("relay_addr cannot be empty");
        }
        self.relay_host_public_key()?;
        validate_identifier("agent_id", &self.agent_id)?;
        if self.reconnect_secs == 0 {
            bail!("reconnect_secs must be at least 1");
        }
        if self.target != "127.0.0.1:22" {
            bail!("agent target must be 127.0.0.1:22 for the SSH-only MVP");
        }
        Ok(())
    }
}

pub fn parse_public_key(input: &str) -> Result<PublicKey> {
    PublicKey::from_openssh(input.trim()).map_err(Into::into)
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey};

    fn public_key_line() -> String {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        key.public_key().to_openssh().unwrap()
    }

    fn base_config(agent_id: &str) -> String {
        let user_key = public_key_line();
        let agent_key = public_key_line();
        format!(
            r#"
[server]
ssh_listen = "127.0.0.1:2222"
ssh_host_key = "/tmp/slay-test-host-key"

[users.alice]
authorized_keys = ["{}"]
allowed_agents = ["{}"]

[agents.{}]
agent_authorized_keys = ["{}"]
target = "127.0.0.1:22"
"#,
            user_key, agent_id, agent_id, agent_key
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
    fn rejects_non_ssh_target() {
        let raw = base_config("alice-home-linux")
            .replace("target = \"127.0.0.1:22\"", "target = \"127.0.0.1:8080\"");
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("127.0.0.1:22"));
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
    fn rejects_unknown_relay_server_field() {
        let raw = base_config("alice-home-linux").replace(
            "ssh_host_key = \"/tmp/slay-test-host-key\"",
            "ssh_host_key = \"/tmp/slay-test-host-key\"\nunexpected_field = true",
        );
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn rejects_unknown_agent_field() {
        let raw = r#"
relay_addr = "relay.example.com:2222"
relay_host_key = "ssh-ed25519 AAAA relay@example"
unexpected_field = true
agent_id = "alice-home-linux"
agent_private_key = "/etc/slay/agent_ed25519"
target = "127.0.0.1:22"
"#;
        let err = toml::from_str::<AgentConfig>(raw).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
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
relay_host_key = "RELAY_KEY"
agent_id = "mch_01"
agent_private_key = "/etc/slay/agent_ed25519"
target = "127.0.0.1:22"
reconnect_secs = 0
"#
        .replace("RELAY_KEY", &relay_key);
        let config: AgentConfig = toml::from_str(&raw).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("reconnect_secs"));
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
