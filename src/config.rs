use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use russh::keys::{HashAlg, PublicKey};
use serde::Deserialize;

use crate::token::validate_token_hash;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfigFile {
    pub server: RelayServerConfig,
    #[serde(default)]
    pub users: HashMap<String, RelayUserConfig>,
    #[serde(default)]
    pub machines: HashMap<String, MachineConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayServerConfig {
    pub ssh_listen: SocketAddr,
    pub relay_listen: SocketAddr,
    pub ssh_host_key: PathBuf,
    pub relay_tls_cert: Option<PathBuf>,
    pub relay_tls_key: Option<PathBuf>,
    #[serde(default)]
    pub allow_insecure_relay: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayUserConfig {
    #[serde(default)]
    pub public_keys: Vec<String>,
    #[serde(default)]
    pub allowed_machines: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    pub machine_id: String,
    pub machine_alias: String,
    pub display_name: Option<String>,
    pub agent_token_hash: String,
    pub target: String,
}

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub server: RuntimeRelayServerConfig,
    users: Arc<HashMap<String, RuntimeRelayUser>>,
    machines_by_id: Arc<HashMap<String, MachineConfig>>,
    machines_by_alias: Arc<HashMap<String, MachineConfig>>,
}

#[derive(Clone, Debug)]
pub struct RuntimeRelayServerConfig {
    pub ssh_listen: SocketAddr,
    pub relay_listen: SocketAddr,
    pub ssh_host_key: PathBuf,
    pub relay_tls_cert: Option<PathBuf>,
    pub relay_tls_key: Option<PathBuf>,
    pub allow_insecure_relay: bool,
}

#[derive(Clone, Debug)]
struct RuntimeRelayUser {
    key_fingerprints: HashSet<String>,
    allowed_machines: HashSet<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub relay_addr: String,
    pub relay_name: Option<String>,
    pub relay_ca_cert: Option<PathBuf>,
    #[serde(default)]
    pub allow_insecure_relay: bool,
    pub machine_id: String,
    pub agent_token: String,
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
        if file.machines.is_empty() {
            bail!("relay config must define at least one machine");
        }

        let tls_pair_complete =
            file.server.relay_tls_cert.is_some() == file.server.relay_tls_key.is_some();
        if !tls_pair_complete {
            bail!("relay_tls_cert and relay_tls_key must be configured together");
        }
        if file.server.relay_tls_cert.is_none() && !file.server.allow_insecure_relay {
            bail!(
                "relay TLS is required; configure relay_tls_cert/relay_tls_key or set allow_insecure_relay = true for local development"
            );
        }

        let mut machines_by_id = HashMap::new();
        let mut machines_by_alias = HashMap::new();
        for (entry_name, machine) in file.machines {
            validate_identifier("machine_id", &machine.machine_id)?;
            validate_identifier("machine_alias", &machine.machine_alias)?;
            validate_token_hash(&machine.agent_token_hash)?;
            if machine.target != "127.0.0.1:22" {
                bail!("machine {entry_name} target must be 127.0.0.1:22 for the SSH-only MVP");
            }
            if machines_by_id
                .insert(machine.machine_id.clone(), machine.clone())
                .is_some()
            {
                bail!("duplicate machine_id {}", machine.machine_id);
            }
            if machines_by_alias
                .insert(machine.machine_alias.clone(), machine)
                .is_some()
            {
                bail!("duplicate machine_alias in relay config");
            }
        }

        let mut users = HashMap::new();
        for (name, user) in file.users {
            if user.public_keys.is_empty() {
                bail!("user {name} must have at least one public key");
            }

            let mut key_fingerprints = HashSet::new();
            for public_key in user.public_keys {
                let key = parse_public_key(&public_key)
                    .with_context(|| format!("invalid public key for user {name}"))?;
                key_fingerprints.insert(fingerprint(&key));
            }

            let mut allowed_machines = HashSet::new();
            for alias in user.allowed_machines {
                if !machines_by_alias.contains_key(&alias) {
                    bail!("user {name} references unknown machine alias {alias}");
                }
                allowed_machines.insert(alias);
            }

            users.insert(
                name,
                RuntimeRelayUser {
                    key_fingerprints,
                    allowed_machines,
                },
            );
        }

        Ok(Self {
            server: RuntimeRelayServerConfig {
                ssh_listen: file.server.ssh_listen,
                relay_listen: file.server.relay_listen,
                ssh_host_key: file.server.ssh_host_key,
                relay_tls_cert: file.server.relay_tls_cert,
                relay_tls_key: file.server.relay_tls_key,
                allow_insecure_relay: file.server.allow_insecure_relay,
            },
            users: Arc::new(users),
            machines_by_id: Arc::new(machines_by_id),
            machines_by_alias: Arc::new(machines_by_alias),
        })
    }

    pub fn user_key_allowed(&self, user: &str, key: &PublicKey) -> bool {
        self.users
            .get(user)
            .is_some_and(|entry| entry.key_fingerprints.contains(&fingerprint(key)))
    }

    pub fn user_can_access(&self, user: &str, machine_alias: &str) -> bool {
        self.users
            .get(user)
            .is_some_and(|entry| entry.allowed_machines.contains(machine_alias))
    }

    pub fn machine_by_id(&self, machine_id: &str) -> Option<&MachineConfig> {
        self.machines_by_id.get(machine_id)
    }

    pub fn machine_by_alias(&self, machine_alias: &str) -> Option<&MachineConfig> {
        self.machines_by_alias.get(machine_alias)
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

    pub fn relay_server_name(&self) -> Result<String> {
        if let Some(name) = &self.relay_name {
            return Ok(name.clone());
        }

        let host = self
            .relay_addr
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(&self.relay_addr);
        if host.is_empty() {
            bail!("relay_addr does not contain a relay host");
        }
        Ok(host.to_string())
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier("machine_id", &self.machine_id)?;
        if self.agent_token.len() < 32 {
            bail!("agent_token must be at least 32 characters");
        }
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
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if !valid {
        bail!("{label} {value:?} may only contain ASCII letters, digits, '_', '-' and '.'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{
        Argon2, PasswordHasher,
        password_hash::{SaltString, rand_core::OsRng},
    };
    use russh::keys::{Algorithm, PrivateKey};

    fn public_key_line() -> String {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        key.public_key().to_openssh().unwrap()
    }

    fn token_hash(token: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(token.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    fn base_config(machine_alias: &str) -> String {
        format!(
            r#"
[server]
ssh_listen = "127.0.0.1:2222"
relay_listen = "127.0.0.1:4443"
ssh_host_key = "/tmp/slay-test-host-key"
allow_insecure_relay = true

[users.alice]
public_keys = ["{}"]
allowed_machines = ["{}"]

[machines.alice_home]
machine_id = "mch_01"
machine_alias = "{}"
display_name = "Alice Home"
agent_token_hash = "{}"
target = "127.0.0.1:22"
"#,
            public_key_line(),
            machine_alias,
            machine_alias,
            token_hash("01234567890123456789012345678901")
        )
    }

    #[test]
    fn validates_machine_alias_acl() {
        let config = RelayConfig::from_toml_str(&base_config("alice-home-linux")).unwrap();
        assert!(config.user_can_access("alice", "alice-home-linux"));
        assert!(!config.user_can_access("alice", "alice-office-linux"));
    }

    #[test]
    fn rejects_acl_for_unknown_machine() {
        let raw = base_config("alice-home-linux").replace(
            "allowed_machines = [\"alice-home-linux\"]",
            "allowed_machines = [\"missing\"]",
        );
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("unknown machine alias"));
    }

    #[test]
    fn empty_acl_allows_no_machines() {
        let raw = base_config("alice-home-linux").replace(
            "allowed_machines = [\"alice-home-linux\"]",
            "allowed_machines = []",
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
    fn rejects_relay_config_without_tls_or_insecure_flag() {
        let raw = base_config("alice-home-linux").replace("allow_insecure_relay = true\n", "");
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("relay TLS is required"));
    }

    #[test]
    fn rejects_unknown_relay_server_field() {
        let raw = base_config("alice-home-linux").replace(
            "allow_insecure_relay = true",
            "allow_insecure_relay = true\nunexpected_field = true",
        );
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn rejects_unknown_agent_field() {
        let raw = r#"
relay_addr = "relay.example.com:443"
unexpected_field = true
machine_id = "mch_01"
agent_token = "01234567890123456789012345678901"
target = "127.0.0.1:22"
"#;
        let err = toml::from_str::<AgentConfig>(raw).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_invalid_agent_token_hash() {
        let raw = base_config("alice-home-linux").replace(
            "agent_token_hash = \"",
            "agent_token_hash = \"not-a-valid-hash",
        );
        let err = RelayConfig::from_toml_str(&raw).unwrap_err();
        assert!(err.to_string().contains("invalid agent_token_hash"));
    }

    #[test]
    fn rejects_zero_reconnect_delay() {
        let raw = r#"
relay_addr = "relay.example.com:443"
machine_id = "mch_01"
agent_token = "01234567890123456789012345678901"
target = "127.0.0.1:22"
reconnect_secs = 0
"#;
        let config: AgentConfig = toml::from_str(raw).unwrap();
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
