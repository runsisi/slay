use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use slay::agent::run_agent;
use slay::config::{
    AgentConfig, RelayConfig, parse_private_key, relay_listen_for_addr, render_known_host_entry,
};
use slay::config_templates::{PairTemplateInput, render_agent_config, render_relay_config};
use slay::relay::run_relay_server;

const INIT_RELAY_CONFIG_OUTPUT: &str = "slay-relay.toml";
const INIT_AGENT_CONFIG_OUTPUT: &str = "slay-agent.toml";

#[derive(Debug, Parser)]
#[command(version, about = "SSH relay for agents behind NAT")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Run the public relay")]
    Relay {
        #[arg(short, long, default_value = "slay-relay.toml")]
        config: PathBuf,
    },
    #[command(about = "Run the internal agent")]
    Agent {
        #[arg(short, long, default_value = "slay-agent.toml")]
        config: PathBuf,
    },
    #[command(about = "Create and validate configuration")]
    Config {
        #[command(subcommand)]
        command: Box<ConfigCommand>,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum ConfigCommand {
    #[command(about = "Create matching relay and agent configs")]
    Init {
        #[arg(
            long,
            help = "Public relay SSH address used by agents, e.g. relay.example.com:2222"
        )]
        relay_addr: String,
        #[arg(
            long,
            default_value = "alice",
            help = "Relay SSH username for client access"
        )]
        relay_user: String,
        #[arg(
            long = "relay-private-key-output",
            value_name = "PATH",
            help = "Where to write a generated relay user private key (default: slay-relay-<relay_user>.key)"
        )]
        relay_private_key_output: Option<PathBuf>,
        #[arg(
            long,
            default_value = "home-linux",
            help = "Agent id used as relay-side SSH username and public target prefix"
        )]
        agent_id: String,
        #[arg(
            short,
            long,
            help = "Overwrite generated output files if they already exist"
        )]
        force: bool,
    },
    #[command(about = "Validate a config file")]
    Validate {
        #[command(subcommand)]
        target: ConfigValidateTarget,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigValidateTarget {
    #[command(about = "Validate a relay config")]
    Relay {
        #[arg(short, long, default_value = "slay-relay.toml")]
        config: PathBuf,
    },
    #[command(about = "Validate an agent config")]
    Agent {
        #[arg(short, long, default_value = "slay-agent.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Relay { config } => run_relay_server(RelayConfig::from_path(config)?).await,
        Command::Agent { config } => run_agent(AgentConfig::from_path(config)?).await,
        Command::Config { command } => handle_config_command(*command),
    }
}

fn handle_config_command(command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Init {
            relay_addr,
            relay_user,
            relay_private_key_output,
            agent_id,
            force,
        } => write_pair_templates(PairInitOptions {
            relay_addr: &relay_addr,
            relay_user: &relay_user,
            relay_private_key_output: relay_private_key_output.as_deref(),
            agent_id: &agent_id,
            force,
        }),
        ConfigCommand::Validate { target } => match target {
            ConfigValidateTarget::Relay { config } => {
                RelayConfig::from_path(&config)?;
                println!("relay config OK: {}", config.display());
                Ok(())
            }
            ConfigValidateTarget::Agent { config } => {
                AgentConfig::from_path(&config)?;
                println!("agent config OK: {}", config.display());
                Ok(())
            }
        },
    }
}

fn write_template(output: &Path, content: &str, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite it",
            output.display()
        );
    }

    fs::write(output, content)
        .with_context(|| format!("failed to write config file {}", output.display()))?;
    println!("wrote {}", output.display());
    Ok(())
}

struct PairInitOptions<'a> {
    relay_addr: &'a str,
    relay_user: &'a str,
    relay_private_key_output: Option<&'a Path>,
    agent_id: &'a str,
    force: bool,
}

fn write_pair_templates(options: PairInitOptions<'_>) -> Result<()> {
    write_pair_templates_to(
        Path::new(INIT_RELAY_CONFIG_OUTPUT),
        Path::new(INIT_AGENT_CONFIG_OUTPUT),
        options,
    )
}

fn write_pair_templates_to(
    relay_output: &Path,
    agent_output: &Path,
    options: PairInitOptions<'_>,
) -> Result<()> {
    if relay_output == agent_output {
        bail!("relay_output and agent_output must be different paths");
    }
    if options.relay_addr.is_empty() {
        bail!("relay_addr cannot be empty");
    }
    validate_agent_id(options.agent_id)?;
    validate_config_table_key("relay_user", options.relay_user)?;
    ensure_can_write(relay_output, options.force)?;
    ensure_can_write(agent_output, options.force)?;
    let default_output;
    let relay_private_key_output = match options.relay_private_key_output {
        Some(output) => output,
        None => {
            default_output = default_relay_private_key_output(options.relay_user);
            &default_output
        }
    };

    let relay_authorized_keys = vec![generate_relay_user_key(
        relay_private_key_output,
        options.relay_user,
        options.force,
    )?];

    let private_key = generate_private_key("agent private key")?;
    let agent_public_key = parse_private_key(&private_key)
        .context("invalid agent private key")?
        .public_key()
        .to_openssh()
        .context("failed to encode agent public key")?;
    let agent_authorized_keys = vec![agent_public_key];

    let host_key = generate_private_key("relay host key")?;
    let host_private_key = parse_private_key(&host_key).context("invalid relay host key")?;
    let relay_listen = relay_listen_for_addr(options.relay_addr)?;
    let relay_known_hosts = vec![render_known_host_entry(
        options.relay_addr,
        host_private_key.public_key(),
    )?];
    let input = PairTemplateInput {
        relay_user: options.relay_user,
        relay_authorized_keys: &relay_authorized_keys,
        agent_authorized_keys: &agent_authorized_keys,
        relay_listen: &relay_listen,
        relay_addr: options.relay_addr,
        host_key: &host_key,
        relay_known_hosts: &relay_known_hosts,
        agent_private_key: &private_key,
        agent_id: options.agent_id,
    };

    write_template(relay_output, &render_relay_config(&input), true)?;
    write_template(agent_output, &render_agent_config(&input), true)?;
    Ok(())
}

fn generate_private_key(label: &str) -> Result<String> {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .with_context(|| format!("failed to generate {label}"))?;
    Ok(key.to_openssh(LineEnding::LF)?.to_string())
}

fn generate_relay_user_key(output: &Path, relay_user: &str, force: bool) -> Result<String> {
    if output.as_os_str() == "-" {
        bail!("relay_private_key_output cannot be '-'");
    }

    ensure_can_write(output, force)?;

    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .context("failed to generate relay user key")?;
    let private_key = key.to_openssh(LineEnding::LF)?.to_string();
    let public_key = format!("{} {relay_user}@slay", key.public_key().to_openssh()?);

    write_private_key_file(output, &private_key)
        .with_context(|| format!("failed to write relay user key {}", output.display()))?;
    println!("wrote {}", output.display());

    Ok(public_key)
}

fn default_relay_private_key_output(relay_user: &str) -> PathBuf {
    PathBuf::from(format!("slay-relay-{relay_user}.key"))
}

#[cfg(unix)]
fn write_private_key_file(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content)?;
    Ok(())
}

fn validate_agent_id(agent_id: &str) -> Result<()> {
    if agent_id.is_empty() {
        bail!("agent_id cannot be empty");
    }
    let valid = agent_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    if !valid {
        bail!("agent_id may only contain ASCII letters, digits, '_' and '-'");
    }
    Ok(())
}

fn validate_config_table_key(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{label} cannot be empty");
    }
    let valid = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    if !valid {
        bail!("{label} may only contain ASCII letters, digits, '_' and '-'");
    }
    Ok(())
}

fn ensure_can_write(output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite it",
            output.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn init_derives_relay_listen_from_relay_addr_port() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("slay-config-init-{unique}-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let relay_output = dir.join("relay.toml");
        let agent_output = dir.join("agent.toml");
        let relay_private_key_output = dir.join("relay_user.key");

        write_pair_templates_to(
            &relay_output,
            &agent_output,
            PairInitOptions {
                relay_addr: "relay.example.com:3333",
                relay_user: "alice",
                relay_private_key_output: Some(&relay_private_key_output),
                agent_id: "alice-home-linux",
                force: false,
            },
        )
        .unwrap();

        let relay_raw = fs::read_to_string(&relay_output).unwrap();
        let relay: toml::Value = toml::from_str(&relay_raw).unwrap();
        assert_eq!(relay["relay"]["listen"].as_str(), Some("0.0.0.0:3333"));
        assert!(
            relay["agents"]["alice-home-linux"]
                .get("forward_targets")
                .is_none()
        );
        let relay_private_key = fs::read_to_string(&relay_private_key_output).unwrap();
        let relay_user_key = format!(
            "{} alice@slay",
            parse_private_key(&relay_private_key)
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap()
        );
        assert!(!relay_private_key_output.with_extension("key.pub").exists());
        assert_eq!(
            relay["users"]["alice"]["authorized_keys"][0].as_str(),
            Some(relay_user_key.as_str())
        );
        parse_private_key(&relay_private_key).unwrap();

        let agent_raw = fs::read_to_string(&agent_output).unwrap();
        let agent: toml::Value = toml::from_str(&agent_raw).unwrap();
        assert_eq!(agent["relay_addr"].as_str(), Some("relay.example.com:3333"));
        assert_eq!(agent["forward_targets"][0]["name"].as_str(), Some("ssh"));
        assert_eq!(agent["forward_targets"][0]["port"].as_integer(), Some(22));
        assert_eq!(
            agent["forward_targets"][0]["target"].as_str(),
            Some("127.0.0.1:22")
        );
        let agent_private_key = agent["agent_private_key"].as_str().unwrap();
        let agent_public_key = parse_private_key(agent_private_key)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        assert_eq!(
            relay["agents"]["alice-home-linux"]["agent_authorized_keys"][0].as_str(),
            Some(agent_public_key.as_str())
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn default_relay_private_key_output_uses_relay_user() {
        assert_eq!(
            default_relay_private_key_output("alice"),
            PathBuf::from("slay-relay-alice.key")
        );
        assert_eq!(
            default_relay_private_key_output("ops_admin"),
            PathBuf::from("slay-relay-ops_admin.key")
        );
    }
}
