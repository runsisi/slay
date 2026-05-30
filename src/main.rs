use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use slay::agent::run_agent;
use slay::config::{AgentConfig, RelayConfig, parse_public_key};
use slay::config_templates::{
    AGENT_CONFIG_TEMPLATE, DEFAULT_AGENT_PRIVATE_KEY_PATH, PairTemplateInput,
    RELAY_CONFIG_TEMPLATE, render_agent_config, render_relay_config,
};
use slay::relay::run_relay_server;

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
        command: ConfigCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    #[command(about = "Create matching relay and agent configs")]
    Init {
        #[arg(long, default_value = "slay-relay.toml")]
        relay_output: PathBuf,
        #[arg(long, default_value = "slay-agent.toml")]
        agent_output: PathBuf,
        #[arg(long)]
        relay_addr: String,
        #[arg(long, default_value = "home-linux")]
        agent_id: String,
        #[arg(long, default_value = "alice")]
        relay_user: String,
        #[arg(long = "relay-authorized-key", value_name = "PATH")]
        relay_authorized_keys: Vec<PathBuf>,
        #[arg(long = "relay-authorized-keys", value_name = "PATH")]
        relay_authorized_key_files: Vec<PathBuf>,
        #[arg(long = "agent-authorized-key", value_name = "PATH")]
        agent_authorized_keys: Vec<PathBuf>,
        #[arg(long = "agent-authorized-keys", value_name = "PATH")]
        agent_authorized_key_files: Vec<PathBuf>,
        #[arg(long = "relay-host-public-key", value_name = "PATH")]
        relay_host_public_key: Option<PathBuf>,
        #[arg(long, default_value = DEFAULT_AGENT_PRIVATE_KEY_PATH)]
        agent_private_key: PathBuf,
        #[arg(short, long)]
        force: bool,
    },
    #[command(about = "Validate a config file")]
    Validate {
        #[command(subcommand)]
        target: ConfigValidateTarget,
    },
    #[command(about = "Generate a single-side config")]
    Gen {
        #[command(subcommand)]
        target: ConfigGenTarget,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigGenTarget {
    #[command(about = "Generate a relay config")]
    Relay {
        #[arg(short, long, default_value = "slay-relay.toml")]
        output: PathBuf,
        #[arg(short, long)]
        force: bool,
    },
    #[command(about = "Generate an agent config")]
    Agent {
        #[arg(short, long, default_value = "slay-agent.toml")]
        output: PathBuf,
        #[arg(short, long)]
        force: bool,
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
        Command::Config { command } => handle_config_command(command),
    }
}

fn handle_config_command(command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Init {
            relay_output,
            agent_output,
            relay_addr,
            agent_id,
            relay_user,
            relay_authorized_keys,
            relay_authorized_key_files,
            agent_authorized_keys,
            agent_authorized_key_files,
            relay_host_public_key,
            agent_private_key,
            force,
        } => write_pair_templates(PairInitOptions {
            relay_output: &relay_output,
            agent_output: &agent_output,
            relay_addr: &relay_addr,
            agent_id: &agent_id,
            relay_user: &relay_user,
            relay_authorized_keys: &relay_authorized_keys,
            relay_authorized_key_files: &relay_authorized_key_files,
            agent_authorized_keys: &agent_authorized_keys,
            agent_authorized_key_files: &agent_authorized_key_files,
            relay_host_public_key: relay_host_public_key.as_deref(),
            agent_private_key: &agent_private_key,
            force,
        }),
        ConfigCommand::Gen { target } => match target {
            ConfigGenTarget::Relay { output, force } => {
                write_template(&output, RELAY_CONFIG_TEMPLATE, force)
            }
            ConfigGenTarget::Agent { output, force } => {
                write_template(&output, AGENT_CONFIG_TEMPLATE, force)
            }
        },
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
    if output.as_os_str() == "-" {
        print!("{content}");
        return Ok(());
    }

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
    relay_output: &'a Path,
    agent_output: &'a Path,
    relay_addr: &'a str,
    agent_id: &'a str,
    relay_user: &'a str,
    relay_authorized_keys: &'a [PathBuf],
    relay_authorized_key_files: &'a [PathBuf],
    agent_authorized_keys: &'a [PathBuf],
    agent_authorized_key_files: &'a [PathBuf],
    relay_host_public_key: Option<&'a Path>,
    agent_private_key: &'a Path,
    force: bool,
}

fn write_pair_templates(options: PairInitOptions<'_>) -> Result<()> {
    if options.relay_output == options.agent_output {
        bail!("relay_output and agent_output must be different paths");
    }
    if options.relay_addr.is_empty() {
        bail!("relay_addr cannot be empty");
    }
    validate_agent_id(options.agent_id)?;
    validate_config_table_key("relay_user", options.relay_user)?;
    ensure_can_write(options.relay_output, options.force)?;
    ensure_can_write(options.agent_output, options.force)?;

    let mut relay_authorized_keys = read_authorized_public_keys(
        "relay authorized key",
        options.relay_authorized_keys,
        options.relay_authorized_key_files,
    )?;
    if relay_authorized_keys.is_empty() {
        relay_authorized_keys
            .push("ssh-ed25519 REPLACE_WITH_RELAY_USER_AUTHORIZED_KEY alice@example".to_string());
    }

    let mut agent_authorized_keys = read_authorized_public_keys(
        "agent authorized key",
        options.agent_authorized_keys,
        options.agent_authorized_key_files,
    )?;
    if agent_authorized_keys.is_empty() {
        agent_authorized_keys
            .push("ssh-ed25519 REPLACE_WITH_AGENT_AUTHORIZED_KEY alice-home-agent".to_string());
    }

    let relay_host_key = match options.relay_host_public_key {
        Some(path) => read_single_public_key("relay host public key", path)?,
        None => "ssh-ed25519 REPLACE_WITH_RELAY_HOST_PUBLIC_KEY relay@example".to_string(),
    };
    let agent_private_key = path_to_config_string(options.agent_private_key)?;
    let input = PairTemplateInput {
        relay_user: options.relay_user,
        relay_authorized_keys: &relay_authorized_keys,
        agent_authorized_keys: &agent_authorized_keys,
        relay_addr: options.relay_addr,
        relay_host_key: &relay_host_key,
        agent_private_key: &agent_private_key,
        agent_id: options.agent_id,
    };

    write_template(options.relay_output, &render_relay_config(&input), true)?;
    write_template(options.agent_output, &render_agent_config(&input), true)?;
    Ok(())
}

fn read_authorized_public_keys(
    label: &str,
    authorized_key_paths: &[PathBuf],
    authorized_keys_paths: &[PathBuf],
) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    for path in authorized_key_paths {
        push_unique_authorized_key(&mut keys, read_single_public_key(label, path)?);
    }
    for path in authorized_keys_paths {
        for key in read_authorized_keys_file(label, path)? {
            push_unique_authorized_key(&mut keys, key);
        }
    }
    Ok(keys)
}

fn read_single_public_key(label: &str, path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    let keys = parse_authorized_key_lines(label, &raw, path)?;
    match keys.as_slice() {
        [key] => Ok(key.clone()),
        [] => bail!("{label} {} does not contain a public key", path.display()),
        _ => bail!(
            "{label} {} contains multiple public keys; use an authorized_keys input for multiple keys",
            path.display()
        ),
    }
}

fn read_authorized_keys_file(label: &str, path: &Path) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    let keys = parse_authorized_key_lines(label, &raw, path)?;
    if keys.is_empty() {
        bail!(
            "{label} {} does not contain any public keys",
            path.display()
        );
    }
    Ok(keys)
}

fn parse_authorized_key_lines(label: &str, raw: &str, path: &Path) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let key = extract_public_key_from_authorized_key_line(line)
            .with_context(|| format!("invalid {label} {}:{}", path.display(), index + 1))?;
        parse_public_key(&key)
            .with_context(|| format!("invalid {label} {}:{}", path.display(), index + 1))?;
        keys.push(key);
    }
    Ok(keys)
}

fn extract_public_key_from_authorized_key_line(line: &str) -> Result<String> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    let Some(key_type_index) = parts.iter().position(|part| is_ssh_public_key_type(part)) else {
        bail!("missing SSH public key type");
    };
    if key_type_index + 1 >= parts.len() {
        bail!("missing SSH public key body");
    }
    Ok(parts[key_type_index..].join(" "))
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

fn push_unique_authorized_key(keys: &mut Vec<String>, key: String) {
    if !keys.iter().any(|existing| existing == &key) {
        keys.push(key);
    }
}

fn path_to_config_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(ToString::to_string)
        .with_context(|| format!("path must be valid UTF-8: {}", path.display()))
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
    if output.as_os_str() != "-" && output.exists() && !force {
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
    use russh::keys::{Algorithm, PrivateKey};

    fn public_key_line(comment: &str) -> String {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        format!("{} {comment}", key.public_key().to_openssh().unwrap())
    }

    #[test]
    fn parses_authorized_keys_file_style_lines() {
        let key_a = public_key_line("laptop");
        let key_b = public_key_line("phone");
        let raw = format!("# relay user keys\n{key_a}\nno-pty {key_b}\n\n");
        let parsed =
            parse_authorized_key_lines("relay authorized key", &raw, Path::new("authorized_keys"))
                .unwrap();

        assert_eq!(parsed, vec![key_a, key_b]);
    }
}
