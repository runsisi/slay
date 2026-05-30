use std::{
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use slay::agent::run_agent;
use slay::config::{AgentConfig, RelayConfig, parse_public_key};
use slay::config_templates::{
    AGENT_CONFIG_TEMPLATE, PairTemplateInput, RELAY_CONFIG_TEMPLATE, render_agent_config,
    render_relay_config,
};
use slay::relay::run_relay_server;
use slay::token::{generate_machine_id, generate_token, hash_token};

#[derive(Debug, Parser)]
#[command(version, about = "SSH relay for machines behind NAT")]
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
    #[command(about = "Run the internal machine agent")]
    Agent {
        #[arg(short, long, default_value = "slay-agent.toml")]
        config: PathBuf,
    },
    #[command(about = "Create, validate, and hash configuration")]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    #[command(about = "Create a config template")]
    Init {
        #[command(subcommand)]
        target: ConfigInitTarget,
    },
    #[command(about = "Validate a config file")]
    Validate {
        #[command(subcommand)]
        target: ConfigValidateTarget,
    },
    #[command(about = "Generate a new agent token and relay-side hash")]
    Token,
    #[command(about = "Hash an agent token for relay config")]
    HashToken {
        #[arg(help = "Token to hash. If omitted, token is read from stdin.")]
        token: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigInitTarget {
    #[command(about = "Create matching relay and agent configs")]
    Pair {
        #[arg(long, default_value = "slay-relay.toml")]
        relay_output: PathBuf,
        #[arg(long, default_value = "slay-agent.toml")]
        agent_output: PathBuf,
        #[arg(long, default_value = "home-linux")]
        machine_alias: String,
        #[arg(long, default_value = "Home Linux")]
        display_name: String,
        #[arg(long, default_value = "alice")]
        relay_user: String,
        #[arg(long)]
        relay_public_key: Option<PathBuf>,
        #[arg(short, long)]
        force: bool,
    },
    #[command(about = "Create a relay config template")]
    Relay {
        #[arg(short, long, default_value = "slay-relay.toml")]
        output: PathBuf,
        #[arg(short, long)]
        force: bool,
    },
    #[command(about = "Create an agent config template")]
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
        ConfigCommand::Init { target } => match target {
            ConfigInitTarget::Pair {
                relay_output,
                agent_output,
                machine_alias,
                display_name,
                relay_user,
                relay_public_key,
                force,
            } => write_pair_templates(
                &relay_output,
                &agent_output,
                &machine_alias,
                &display_name,
                &relay_user,
                relay_public_key.as_deref(),
                force,
            ),
            ConfigInitTarget::Relay { output, force } => {
                write_template(&output, RELAY_CONFIG_TEMPLATE, force)
            }
            ConfigInitTarget::Agent { output, force } => {
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
        ConfigCommand::Token => {
            let token = generate_token();
            let hash = hash_token(&token)?;
            println!("agent_token = \"{token}\"");
            println!("agent_token_hash = \"{hash}\"");
            Ok(())
        }
        ConfigCommand::HashToken { token } => {
            let token = read_token(token)?;
            if token.len() < 32 {
                bail!("token must be at least 32 characters");
            }
            println!("{}", hash_token(&token)?);
            Ok(())
        }
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
        .with_context(|| format!("failed to write config template {}", output.display()))?;
    println!("wrote {}", output.display());
    Ok(())
}

fn write_pair_templates(
    relay_output: &Path,
    agent_output: &Path,
    machine_alias: &str,
    display_name: &str,
    relay_user: &str,
    relay_public_key: Option<&Path>,
    force: bool,
) -> Result<()> {
    if relay_output == agent_output {
        bail!("relay_output and agent_output must be different paths");
    }
    validate_machine_alias(machine_alias)?;
    validate_config_table_key("relay_user", relay_user)?;
    ensure_can_write(relay_output, force)?;
    ensure_can_write(agent_output, force)?;

    let agent_token = generate_token();
    let agent_token_hash = hash_token(&agent_token)?;
    let machine_id = generate_machine_id();
    let relay_public_key = match relay_public_key {
        Some(path) => {
            let key = fs::read_to_string(path)
                .with_context(|| format!("failed to read relay public key {}", path.display()))?;
            let key = key.trim();
            parse_public_key(key)
                .with_context(|| format!("invalid relay public key {}", path.display()))?;
            key.to_string()
        }
        None => "ssh-ed25519 REPLACE_WITH_RELAY_USER_PUBLIC_KEY alice@example".to_string(),
    };
    let input = PairTemplateInput {
        relay_user,
        relay_public_key: &relay_public_key,
        machine_id: &machine_id,
        machine_alias,
        display_name,
        agent_token: &agent_token,
        agent_token_hash: &agent_token_hash,
    };

    write_template(relay_output, &render_relay_config(&input), true)?;
    write_template(agent_output, &render_agent_config(&input), true)?;
    Ok(())
}

fn validate_machine_alias(machine_alias: &str) -> Result<()> {
    if machine_alias.is_empty() {
        bail!("machine_alias cannot be empty");
    }
    let valid = machine_alias
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if !valid {
        bail!("machine_alias may only contain ASCII letters, digits, '_', '-' and '.'");
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

fn read_token(token: Option<String>) -> Result<String> {
    if let Some(token) = token {
        return Ok(token);
    }

    let mut input = String::new();
    io::Read::read_to_string(&mut io::stdin(), &mut input).context("failed to read token")?;
    Ok(input.trim_end_matches(['\r', '\n']).to_string())
}
