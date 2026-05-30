use std::{fs, io, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use slay::agent::run_agent;
use slay::config::{AgentConfig, RelayConfig};
use slay::config_templates::{AGENT_CONFIG_TEMPLATE, RELAY_CONFIG_TEMPLATE};
use slay::relay::run_relay_server;
use slay::token::hash_token;

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
    #[command(about = "Hash an agent token for relay config")]
    HashToken {
        #[arg(help = "Token to hash. If omitted, token is read from stdin.")]
        token: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigInitTarget {
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

fn write_template(output: &PathBuf, content: &str, force: bool) -> Result<()> {
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

fn read_token(token: Option<String>) -> Result<String> {
    if let Some(token) = token {
        return Ok(token);
    }

    let mut input = String::new();
    io::Read::read_to_string(&mut io::stdin(), &mut input).context("failed to read token")?;
    Ok(input.trim_end_matches(['\r', '\n']).to_string())
}
