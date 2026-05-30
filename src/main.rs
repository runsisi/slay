use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
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
        #[arg(long, default_value = "relay.example.com:443")]
        relay_addr: String,
        #[arg(long)]
        relay_name: Option<String>,
        #[arg(long, default_value = "home-linux")]
        machine_alias: String,
        #[arg(long, default_value = "Home Linux")]
        display_name: String,
        #[arg(long, default_value = "alice")]
        relay_user: String,
        #[arg(long)]
        relay_public_key: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = AgentTlsMode::PrivateCa)]
        agent_tls: AgentTlsMode,
        #[arg(long, default_value = "slay-tls")]
        tls_dir: PathBuf,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum AgentTlsMode {
    PrivateCa,
    External,
    Insecure,
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
                relay_addr,
                relay_name,
                machine_alias,
                display_name,
                relay_user,
                relay_public_key,
                agent_tls,
                tls_dir,
                force,
            } => write_pair_templates(PairInitOptions {
                relay_output: &relay_output,
                agent_output: &agent_output,
                relay_addr: &relay_addr,
                relay_name: relay_name.as_deref(),
                machine_alias: &machine_alias,
                display_name: &display_name,
                relay_user: &relay_user,
                relay_public_key: relay_public_key.as_deref(),
                agent_tls,
                tls_dir: &tls_dir,
                force,
            }),
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

struct PairInitOptions<'a> {
    relay_output: &'a Path,
    agent_output: &'a Path,
    relay_addr: &'a str,
    relay_name: Option<&'a str>,
    machine_alias: &'a str,
    display_name: &'a str,
    relay_user: &'a str,
    relay_public_key: Option<&'a Path>,
    agent_tls: AgentTlsMode,
    tls_dir: &'a Path,
    force: bool,
}

fn write_pair_templates(options: PairInitOptions<'_>) -> Result<()> {
    if options.relay_output == options.agent_output {
        bail!("relay_output and agent_output must be different paths");
    }
    if options.relay_addr.is_empty() {
        bail!("relay_addr cannot be empty");
    }
    let relay_name = resolve_relay_name(options.relay_addr, options.relay_name)?;
    validate_machine_alias(options.machine_alias)?;
    validate_config_table_key("relay_user", options.relay_user)?;
    ensure_can_write(options.relay_output, options.force)?;
    ensure_can_write(options.agent_output, options.force)?;
    let tls_config = prepare_pair_tls_config(
        options.agent_tls,
        options.tls_dir,
        &relay_name,
        options.force,
    )?;

    let agent_token = generate_token();
    let agent_token_hash = hash_token(&agent_token)?;
    let machine_id = generate_machine_id();
    let relay_public_key = match options.relay_public_key {
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
        relay_user: options.relay_user,
        relay_public_key: &relay_public_key,
        relay_addr: options.relay_addr,
        relay_name: &relay_name,
        relay_agent_tls_cert: tls_config.relay_agent_tls_cert.as_deref(),
        relay_agent_tls_key: tls_config.relay_agent_tls_key.as_deref(),
        allow_insecure_agent_link: tls_config.allow_insecure_agent_link,
        agent_relay_ca_cert: tls_config.agent_relay_ca_cert.as_deref(),
        allow_insecure_relay_link: tls_config.allow_insecure_relay_link,
        machine_id: &machine_id,
        machine_alias: options.machine_alias,
        display_name: options.display_name,
        agent_token: &agent_token,
        agent_token_hash: &agent_token_hash,
    };

    write_template(options.relay_output, &render_relay_config(&input), true)?;
    write_template(options.agent_output, &render_agent_config(&input), true)?;
    Ok(())
}

struct PairTlsConfig {
    relay_agent_tls_cert: Option<String>,
    relay_agent_tls_key: Option<String>,
    allow_insecure_agent_link: bool,
    agent_relay_ca_cert: Option<String>,
    allow_insecure_relay_link: bool,
}

fn prepare_pair_tls_config(
    mode: AgentTlsMode,
    tls_dir: &Path,
    relay_name: &str,
    force: bool,
) -> Result<PairTlsConfig> {
    match mode {
        AgentTlsMode::PrivateCa => generate_private_ca_tls_config(tls_dir, relay_name, force),
        AgentTlsMode::External => Ok(PairTlsConfig {
            relay_agent_tls_cert: None,
            relay_agent_tls_key: None,
            allow_insecure_agent_link: false,
            agent_relay_ca_cert: None,
            allow_insecure_relay_link: false,
        }),
        AgentTlsMode::Insecure => Ok(PairTlsConfig {
            relay_agent_tls_cert: None,
            relay_agent_tls_key: None,
            allow_insecure_agent_link: true,
            agent_relay_ca_cert: None,
            allow_insecure_relay_link: true,
        }),
    }
}

fn generate_private_ca_tls_config(
    tls_dir: &Path,
    relay_name: &str,
    force: bool,
) -> Result<PairTlsConfig> {
    let tls_dir = absolute_path(tls_dir)?;
    let ca_cert_path = tls_dir.join("agent_ca.crt");
    let ca_key_path = tls_dir.join("agent_ca.key");
    let relay_cert_path = tls_dir.join("agent_relay.crt");
    let relay_key_path = tls_dir.join("agent_relay.key");
    for path in [
        &ca_cert_path,
        &ca_key_path,
        &relay_cert_path,
        &relay_key_path,
    ] {
        ensure_can_write(path, force)?;
    }

    let material = generate_private_ca_tls_material(relay_name)?;
    fs::create_dir_all(&tls_dir)
        .with_context(|| format!("failed to create TLS directory {}", tls_dir.display()))?;
    write_generated_file(&ca_cert_path, &material.ca_cert_pem, false)?;
    write_generated_file(&ca_key_path, &material.ca_key_pem, true)?;
    write_generated_file(&relay_cert_path, &material.relay_cert_pem, false)?;
    write_generated_file(&relay_key_path, &material.relay_key_pem, true)?;

    Ok(PairTlsConfig {
        relay_agent_tls_cert: Some(path_to_config_string(&relay_cert_path)?),
        relay_agent_tls_key: Some(path_to_config_string(&relay_key_path)?),
        allow_insecure_agent_link: false,
        agent_relay_ca_cert: Some(path_to_config_string(&ca_cert_path)?),
        allow_insecure_relay_link: false,
    })
}

struct PrivateCaTlsMaterial {
    ca_cert_pem: String,
    ca_key_pem: String,
    relay_cert_pem: String,
    relay_key_pem: String,
}

fn generate_private_ca_tls_material(relay_name: &str) -> Result<PrivateCaTlsMaterial> {
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).context("failed to create CA params")?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "slay agent relay CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);

    let ca_key = KeyPair::generate().context("failed to generate CA key")?;
    let ca_key_pem = ca_key.serialize_pem();
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("failed to generate CA certificate")?;
    let ca_cert_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let mut relay_params = CertificateParams::new(vec![relay_name.to_string()])
        .with_context(|| format!("failed to create relay certificate params for {relay_name}"))?;
    relay_params
        .distinguished_name
        .push(DnType::CommonName, relay_name);
    relay_params.is_ca = IsCa::ExplicitNoCa;
    relay_params.use_authority_key_identifier_extension = true;
    relay_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    relay_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let relay_key = KeyPair::generate().context("failed to generate relay TLS key")?;
    let relay_key_pem = relay_key.serialize_pem();
    let relay_cert = relay_params
        .signed_by(&relay_key, &issuer)
        .context("failed to generate relay TLS certificate")?;

    Ok(PrivateCaTlsMaterial {
        ca_cert_pem,
        ca_key_pem,
        relay_cert_pem: relay_cert.pem(),
        relay_key_pem,
    })
}

fn write_generated_file(path: &Path, content: &str, private: bool) -> Result<()> {
    fs::write(path, content)
        .with_context(|| format!("failed to write generated file {}", path.display()))?;
    if private {
        set_private_file_permissions(path)?;
    }
    println!("wrote {}", path.display());
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set private permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn resolve_relay_name(relay_addr: &str, relay_name: Option<&str>) -> Result<String> {
    let name = relay_name.unwrap_or_else(|| relay_host_from_addr(relay_addr));
    if name.is_empty() {
        bail!("relay_name cannot be empty");
    }
    Ok(name.to_string())
}

fn relay_host_from_addr(relay_addr: &str) -> &str {
    if let Some(rest) = relay_addr.strip_prefix('[')
        && let Some((host, _)) = rest.split_once(']')
    {
        return host;
    }
    relay_addr
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(relay_addr)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(env::current_dir()
        .context("failed to read current directory")?
        .join(path))
}

fn path_to_config_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(ToString::to_string)
        .with_context(|| format!("path must be valid UTF-8: {}", path.display()))
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
