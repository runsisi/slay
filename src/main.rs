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
    AGENT_CONFIG_TEMPLATE, DEFAULT_RELAY_TLS_CERT_PATH, DEFAULT_RELAY_TLS_KEY_PATH,
    PairTemplateInput, RELAY_CONFIG_TEMPLATE, render_agent_config, render_relay_config,
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
    #[command(about = "Create matching relay and agent configs")]
    Init {
        #[arg(long, default_value = "slay-relay.toml")]
        relay_output: PathBuf,
        #[arg(long, default_value = "slay-agent.toml")]
        agent_output: PathBuf,
        #[arg(long)]
        relay_addr: String,
        #[arg(long)]
        relay_name: Option<String>,
        #[arg(long, default_value = "home-linux")]
        machine_alias: String,
        #[arg(long, default_value = "Home Linux")]
        display_name: String,
        #[arg(long, default_value = "alice")]
        relay_user: String,
        #[arg(long = "relay-authorized-key", value_name = "PATH")]
        relay_authorized_keys: Vec<PathBuf>,
        #[arg(long = "relay-authorized-keys", value_name = "PATH")]
        relay_authorized_key_files: Vec<PathBuf>,
        #[arg(long, value_enum, default_value_t = RelayTlsMode::PrivateCa)]
        relay_tls: RelayTlsMode,
        #[arg(long, default_value = "slay-tls")]
        tls_dir: PathBuf,
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
    #[command(about = "Generate a new agent token and relay-side hash")]
    Token,
    #[command(about = "Hash an agent token for relay config")]
    HashToken {
        #[arg(help = "Token to hash. If omitted, token is read from stdin.")]
        token: Option<String>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RelayTlsMode {
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
        ConfigCommand::Init {
            relay_output,
            agent_output,
            relay_addr,
            relay_name,
            machine_alias,
            display_name,
            relay_user,
            relay_authorized_keys,
            relay_authorized_key_files,
            relay_tls,
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
            relay_authorized_keys: &relay_authorized_keys,
            relay_authorized_key_files: &relay_authorized_key_files,
            relay_tls,
            tls_dir: &tls_dir,
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
        .with_context(|| format!("failed to write config file {}", output.display()))?;
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
    relay_authorized_keys: &'a [PathBuf],
    relay_authorized_key_files: &'a [PathBuf],
    relay_tls: RelayTlsMode,
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
        options.relay_tls,
        options.tls_dir,
        &relay_name,
        options.force,
    )?;

    let agent_token = generate_token();
    let agent_token_hash = hash_token(&agent_token)?;
    let machine_id = generate_machine_id();
    let mut relay_public_keys = read_relay_authorized_public_keys(
        options.relay_authorized_keys,
        options.relay_authorized_key_files,
    )?;
    if relay_public_keys.is_empty() {
        relay_public_keys
            .push("ssh-ed25519 REPLACE_WITH_RELAY_USER_PUBLIC_KEY alice@example".to_string());
    }
    let input = PairTemplateInput {
        relay_user: options.relay_user,
        relay_public_keys: &relay_public_keys,
        relay_addr: options.relay_addr,
        relay_name: &relay_name,
        relay_tls_cert: tls_config.relay_tls_cert.as_deref(),
        relay_tls_key: tls_config.relay_tls_key.as_deref(),
        relay_allow_insecure: tls_config.relay_allow_insecure,
        relay_ca_cert: tls_config.relay_ca_cert.as_deref(),
        agent_allow_insecure: tls_config.agent_allow_insecure,
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

fn read_relay_authorized_public_keys(
    authorized_key_paths: &[PathBuf],
    authorized_keys_paths: &[PathBuf],
) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    for path in authorized_key_paths {
        push_unique_authorized_key(&mut keys, read_relay_authorized_key(path)?);
    }
    for path in authorized_keys_paths {
        for key in read_relay_authorized_keys_file(path)? {
            push_unique_authorized_key(&mut keys, key);
        }
    }
    Ok(keys)
}

fn read_relay_authorized_key(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read relay authorized key {}", path.display()))?;
    let keys = parse_authorized_key_lines(&raw, path)?;
    match keys.as_slice() {
        [key] => Ok(key.clone()),
        [] => bail!(
            "relay authorized key {} does not contain a public key",
            path.display()
        ),
        _ => bail!(
            "relay authorized key {} contains multiple public keys; use --relay-authorized-keys for authorized_keys files",
            path.display()
        ),
    }
}

fn read_relay_authorized_keys_file(path: &Path) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read relay authorized keys {}", path.display()))?;
    let keys = parse_authorized_key_lines(&raw, path)?;
    if keys.is_empty() {
        bail!(
            "relay authorized keys {} does not contain any public keys",
            path.display()
        );
    }
    Ok(keys)
}

fn parse_authorized_key_lines(raw: &str, path: &Path) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let key = extract_public_key_from_authorized_key_line(line).with_context(|| {
            format!(
                "invalid relay authorized key {}:{}",
                path.display(),
                index + 1
            )
        })?;
        parse_public_key(&key).with_context(|| {
            format!(
                "invalid relay authorized key {}:{}",
                path.display(),
                index + 1
            )
        })?;
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

fn is_ssh_public_key_type(token: &str) -> bool {
    matches!(
        token,
        "ssh-ed25519"
            | "ssh-rsa"
            | "rsa-sha2-256"
            | "rsa-sha2-512"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) || token.starts_with("ecdsa-sha2-")
}

fn push_unique_authorized_key(keys: &mut Vec<String>, key: String) {
    if !keys.iter().any(|existing| existing == &key) {
        keys.push(key);
    }
}

struct PairTlsConfig {
    relay_tls_cert: Option<String>,
    relay_tls_key: Option<String>,
    relay_allow_insecure: bool,
    relay_ca_cert: Option<String>,
    agent_allow_insecure: bool,
}

fn prepare_pair_tls_config(
    mode: RelayTlsMode,
    tls_dir: &Path,
    relay_name: &str,
    force: bool,
) -> Result<PairTlsConfig> {
    match mode {
        RelayTlsMode::PrivateCa => generate_private_ca_tls_config(tls_dir, relay_name, force),
        RelayTlsMode::External => Ok(PairTlsConfig {
            relay_tls_cert: None,
            relay_tls_key: None,
            relay_allow_insecure: false,
            relay_ca_cert: None,
            agent_allow_insecure: false,
        }),
        RelayTlsMode::Insecure => Ok(PairTlsConfig {
            relay_tls_cert: None,
            relay_tls_key: None,
            relay_allow_insecure: true,
            relay_ca_cert: None,
            agent_allow_insecure: true,
        }),
    }
}

fn generate_private_ca_tls_config(
    tls_dir: &Path,
    relay_name: &str,
    force: bool,
) -> Result<PairTlsConfig> {
    let tls_dir = absolute_path(tls_dir)?;
    let ca_cert_path = tls_dir.join("relay-ca.crt");
    let ca_key_path = tls_dir.join("relay-ca.key");
    let relay_cert_path = tls_dir.join("relay.crt");
    let relay_key_path = tls_dir.join("relay.key");
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
        relay_tls_cert: Some(DEFAULT_RELAY_TLS_CERT_PATH.to_string()),
        relay_tls_key: Some(DEFAULT_RELAY_TLS_KEY_PATH.to_string()),
        relay_allow_insecure: false,
        relay_ca_cert: Some(path_to_config_string(&ca_cert_path)?),
        agent_allow_insecure: false,
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
        .push(DnType::CommonName, "slay relay CA");
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

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_tls_dir() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("slay-main-test-{}-{suffix}", std::process::id()))
    }

    fn public_key_line(comment: &str) -> String {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        format!("{} {comment}", key.public_key().to_openssh().unwrap())
    }

    #[test]
    fn private_ca_init_writes_relay_runtime_tls_paths() {
        let tls_dir = temp_tls_dir();
        let config = generate_private_ca_tls_config(&tls_dir, "relay.example.com", false).unwrap();

        assert_eq!(
            config.relay_tls_cert.as_deref(),
            Some(DEFAULT_RELAY_TLS_CERT_PATH)
        );
        assert_eq!(
            config.relay_tls_key.as_deref(),
            Some(DEFAULT_RELAY_TLS_KEY_PATH)
        );
        assert!(tls_dir.join("relay.crt").exists());
        assert!(tls_dir.join("relay.key").exists());

        fs::remove_dir_all(&tls_dir).unwrap();
    }

    #[test]
    fn parses_authorized_keys_file_style_lines() {
        let key_a = public_key_line("laptop");
        let key_b = public_key_line("phone");
        let raw = format!("# relay user keys\n{key_a}\nno-pty {key_b}\n\n");
        let parsed = parse_authorized_key_lines(&raw, Path::new("authorized_keys")).unwrap();

        assert_eq!(parsed, vec![key_a, key_b]);
    }
}
