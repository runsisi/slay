pub const DEFAULT_RELAY_TLS_CERT_PATH: &str = "/etc/slay/relay.crt";
pub const DEFAULT_RELAY_TLS_KEY_PATH: &str = "/etc/slay/relay.key";

pub const RELAY_CONFIG_TEMPLATE: &str = r#"# slay relay config

[server]
ssh_listen = "0.0.0.0:2222"
relay_listen = "0.0.0.0:443"
ssh_host_key = "/etc/slay/relay_host_ed25519"
relay_tls_cert = "/etc/slay/relay.crt"
relay_tls_key = "/etc/slay/relay.key"
# For local development only:
# allow_insecure_relay = true

[users.alice]
# Replace with the public key used to authenticate to the relay.
public_keys = [
  "ssh-ed25519 REPLACE_WITH_RELAY_USER_PUBLIC_KEY alice@example"
]
allowed_machines = [
  "alice-home-linux"
]

[machines.alice_home]
machine_id = "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW"
machine_alias = "alice-home-linux"
display_name = "Alice Home Linux"
# Generate with: slay config token
agent_token_hash = "REPLACE_WITH_AGENT_TOKEN_HASH"
target = "127.0.0.1:22"
"#;

pub const AGENT_CONFIG_TEMPLATE: &str = r#"# slay agent config

relay_addr = "relay.example.com:443"
relay_name = "relay.example.com"
# For public CA certificates, relay_ca_cert can be omitted.
relay_ca_cert = "/etc/slay/relay-ca.crt"
# For local development only:
# allow_insecure_relay = true

machine_id = "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW"
# Use the token that was hashed into relay config.
agent_token = "REPLACE_WITH_AGENT_TOKEN_AT_LEAST_32_CHARS"
target = "127.0.0.1:22"
reconnect_secs = 5
"#;

pub struct PairTemplateInput<'a> {
    pub relay_user: &'a str,
    pub relay_public_keys: &'a [String],
    pub relay_addr: &'a str,
    pub relay_name: &'a str,
    pub relay_tls_cert: Option<&'a str>,
    pub relay_tls_key: Option<&'a str>,
    pub relay_allow_insecure: bool,
    pub relay_ca_cert: Option<&'a str>,
    pub agent_allow_insecure: bool,
    pub machine_id: &'a str,
    pub machine_alias: &'a str,
    pub display_name: &'a str,
    pub agent_token: &'a str,
    pub agent_token_hash: &'a str,
}

pub fn render_relay_config(input: &PairTemplateInput<'_>) -> String {
    let relay_user = input.relay_user;
    let relay_public_keys = render_toml_array_items(input.relay_public_keys);
    let tls_config = render_relay_tls_config(input);
    let machine_id = toml_string(input.machine_id);
    let machine_alias = toml_string(input.machine_alias);
    let display_name = toml_string(input.display_name);
    let agent_token_hash = toml_string(input.agent_token_hash);
    format!(
        r#"# slay relay config

[server]
ssh_listen = "0.0.0.0:2222"
relay_listen = "0.0.0.0:443"
ssh_host_key = "/etc/slay/relay_host_ed25519"
{tls_config}

[users.{relay_user}]
# Replace with the public key used to authenticate to the relay.
public_keys = [
{relay_public_keys}
]
allowed_machines = [
  {machine_alias}
]

[machines.default]
machine_id = {machine_id}
machine_alias = {machine_alias}
display_name = {display_name}
agent_token_hash = {agent_token_hash}
target = "127.0.0.1:22"
"#,
    )
}

pub fn render_agent_config(input: &PairTemplateInput<'_>) -> String {
    let relay_addr = toml_string(input.relay_addr);
    let relay_name = toml_string(input.relay_name);
    let tls_config = render_agent_relay_tls_config(input);
    let machine_id = toml_string(input.machine_id);
    let agent_token = toml_string(input.agent_token);
    format!(
        r#"# slay agent config

relay_addr = {relay_addr}
relay_name = {relay_name}
{tls_config}

machine_id = {machine_id}
agent_token = {agent_token}
target = "127.0.0.1:22"
reconnect_secs = 5
"#,
    )
}

fn render_relay_tls_config(input: &PairTemplateInput<'_>) -> String {
    if input.relay_allow_insecure {
        return "allow_insecure_relay = true".to_string();
    }

    let cert = input
        .relay_tls_cert
        .map(toml_string)
        .unwrap_or_else(|| toml_string(DEFAULT_RELAY_TLS_CERT_PATH));
    let key = input
        .relay_tls_key
        .map(toml_string)
        .unwrap_or_else(|| toml_string(DEFAULT_RELAY_TLS_KEY_PATH));
    format!("relay_tls_cert = {cert}\nrelay_tls_key = {key}")
}

fn render_agent_relay_tls_config(input: &PairTemplateInput<'_>) -> String {
    if input.agent_allow_insecure {
        return "allow_insecure_relay = true".to_string();
    }

    input
        .relay_ca_cert
        .map(|path| format!("relay_ca_cert = {}", toml_string(path)))
        .unwrap_or_else(|| {
            "# relay_ca_cert can be omitted when the relay certificate uses a public CA".to_string()
        })
}

fn render_toml_array_items(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("  {}", toml_string(value)))
        .collect::<Vec<_>>()
        .join(",\n")
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_template_is_toml() {
        toml::from_str::<toml::Value>(RELAY_CONFIG_TEMPLATE).unwrap();
    }

    #[test]
    fn agent_template_is_toml() {
        toml::from_str::<toml::Value>(AGENT_CONFIG_TEMPLATE).unwrap();
    }

    #[test]
    fn rendered_pair_templates_are_toml() {
        let relay_public_keys = vec!["ssh-ed25519 AAAA alice@example".to_string()];
        let input = PairTemplateInput {
            relay_user: "alice",
            relay_public_keys: &relay_public_keys,
            relay_addr: "relay.example.com:443",
            relay_name: "relay.example.com",
            relay_tls_cert: Some("/tmp/slay-tls/relay.crt"),
            relay_tls_key: Some("/tmp/slay-tls/relay.key"),
            relay_allow_insecure: false,
            relay_ca_cert: Some("/tmp/slay-tls/relay-ca.crt"),
            agent_allow_insecure: false,
            machine_id: "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW",
            machine_alias: "alice-home-linux",
            display_name: "Alice \"Home\" Linux",
            agent_token: "abcdefghijklmnopqrstuvwxyz0123456789",
            agent_token_hash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash",
        };
        toml::from_str::<toml::Value>(&render_relay_config(&input)).unwrap();
        toml::from_str::<toml::Value>(&render_agent_config(&input)).unwrap();
    }

    #[test]
    fn rendered_insecure_pair_templates_are_toml() {
        let relay_public_keys = vec!["ssh-ed25519 AAAA alice@example".to_string()];
        let input = PairTemplateInput {
            relay_user: "alice",
            relay_public_keys: &relay_public_keys,
            relay_addr: "127.0.0.1:4443",
            relay_name: "127.0.0.1",
            relay_tls_cert: None,
            relay_tls_key: None,
            relay_allow_insecure: true,
            relay_ca_cert: None,
            agent_allow_insecure: true,
            machine_id: "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW",
            machine_alias: "alice-home-linux",
            display_name: "Alice Home Linux",
            agent_token: "abcdefghijklmnopqrstuvwxyz0123456789",
            agent_token_hash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash",
        };
        toml::from_str::<toml::Value>(&render_relay_config(&input)).unwrap();
        toml::from_str::<toml::Value>(&render_agent_config(&input)).unwrap();
    }

    #[test]
    fn rendered_pair_template_supports_multiple_relay_public_keys() {
        let relay_public_keys = vec![
            "ssh-ed25519 AAAA alice@example".to_string(),
            "ssh-ed25519 BBBB phone@example".to_string(),
        ];
        let input = PairTemplateInput {
            relay_user: "alice",
            relay_public_keys: &relay_public_keys,
            relay_addr: "relay.example.com:443",
            relay_name: "relay.example.com",
            relay_tls_cert: Some("/etc/slay/relay.crt"),
            relay_tls_key: Some("/etc/slay/relay.key"),
            relay_allow_insecure: false,
            relay_ca_cert: Some("/tmp/slay-tls/relay-ca.crt"),
            agent_allow_insecure: false,
            machine_id: "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW",
            machine_alias: "alice-home-linux",
            display_name: "Alice Home Linux",
            agent_token: "abcdefghijklmnopqrstuvwxyz0123456789",
            agent_token_hash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash",
        };
        let raw = render_relay_config(&input);
        let parsed = toml::from_str::<toml::Value>(&raw).unwrap();
        let public_keys = parsed["users"]["alice"]["public_keys"].as_array().unwrap();
        assert_eq!(public_keys.len(), 2);
    }
}
