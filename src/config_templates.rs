pub const RELAY_CONFIG_TEMPLATE: &str = r#"# slay relay config

[server]
ssh_listen = "0.0.0.0:2222"
agent_listen = "0.0.0.0:443"
ssh_host_key = "/etc/slay/relay_host_ed25519"
agent_tls_cert = "/etc/slay/agent_relay.crt"
agent_tls_key = "/etc/slay/agent_relay.key"
# For local development only:
# allow_insecure_agent_link = true

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
relay_ca_cert = "/etc/slay/agent_relay_ca.crt"
# For local development only:
# allow_insecure_relay_link = true

machine_id = "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW"
# Use the token that was hashed into relay config.
agent_token = "REPLACE_WITH_AGENT_TOKEN_AT_LEAST_32_CHARS"
target = "127.0.0.1:22"
reconnect_secs = 5
"#;

pub struct PairTemplateInput<'a> {
    pub relay_user: &'a str,
    pub relay_public_key: &'a str,
    pub machine_id: &'a str,
    pub machine_alias: &'a str,
    pub display_name: &'a str,
    pub agent_token: &'a str,
    pub agent_token_hash: &'a str,
}

pub fn render_relay_config(input: &PairTemplateInput<'_>) -> String {
    let relay_user = input.relay_user;
    let relay_public_key = toml_string(input.relay_public_key);
    let machine_id = toml_string(input.machine_id);
    let machine_alias = toml_string(input.machine_alias);
    let display_name = toml_string(input.display_name);
    let agent_token_hash = toml_string(input.agent_token_hash);
    format!(
        r#"# slay relay config

[server]
ssh_listen = "0.0.0.0:2222"
agent_listen = "0.0.0.0:443"
ssh_host_key = "/etc/slay/relay_host_ed25519"
agent_tls_cert = "/etc/slay/agent_relay.crt"
agent_tls_key = "/etc/slay/agent_relay.key"
# For local development only:
# allow_insecure_agent_link = true

[users.{relay_user}]
# Replace with the public key used to authenticate to the relay.
public_keys = [
  {relay_public_key}
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
    let machine_id = toml_string(input.machine_id);
    let agent_token = toml_string(input.agent_token);
    format!(
        r#"# slay agent config

relay_addr = "relay.example.com:443"
relay_name = "relay.example.com"
# For public CA certificates, relay_ca_cert can be omitted.
relay_ca_cert = "/etc/slay/agent_relay_ca.crt"
# For local development only:
# allow_insecure_relay_link = true

machine_id = {machine_id}
agent_token = {agent_token}
target = "127.0.0.1:22"
reconnect_secs = 5
"#,
    )
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
        let input = PairTemplateInput {
            relay_user: "alice",
            relay_public_key: "ssh-ed25519 AAAA alice@example",
            machine_id: "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW",
            machine_alias: "alice-home-linux",
            display_name: "Alice \"Home\" Linux",
            agent_token: "abcdefghijklmnopqrstuvwxyz0123456789",
            agent_token_hash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash",
        };
        toml::from_str::<toml::Value>(&render_relay_config(&input)).unwrap();
        toml::from_str::<toml::Value>(&render_agent_config(&input)).unwrap();
    }
}
