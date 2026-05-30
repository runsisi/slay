pub const RELAY_CONFIG_TEMPLATE: &str = r#"# slay relay config

[server]
ssh_listen = "0.0.0.0:2222"
agent_listen = "0.0.0.0:443"
ssh_host_key = "/etc/slay/relay_host_ed25519"
agent_tls_cert = "/etc/slay/agent_relay.crt"
agent_tls_key = "/etc/slay/agent_relay.key"

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
# Generate with: slay config hash-token
agent_token_hash = "REPLACE_WITH_AGENT_TOKEN_HASH"
target = "127.0.0.1:22"
"#;

pub const AGENT_CONFIG_TEMPLATE: &str = r#"# slay agent config

relay_addr = "relay.example.com:443"
relay_name = "relay.example.com"
relay_ca_cert = "/etc/slay/agent_relay_ca.crt"

machine_id = "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW"
# Use the token that was hashed into relay config.
agent_token = "REPLACE_WITH_AGENT_TOKEN_AT_LEAST_32_CHARS"
target = "127.0.0.1:22"
reconnect_secs = 5
"#;

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
}
