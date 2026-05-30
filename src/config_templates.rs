pub const DEFAULT_AGENT_PRIVATE_KEY_PATH: &str = "/etc/slay/agent_ed25519";

pub const RELAY_CONFIG_TEMPLATE: &str = r#"# slay relay config

[server]
ssh_listen = "0.0.0.0:2222"
ssh_host_key = "/etc/slay/relay_host_ed25519"

[users.alice]
# Replace with the SSH client keys allowed to use the relay.
authorized_keys = [
  "ssh-ed25519 REPLACE_WITH_RELAY_USER_AUTHORIZED_KEY alice@example"
]
allowed_agents = [
  "alice-home-linux"
]

[agents.alice-home-linux]
# Replace with the public key for this agent.
agent_authorized_keys = [
  "ssh-ed25519 REPLACE_WITH_AGENT_AUTHORIZED_KEY alice-home-agent"
]
target = "127.0.0.1:22"
"#;

pub const AGENT_CONFIG_TEMPLATE: &str = r#"# slay agent config

relay_addr = "relay.example.com:2222"
# The relay SSH host public key. Use the public half of [server].ssh_host_key.
relay_host_key = "ssh-ed25519 REPLACE_WITH_RELAY_HOST_PUBLIC_KEY relay@example"

agent_id = "alice-home-linux"
agent_private_key = "/etc/slay/agent_ed25519"
target = "127.0.0.1:22"
reconnect_secs = 5
"#;

pub struct PairTemplateInput<'a> {
    pub relay_user: &'a str,
    pub relay_authorized_keys: &'a [String],
    pub agent_authorized_keys: &'a [String],
    pub relay_addr: &'a str,
    pub relay_host_key: &'a str,
    pub agent_private_key: &'a str,
    pub agent_id: &'a str,
}

pub fn render_relay_config(input: &PairTemplateInput<'_>) -> String {
    let relay_user = input.relay_user;
    let relay_authorized_keys = render_toml_array_items(input.relay_authorized_keys);
    let agent_authorized_keys = render_toml_array_items(input.agent_authorized_keys);
    let agent_id = toml_string(input.agent_id);
    let agent_table_key = input.agent_id;
    format!(
        r#"# slay relay config

[server]
ssh_listen = "0.0.0.0:2222"
ssh_host_key = "/etc/slay/relay_host_ed25519"

[users.{relay_user}]
# SSH client keys allowed to use the relay.
authorized_keys = [
{relay_authorized_keys}
]
allowed_agents = [
  {agent_id}
]

[agents.{agent_table_key}]
# SSH key used by the agent to register reverse forwarding.
agent_authorized_keys = [
{agent_authorized_keys}
]
target = "127.0.0.1:22"
"#,
    )
}

pub fn render_agent_config(input: &PairTemplateInput<'_>) -> String {
    let relay_addr = toml_string(input.relay_addr);
    let relay_host_key = toml_string(input.relay_host_key);
    let agent_id = toml_string(input.agent_id);
    let agent_private_key = toml_string(input.agent_private_key);
    format!(
        r#"# slay agent config

relay_addr = {relay_addr}
relay_host_key = {relay_host_key}

agent_id = {agent_id}
agent_private_key = {agent_private_key}
target = "127.0.0.1:22"
reconnect_secs = 5
"#,
    )
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
        let relay_authorized_keys = vec!["ssh-ed25519 AAAA alice@example".to_string()];
        let agent_authorized_keys = vec!["ssh-ed25519 BBBB alice-home-agent".to_string()];
        let input = PairTemplateInput {
            relay_user: "alice",
            relay_authorized_keys: &relay_authorized_keys,
            agent_authorized_keys: &agent_authorized_keys,
            relay_addr: "relay.example.com:2222",
            relay_host_key: "ssh-ed25519 CCCC relay@example",
            agent_private_key: "/etc/slay/agent_ed25519",
            agent_id: "alice-home-linux",
        };
        toml::from_str::<toml::Value>(&render_relay_config(&input)).unwrap();
        toml::from_str::<toml::Value>(&render_agent_config(&input)).unwrap();
    }

    #[test]
    fn rendered_pair_template_supports_multiple_relay_keys() {
        let relay_authorized_keys = vec![
            "ssh-ed25519 AAAA alice@example".to_string(),
            "ssh-ed25519 BBBB phone@example".to_string(),
        ];
        let agent_authorized_keys = vec!["ssh-ed25519 CCCC alice-home-agent".to_string()];
        let input = PairTemplateInput {
            relay_user: "alice",
            relay_authorized_keys: &relay_authorized_keys,
            agent_authorized_keys: &agent_authorized_keys,
            relay_addr: "relay.example.com:2222",
            relay_host_key: "ssh-ed25519 DDDD relay@example",
            agent_private_key: "/etc/slay/agent_ed25519",
            agent_id: "alice-home-linux",
        };
        let raw = render_relay_config(&input);
        let parsed = toml::from_str::<toml::Value>(&raw).unwrap();
        let authorized_keys = parsed["users"]["alice"]["authorized_keys"]
            .as_array()
            .unwrap();
        assert_eq!(authorized_keys.len(), 2);
    }
}
