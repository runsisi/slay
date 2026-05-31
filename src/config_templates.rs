pub struct PairTemplateInput<'a> {
    pub relay_user: &'a str,
    pub relay_authorized_keys: &'a [String],
    pub agent_authorized_keys: &'a [String],
    pub relay_listen: &'a str,
    pub relay_addr: &'a str,
    pub host_key: &'a str,
    pub relay_known_hosts: &'a [String],
    pub agent_private_key: &'a str,
    pub agent_id: &'a str,
}

pub fn render_relay_config(input: &PairTemplateInput<'_>) -> String {
    let relay_user = input.relay_user;
    let relay_authorized_keys = render_toml_array_items(input.relay_authorized_keys);
    let agent_authorized_keys = render_toml_array_items(input.agent_authorized_keys);
    let relay_listen = toml_string(input.relay_listen);
    let host_key = toml_multiline_literal(input.host_key);
    let agent_id = toml_string(input.agent_id);
    let agent_table_key = input.agent_id;
    format!(
        r#"# slay relay config

[relay]
listen = {relay_listen}
host_key = {host_key}

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
"#,
    )
}

pub fn render_agent_config(input: &PairTemplateInput<'_>) -> String {
    let relay_addr = toml_string(input.relay_addr);
    let relay_known_hosts = render_toml_array_items(input.relay_known_hosts);
    let agent_id = toml_string(input.agent_id);
    let agent_private_key = toml_multiline_literal(input.agent_private_key);
    format!(
        r#"# slay agent config

relay_addr = {relay_addr}
relay_known_hosts = [
{relay_known_hosts}
]

agent_id = {agent_id}
agent_private_key = {agent_private_key}
forward_targets = [
  {{ name = "ssh", port = 22, target = "127.0.0.1:22" }}
]
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

fn toml_multiline_literal(value: &str) -> String {
    format!("'''{value}'''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_pair_templates_are_toml() {
        let relay_authorized_keys = vec!["ssh-ed25519 AAAA alice@example".to_string()];
        let agent_authorized_keys = vec!["ssh-ed25519 BBBB alice-home-agent".to_string()];
        let relay_known_hosts =
            vec!["[relay.example.com]:2222 ssh-ed25519 CCCC relay@example".to_string()];
        let input = PairTemplateInput {
            relay_user: "alice",
            relay_authorized_keys: &relay_authorized_keys,
            agent_authorized_keys: &agent_authorized_keys,
            relay_listen: "0.0.0.0:2222",
            relay_addr: "relay.example.com:2222",
            host_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nCCCC\n-----END OPENSSH PRIVATE KEY-----\n",
            relay_known_hosts: &relay_known_hosts,
            agent_private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
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
        let relay_known_hosts =
            vec!["[relay.example.com]:2222 ssh-ed25519 DDDD relay@example".to_string()];
        let input = PairTemplateInput {
            relay_user: "alice",
            relay_authorized_keys: &relay_authorized_keys,
            agent_authorized_keys: &agent_authorized_keys,
            relay_listen: "0.0.0.0:2222",
            relay_addr: "relay.example.com:2222",
            host_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nDDDD\n-----END OPENSSH PRIVATE KEY-----\n",
            relay_known_hosts: &relay_known_hosts,
            agent_private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
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
