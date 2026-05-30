# Slay CLI

`slay` uses one binary with role-specific subcommands.

## Runtime Commands

Run the VPS relay:

```bash
slay relay --config slay-relay.toml
```

Run the agent on an internal machine:

```bash
slay agent --config slay-agent.toml
```

## Config Commands

Create matching relay and agent configs:

```bash
slay config init \
  --relay-output slay-relay.toml \
  --agent-output slay-agent.toml \
  --relay-addr relay.example.com:2222 \
  --relay-user alice \
  --relay-authorized-key ~/.ssh/id_relay_user.pub \
  --agent-id alice-home-linux
```

`--relay-addr` is the SSH address used by the agent to connect back to the relay. `config init` generates both the relay host key and the agent key by default, embeds the private keys in the generated configs, and writes the matching public keys into `relay_known_hosts` and `agent_authorized_keys`.

Embed existing relay or agent private keys instead of generating them:

```bash
slay config init \
  --relay-addr relay.example.com:2222 \
  --relay-authorized-key ~/.ssh/id_relay_user.pub \
  --relay-host-key /etc/slay/relay_host_ed25519 \
  --agent-private-key /etc/slay/agent_ed25519
```

Authorize multiple SSH client keys for the relay user:

```bash
slay config init \
  --relay-addr relay.example.com:2222 \
  --relay-authorized-key ~/.ssh/id_laptop.pub \
  --relay-authorized-key ~/.ssh/id_phone.pub
```

Read OpenSSH-style `authorized_keys` files:

```bash
slay config init \
  --relay-addr relay.example.com:2222 \
  --relay-authorized-keys ~/.ssh/authorized_keys \
  --agent-authorized-keys ./agent_authorized_keys
```

Set the agent id during paired generation:

```bash
slay config init \
  --relay-addr relay.example.com:2222 \
  --relay-authorized-key ~/.ssh/id_relay_user.pub \
  --agent-authorized-key ~/.ssh/id_slay_agent.pub \
  --agent-id alice-home-linux
```

If relay user keys are omitted, `config init` writes placeholders. Replace them before validating or running.

Generate a relay config:

```bash
slay config gen relay --output slay-relay.toml
```

Generate an agent config:

```bash
slay config gen agent --output slay-agent.toml
```

Overwrite an existing generated config:

```bash
slay config gen relay --output slay-relay.toml --force
```

Print generated config to stdout:

```bash
slay config gen relay --output -
```

Validate configs:

```bash
slay config validate relay --config slay-relay.toml
slay config validate agent --config slay-agent.toml
```

## Minimal Setup Flow

1. Create or choose a normal user SSH key for `--relay-authorized-key`. Relay host and agent keys can be generated and embedded by `config init`.

2. Create matching relay and agent configs:

```bash
slay config init \
  --relay-output slay-relay.toml \
  --agent-output slay-agent.toml \
  --relay-addr relay.example.com:2222 \
  --relay-user alice \
  --relay-authorized-key ~/.ssh/id_ed25519.pub \
  --agent-id alice-home-linux
```

3. Edit `slay-relay.toml`:

- Confirm `[server].listen`.
- Protect `slay-relay.toml`; `[server].host_key` contains the relay SSH host private key.
- Confirm `[users.<name>].authorized_keys`.
- Confirm `[agents.<agent_id>].agent_authorized_keys` contains the agent public key derived from `slay-agent.toml`.
- Keep each `[agents.<agent_id>]` table key unique.

4. Edit `slay-agent.toml`:

- Confirm `relay_addr`.
- Confirm `relay_known_hosts` contains the relay address and SSH host public key.
- Confirm `agent_id` matches the relay `[agents.<agent_id>]` entry.
- Protect `slay-agent.toml`; `private_key` contains the agent SSH private key.

5. Validate both configs:

```bash
slay config validate relay --config slay-relay.toml
slay config validate agent --config slay-agent.toml
```

6. Start both roles:

```bash
slay relay --config slay-relay.toml
slay agent --config slay-agent.toml
```

The agent connects to the relay over SSH, authenticates as `agent_id`, and registers reverse forwarding for `agent_id:22`. User SSH clients still connect to the relay and request `direct-tcpip` to the agent id through `ProxyJump`.
