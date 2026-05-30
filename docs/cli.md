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
  --agent-authorized-key ~/.ssh/id_slay_agent.pub \
  --relay-host-public-key /etc/slay/relay_host_ed25519.pub \
  --agent-private-key /etc/slay/agent_ed25519
```

`--relay-addr` is the SSH address used by the agent to connect back to the relay. The relay SSH host key is written to `relay_host_key` in the agent config so the agent can verify the relay before authenticating.

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

If relay user keys, agent keys, or the relay host public key are omitted, `config init` writes placeholders. Replace them before validating or running.

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

1. Create or choose SSH keys:

```bash
ssh-keygen -t ed25519 -f /etc/slay/relay_host_ed25519 -N ''
ssh-keygen -t ed25519 -f /etc/slay/agent_ed25519 -N ''
```

Use a normal user SSH public key for `--relay-authorized-key`. Use `/etc/slay/agent_ed25519.pub` for `--agent-authorized-key`.

2. Create matching relay and agent configs:

```bash
slay config init \
  --relay-output slay-relay.toml \
  --agent-output slay-agent.toml \
  --relay-addr relay.example.com:2222 \
  --relay-user alice \
  --relay-authorized-key ~/.ssh/id_ed25519.pub \
  --agent-authorized-key /etc/slay/agent_ed25519.pub \
  --relay-host-public-key /etc/slay/relay_host_ed25519.pub \
  --agent-private-key /etc/slay/agent_ed25519 \
  --agent-id alice-home-linux
```

3. Edit `slay-relay.toml`:

- Set `[server].ssh_host_key` to the relay host private key.
- Confirm `[users.<name>].authorized_keys`.
- Confirm `[agents.<agent_id>].agent_authorized_keys`.
- Keep each `[agents.<agent_id>]` table key unique.

4. Edit `slay-agent.toml`:

- Confirm `relay_addr`.
- Confirm `relay_host_key` matches the relay SSH host public key.
- Confirm `agent_id` matches the relay `[agents.<agent_id>]` entry.
- Confirm `agent_private_key` points to the private half of a relay `agent_authorized_keys` entry.

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
