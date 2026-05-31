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
  --relay-addr relay.example.com:2222 \
  --relay-user alice \
  --agent-id alice-home-linux
```

`config init` writes `slay-relay.toml` and `slay-agent.toml`. `--relay-addr` is the SSH address used by the agent to connect back to the relay. `config init` uses the relay address port for the generated relay `[relay].listen` wildcard bind address. It generates the relay host key, the agent key, and the relay user key, embeds the role keys in the generated configs, writes the relay user public key into `authorized_keys`, and writes the agent public key into `agent_authorized_keys`. The generated relay user private key defaults to `slay-relay-<relay_user>.key`, for example `slay-relay-alice.key`; use it in your SSH client.

`config init` creates one default forward target in `slay-agent.toml`:

```toml
forward_targets = [
  { name = "ssh", port = 22, target = "127.0.0.1:22" }
]
```

Add more entries to `slay-agent.toml` when the agent should expose more internal addresses. Client-facing target hosts are derived as `agent_id-name`, for example `alice-home-linux-ssh:22`. The relay does not statically list target names; it accepts runtime registrations from an authenticated agent under that agent's `agent_id-` prefix.

Choose where the generated relay user key is written:

```bash
slay config init \
  --relay-addr relay.example.com:2222 \
  --relay-user alice \
  --relay-private-key-output ./alice-relay.key \
  --agent-id alice-home-linux
```

Overwrite existing generated files:

```bash
slay config init \
  --relay-addr relay.example.com:2222 \
  --relay-user alice \
  --relay-private-key-output ./alice-relay.key \
  --agent-id alice-home-linux \
  --force
```

Use `--force` to overwrite existing generated files.

Validate configs:

```bash
slay config validate relay --config slay-relay.toml
slay config validate agent --config slay-agent.toml
```

## Minimal Setup Flow

1. Run `config init` to generate matching relay and agent configs. Relay host, relay user, and agent keys are generated and embedded by `config init`.

2. Create matching relay and agent configs:

```bash
slay config init \
  --relay-addr relay.example.com:2222 \
  --relay-user alice \
  --agent-id alice-home-linux
```

3. Edit `slay-relay.toml`:

- Confirm `[relay].listen`.
- Protect `slay-relay.toml`; `[relay].host_key` contains the relay SSH host private key.
- Confirm `[users.<name>].authorized_keys`; use the generated relay user private key with your SSH client.
- Confirm `[agents.<agent_id>].agent_authorized_keys` contains the agent public key derived from `slay-agent.toml`.
- Keep each `[agents.<agent_id>]` table key unique.

4. Edit `slay-agent.toml`:

- Confirm `relay_addr`.
- Confirm `relay_known_hosts` contains the relay address and SSH host public key.
- Confirm `agent_id` matches the relay `[agents.<agent_id>]` entry.
- Protect `slay-agent.toml`; `agent_private_key` contains the agent SSH private key.
- Confirm `forward_targets` maps each local service `name` and public `port` to the `target` address behind the agent.

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

The agent connects to the relay over SSH, authenticates as `agent_id`, and registers reverse forwarding for each configured `forward_targets` entry as `agent_id-name:port`. User SSH clients still connect to the relay and request `direct-tcpip` to that derived target through `ProxyJump` or an equivalent jump-host feature.
