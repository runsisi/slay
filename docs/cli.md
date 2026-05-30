# Slay CLI

`slay` uses one binary with role-specific subcommands.

## Runtime Commands

Run the VPS relay:

```bash
slay relay --config slay-relay.toml
```

Run the machine agent on an internal machine:

```bash
slay agent --config slay-agent.toml
```

## Config Commands

Create matching relay and agent configs with a generated `machine_id`, `agent_token`, and `agent_token_hash`:

```bash
slay config init \
  --relay-output slay-relay.toml \
  --agent-output slay-agent.toml \
  --relay-addr relay.example.com:443 \
  --relay-name relay.example.com \
  --relay-user alice \
  --relay-public-key ~/.ssh/id_relay.pub \
  --tls-dir ./slay-tls
```

By default this uses `--relay-tls private-ca`, creates a private CA plus a relay server certificate in `--tls-dir`, and writes the matching TLS paths into both configs.

Set the machine alias and display name during paired generation:

```bash
slay config init \
  --relay-addr relay.example.com:443 \
  --relay-public-key ~/.ssh/id_relay.pub \
  --machine-alias alice-home-linux \
  --display-name "Alice Home Linux"
```

`--relay-addr` is required because it is written into the agent config and used for generated TLS certificates. `--relay-public-key` is optional; if omitted, replace the placeholder public key before validating or running the relay.

Select relay-link TLS mode:

```bash
# Default: generate a private CA and relay certificate.
slay config init --relay-addr relay.example.com:443 --relay-public-key ~/.ssh/id_relay.pub --relay-tls private-ca --tls-dir ./slay-tls

# Use externally managed TLS files, such as a public CA certificate.
slay config init --relay-addr relay.example.com:443 --relay-public-key ~/.ssh/id_relay.pub --relay-tls external

# Local development only.
slay config init --relay-addr 127.0.0.1:4443 --relay-public-key ~/.ssh/id_relay.pub --relay-tls insecure
```

`private-ca` creates:

```text
slay-tls/
  relay-ca.crt
  relay-ca.key
  relay.crt
  relay.key
```

Keep `relay-ca.key` and `relay.key` private. Do not copy `relay-ca.key` to agent machines.

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

Validate a relay config:

```bash
slay config validate relay --config slay-relay.toml
```

Validate an agent config:

```bash
slay config validate agent --config slay-agent.toml
```

Generate a new random agent token and its relay-side hash without writing config files:

```bash
slay config token
```

Hash an existing agent token without writing config files:

```bash
slay config hash-token 'at-least-32-random-characters-here'
```

## Minimal Setup Flow

1. Create matching relay and agent configs:

```bash
slay config init \
  --relay-output slay-relay.toml \
  --agent-output slay-agent.toml \
  --relay-addr relay.example.com:443 \
  --relay-name relay.example.com \
  --relay-user alice \
  --relay-public-key ~/.ssh/id_relay.pub \
  --relay-tls private-ca \
  --tls-dir ./slay-tls \
  --machine-alias alice-home-linux \
  --display-name "Alice Home Linux"
```

2. Edit `slay-relay.toml`:

- Set the relay SSH host key path.
- Keep or deploy the generated `relay_tls_cert` and `relay_tls_key` paths.
- Confirm the relay user public key.
- Keep `machine_alias` unique.

3. Edit `slay-agent.toml`:

- Confirm `relay_addr` and `relay_name`.
- Keep `relay_ca_cert` when using `--relay-tls private-ca`; omit it only when the relay certificate uses a public CA.
- Use the same `machine_id` configured in relay config.
- Keep the generated `agent_token`.

For local development only, generate plain relay links explicitly:

```bash
slay config init --relay-addr 127.0.0.1:4443 --relay-public-key ~/.ssh/id_relay.pub --relay-tls insecure
```

This writes:

```toml
# slay-relay.toml
[server]
allow_insecure_relay = true
```

```toml
# slay-agent.toml
allow_insecure_relay = true
```

4. Validate both configs:

```bash
slay config validate relay --config slay-relay.toml
slay config validate agent --config slay-agent.toml
```

5. Start both roles:

```bash
slay relay --config slay-relay.toml
slay agent --config slay-agent.toml
```

## Advanced Token Commands

Generate a token/hash pair without writing config files:

```bash
slay config token
```

Hash an existing token, for migration or scripted deployment:

```bash
slay config hash-token 'at-least-32-random-characters-here'
```

To avoid putting the token in shell history, pass it through stdin:

```bash
printf '%s' 'at-least-32-random-characters-here' | slay config hash-token
```
