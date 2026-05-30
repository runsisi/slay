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
slay config init pair \
  --relay-output slay-relay.toml \
  --agent-output slay-agent.toml \
  --relay-user alice \
  --relay-public-key ~/.ssh/id_relay.pub
```

Set the machine alias and display name during paired generation:

```bash
slay config init pair \
  --machine-alias alice-home-linux \
  --display-name "Alice Home Linux"
```

If `--relay-public-key` is omitted, the relay config contains a placeholder public key and will not pass `slay config validate relay` until that key is replaced.

Create a relay config template:

```bash
slay config init relay --output slay-relay.toml
```

Create an agent config template:

```bash
slay config init agent --output slay-agent.toml
```

Overwrite an existing template:

```bash
slay config init relay --output slay-relay.toml --force
```

Print a template to stdout:

```bash
slay config init relay --output -
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
slay config init pair \
  --relay-output slay-relay.toml \
  --agent-output slay-agent.toml \
  --relay-user alice \
  --relay-public-key ~/.ssh/id_relay.pub \
  --machine-alias alice-home-linux \
  --display-name "Alice Home Linux"
```

2. Edit `slay-relay.toml`:

- Set the relay SSH host key path.
- Set agent TLS certificate/key paths.
- If `--relay-public-key` was not used, replace relay user public keys.
- Keep `machine_alias` unique.

3. Edit `slay-agent.toml`:

- Set `relay_addr`.
- Set `relay_name`; set `relay_ca_cert` when using a private CA or self-signed relay certificate.
- Use the same `machine_id` configured in relay config.
- Keep the generated `agent_token`.

For local development only, plain agent links can be enabled explicitly:

```toml
# slay-relay.toml
[server]
allow_insecure_agent_link = true
```

```toml
# slay-agent.toml
allow_insecure_relay_link = true
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
