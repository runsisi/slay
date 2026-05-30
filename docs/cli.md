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

Generate the relay-side hash for an agent token:

```bash
slay config hash-token 'at-least-32-random-characters-here'
```

To avoid putting the token in shell history, pass it through stdin:

```bash
printf '%s' 'at-least-32-random-characters-here' | slay config hash-token
```

## Minimal Setup Flow

1. Generate or choose a high-entropy agent token with at least 32 characters.
2. Generate its relay-side hash:

```bash
slay config hash-token 'at-least-32-random-characters-here'
```

3. Create templates:

```bash
slay config init relay --output slay-relay.toml
slay config init agent --output slay-agent.toml
```

4. Edit `slay-relay.toml`:

- Set the relay SSH host key path.
- Set agent TLS certificate/key paths.
- Replace relay user public keys.
- Replace `agent_token_hash` with the hash from step 2.
- Keep `machine_alias` unique.

5. Edit `slay-agent.toml`:

- Set `relay_addr`.
- Set `relay_name` and `relay_ca_cert` for TLS verification.
- Use the same `machine_id` configured in relay config.
- Put the raw agent token in `agent_token`.

6. Validate both configs:

```bash
slay config validate relay --config slay-relay.toml
slay config validate agent --config slay-agent.toml
```

7. Start both roles:

```bash
slay relay --config slay-relay.toml
slay agent --config slay-agent.toml
```
