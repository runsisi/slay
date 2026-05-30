# Slay

`slay` 是一个 SSH 专用的反向 relay，用于通过公网 relay 访问内网机器。

公网 relay 接收 SSH 客户端和已认证 agent。内网机器运行 `slay agent`，主动以 SSH client 身份连接 relay，注册 remote forwarding target，并把 relay 打开的连接转发到本机或内网 TCP 地址。

`slay` 不是通用内网穿透平台，不实现 NAT 打洞、P2P 直连、UDP relay、Mosh relay、relay 端 shell 或 relay 代替用户登录 PC。

## 角色

- relay user：连接公网 relay 的 SSH 用户，例如 `alice`。
- agent：内网机器身份，例如 `alice-home-linux`。
- PC SSH user：目标机器操作系统里的 SSH 用户，例如 `pcuser`。

relay 只认证 relay user 和 agent。最终 PC SSH 登录仍然发生在 SSH 客户端和目标 sshd 之间。

## 路由命名

agent 为每个 `forward_targets` 条目注册一个 SSH remote forward。

公开 target 名由以下格式派生：

```text
agent_id-name:port
```

示例：

```text
agent_id = "alice-home-linux"
name = "ssh"
port = 22
public target = "alice-home-linux-ssh:22"
```

分隔符使用 `-`，不使用 `:`，避免和 `host:port`、IPv6、scp 风格 SSH 语法混淆。

relay 不静态配置 target 名。relay 根据已认证 agent 的 `tcpip-forward` 注册维护 runtime route。agent 只能注册自身 `agent_id-` 前缀下的公开名。

同一个 agent 内，`name` 可以重复，只要 `name + port` 唯一：

```toml
forward_targets = [
  { name = "web", port = 80, target = "127.0.0.1:8080" },
  { name = "web", port = 443, target = "127.0.0.1:8443" }
]
```

客户端分别连接 `alice-home-linux-web:80` 和 `alice-home-linux-web:443`。

## 认证

relay user 只支持 SSH 公钥认证。

agent 只支持 SSH 公钥认证。agent 登录 relay 时，SSH 用户名就是 `agent_id`。

agent 使用 `relay_known_hosts` 校验 relay SSH host key。

relay 保存：

- `[relay].host_key`
- relay user `authorized_keys`
- agent `agent_authorized_keys`
- relay user 到 agent 的 allowlist

relay 不保存 PC SSH 私钥、PC SSH 密码或 agent 私钥。

agent 保存：

- `agent_private_key`
- `relay_known_hosts`
- 本机 `forward_targets`

## Relay 配置

```toml
[relay]
listen = "0.0.0.0:2222"
host_key = '''
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
'''

[users.alice]
authorized_keys = [
  "ssh-ed25519 AAAA... alice-laptop"
]
allowed_agents = [
  "alice-home-linux",
  "alice-office-linux"
]

[agents.alice-home-linux]
agent_authorized_keys = [
  "ssh-ed25519 BBBB... alice-home-agent"
]

[agents.alice-office-linux]
agent_authorized_keys = [
  "ssh-ed25519 CCCC... alice-office-agent"
]
```

`[agents.<agent_id>]` 的表键就是 agent id。`agent_id` 必须全局唯一，且不能和 relay user 名冲突。

## Agent 配置

```toml
relay_addr = "relay.example.com:2222"
relay_known_hosts = [
  "[relay.example.com]:2222 ssh-ed25519 DDDD... relay-host"
]
agent_id = "alice-home-linux"
agent_private_key = '''
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
'''
forward_targets = [
  { name = "ssh", port = 22, target = "127.0.0.1:22" },
  { name = "web", port = 80, target = "127.0.0.1:8080" },
  { name = "web", port = 443, target = "127.0.0.1:8443" }
]
reconnect_secs = 5
```

`forward_targets[].name` 不能为空，只能包含 ASCII 字母、数字、`_` 和 `-`。

`forward_targets[].port` 必须在 1 到 65535 之间。

`forward_targets[].target` 是 agent 机器可访问的 TCP `host:port` 或 `[ipv6]:port` 地址。

同一个 agent 配置内，`name + port` 必须唯一。

## CLI

运行 relay 和 agent：

```bash
slay relay --config slay-relay.toml
slay agent --config slay-agent.toml
```

生成匹配配置：

```bash
slay config init \
  --relay-addr relay.example.com:2222 \
  --relay-user alice \
  --relay-private-key-output ./slay-relay-alice.key \
  --agent-id alice-home-linux
```

`config init` 写入：

- `slay-relay.toml`
- `slay-agent.toml`
- relay user private key，默认 `slay-relay-<relay_user>.key`

生成的 relay 配置包含：

- `[relay].listen`，端口来自 `--relay-addr`
- `[relay].host_key`
- `[users.<relay_user>].authorized_keys`
- `[users.<relay_user>].allowed_agents`
- `[agents.<agent_id>].agent_authorized_keys`

生成的 agent 配置包含：

- `relay_addr`
- `relay_known_hosts`
- `agent_id`
- `agent_private_key`
- 默认 `forward_targets`
- `reconnect_secs`

默认 agent target：

```toml
forward_targets = [
  { name = "ssh", port = 22, target = "127.0.0.1:22" }
]
```

使用 `--force` 覆盖已存在的生成文件：

```bash
slay config init \
  --relay-addr relay.example.com:2222 \
  --relay-user alice \
  --relay-private-key-output ./slay-relay-alice.key \
  --agent-id alice-home-linux \
  --force
```

校验配置：

```bash
slay config validate relay --config slay-relay.toml
slay config validate agent --config slay-agent.toml
```

## 客户端配置

OpenSSH 示例：

```sshconfig
Host relay
  HostName relay.example.com
  Port 2222
  User alice
  IdentityFile ~/.ssh/id_relay_user

Host home-pc
  HostName alice-home-linux-ssh
  Port 22
  User pcuser
  IdentityFile ~/.ssh/id_pc
  ProxyJump relay
```

iPhone 或其他移动 SSH 客户端需要支持 SSH Jump Host、ProxyJump 或 Bastion host。Mosh 模式不在支持范围内。

## Relay 行为

relay 接受：

- relay user SSH 公钥认证
- agent SSH 公钥认证
- 用户侧 `direct-tcpip` channel
- agent 侧 `tcpip-forward` global request
- relay 到 agent 的 `forwarded-tcpip` channel

relay 拒绝：

- 密码认证
- shell/session channel
- exec command
- scp/sftp subsystem
- 未注册 target 转发
- agent 注册不属于自身 `agent_id-` 前缀的 forward

relay user 访问权限由 `[users.<name>].allowed_agents` 控制。

## Agent 行为

agent 行为：

- 连接 `relay_addr`
- 校验 `relay_known_hosts`
- 使用 `agent_private_key` 以 `agent_id` 身份认证
- 将每个 `forward_targets` 条目注册为 `agent_id-name:port`
- 接收 relay 打开的 `forwarded-tcpip` channel
- 将 channel 连接到对应本机或内网 `target`
- 断线后按 `reconnect_secs` 重连

## 安全要求

- relay 和 agent 认证使用 SSH 公钥。
- relay user 不支持密码认证。
- relay user 只能访问 allowlist 中的 agent。
- agent 只能注册自身 `agent_id-` 前缀下的 forward。
- relay 日志不能记录 SSH payload、私钥或密码。
- 包含 `host_key` 或 `agent_private_key` 的配置文件必须按 secret 处理。
- `relay_known_hosts` 必须匹配 `relay_addr` 和 relay SSH host key。
