# SSH Relay PRD

## 背景

用户的 PC 位于内网，手机位于另一个内网或 5G 移动网络。由于双方都可能没有公网入口，手机上的 SSH 客户端无法直接连接 PC。

目标是在公网 VPS 上运行一个 Rust 实现的 relay。内网 PC 主动以 SSH client 身份连接 relay 并注册 reverse forwarding；手机 SSH 客户端也连接 relay，由 relay 负责认证、授权、路由和转发，使手机能够访问指定 PC 上的 sshd。

## 产品定位

本项目是一个 SSH 专用的反向 relay，不是通用内网穿透平台。

核心原则：

- relay 负责公网入口、认证、授权、agent 路由和 SSH channel 桥接。
- agent 负责从内网主动连接 relay，并把 relay 请求转发到本机 sshd。MVP 使用单个 `slay` 二进制，通过 `slay agent` 子命令运行。
- 手机到 PC 的 SSH 登录仍然由手机 SSH 客户端和 PC sshd 端到端完成。
- relay 不保存 PC 登录私钥、PC 登录密码，也不代表用户登录 PC。

## 目标

- 支持手机从公网访问不同内网中的 PC。
- 支持多台 PC 同时连接同一个 relay。
- 支持不同 PC 使用不同的 agent SSH key。
- 支持不同 relay 用户访问不同 PC 的权限控制。
- 保持手机到 PC sshd 的 SSH 登录语义，不让 relay 代替用户登录 PC。
- 兼容支持 SSH Jump Host / ProxyJump 的普通 SSH 客户端。
- 优先支持 iPhone SSH 客户端以 SSH 模式连接；Mosh/UDP 模式不作为 MVP 范围。

## 非目标

- 不实现完整的 SSH shell 服务。
- 不在 relay 上保存 PC 登录私钥或 PC 登录密码。
- 不让 relay 解密、理解或代理内层 PC SSH 登录流程。
- 不在 MVP 中实现 NAT 打洞、P2P 直连或 UDP relay。
- 不依赖 PC 操作系统 hostname 作为机器唯一标识。
- 不在 MVP 中支持 HTTP、RDP、数据库等非 SSH 服务转发。

## 核心方案

采用 SSH Jump Host + SSH remote forwarding：

```text
手机 SSH 客户端
    |
    | 第 1 层 SSH：登录 relay，完成 relay 用户认证
    v
公网 VPS relay
    ^
    | agent SSH client 长连接，注册 remote forwarding
    |
内网机器 slay agent
    |
    | 本机 TCP 连接
    v
PC sshd: 127.0.0.1:22
```

用户侧通过 `ProxyJump` 让 SSH 客户端先登录 relay，再向 relay 发起 `direct-tcpip` 到派生出来的公开目标 `agent_id-name:port`。agent 侧以 `agent_id` 作为 SSH 用户名登录 relay，认证成功后为每个 `forward_targets` 条目请求 `tcpip-forward agent_id-name:port`。relay 收到用户请求时，按 agent 已注册的 `agent_id-name:port` 找到对应 agent 并打开 `forwarded-tcpip` channel，agent 再连接该条目配置的本机或内网 `target`。

## 最终设计决策

MVP 固定采用以下决策：

- relay 用户认证只支持 SSH 公钥认证，不支持密码登录。
- agent 到 relay 的认证也使用 SSH 公钥认证，不引入自定义 token。
- agent 到 relay 的链路使用 SSH 加密和 SSH host key 校验，不引入单独 TLS。
- 每台 PC 使用全局唯一、可读的 `agent_id` 作为 agent SSH 用户名；用户侧目标 host 使用 `agent_id-<name>`。
- 公开目标名使用中划线拼接 `agent_id` 和 target `name`，不使用冒号，避免和 `host:port`、IPv6、scp 语法混淆。
- relay 侧为每个 agent 配置 `agent_authorized_keys`。
- agent 侧配置内嵌 `agent_private_key` 和 `relay_known_hosts`。
- 手机 SSH 客户端使用 `agent_id-name` 作为 Jump Host 后面的目标 host。
- 每个 agent 可配置多个 `forward_targets`，分别映射到本机或内网的不同地址。
- relay 只支持 `direct-tcpip` 和 agent remote forwarding 所需能力，不提供可交互 shell。

## 认证模型

系统中存在三类身份：

- relay 用户：手机侧用户，例如 `alice`。
- agent：内网 PC 上运行的 agent，例如 `alice-home-linux`。
- PC SSH 用户：PC 操作系统上的 SSH 用户，例如 `pcuser`。

认证分三层：

```text
手机 -> relay：
  relay 用户认证。MVP 只支持 SSH publickey authentication。

slay agent -> relay：
  agent 以 agent_id 作为 SSH 用户名登录 relay，使用 agent SSH key 认证。

手机 -> PC sshd：
  标准 SSH 认证。relay 只转发字节流，不保存 PC 登录凭据。
```

relay 上只能保存公钥和 ACL 配置：

```text
手机：
  - relay 登录私钥
  - PC 登录私钥

relay/VPS：
  - relay 自己的 SSH host 私钥，内嵌在 relay 配置 `[relay].host_key`
  - relay 用户 authorized_keys
  - agent_authorized_keys
  - 用户到 agent 的 ACL

PC：
  - sshd host 私钥
  - PC 用户 authorized_keys
  - slay agent 私钥，内嵌在 agent 配置 `agent_private_key`
  - relay SSH known_hosts 条目
```

推荐给三层使用不同密钥：

```text
id_relay_user:  只允许用户登录 relay
id_slay_agent:  只允许 agent 注册 reverse forwarding
id_pc:          只允许用户登录 PC
```

如果某些手机 SSH 客户端不方便为 relay 和 PC 分别配置不同密钥，用户侧可以临时共用同一把 SSH key；agent key 仍建议独立。

## Agent ID

不能使用 PC 的真实 hostname 作为唯一标识，因为多台 PC 可能 hostname 相同。

每台 PC 配置一个给 agent 登录 relay 使用的可读 `agent_id`。relay 侧不再单独配置 `agent_id` 字段，`[agents.<agent_id>]` 的表键就是 agent id：

```toml
[agents.alice-home-linux]
agent_authorized_keys = [
  "ssh-ed25519 AAAA... alice-home-agent"
]
```

agent 自己的配置中保留同一个 `agent_id`，用于登录 relay。`forward_targets[].name` 是 agent 内部的局部服务名；用户 SSH client 请求的目标 host 是 `agent_id-name`，例如 `alice-home-linux-ssh`。relay 侧不重复配置 target 列表，只校验 agent key、agent id 前缀和用户到 agent 的 allowlist。

命名建议：

```text
alice-home-linux
alice-office-linux
bob-home-linux
```

`agent_id` 必须全局唯一，且不能和 relay 用户名冲突。推荐包含 owner 或 namespace 前缀，避免不同用户都创建 `home-linux` 这种冲突名称。

relay 维护在线 agent 表：

```text
alice-home-linux   -> agent SSH connection A
alice-office-linux -> agent SSH connection B
bob-home-linux     -> agent SSH connection C
```

手机 SSH 客户端里的目标 host 字段使用派生公开名，例如 `alice-home-linux-ssh` 或 `alice-home-linux-web`。relay 收到 jump host 的 `direct-tcpip` 请求后，将目标 `agent_id-name:port` 当作 agent 已注册的 runtime route 查找在线 agent，而不是做 DNS 解析。

## 用户连接体验

理想用户体验是一条连接命令或一个 SSH 客户端 profile：

```bash
ssh home-pc
```

OpenSSH 配置示例：

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

实际流程：

```text
1. slay agent 连接 relay.example.com:2222。
2. agent 校验 relay SSH host key。
3. agent 以 alice-home-linux 作为 SSH 用户名，用 agent 私钥认证。
4. agent 为每个 forward target 请求 tcpip-forward，例如 alice-home-linux-ssh:22。
5. 手机 SSH 客户端连接 relay.example.com:2222。
6. relay 验证 alice 的公钥。
7. 客户端通过 relay 请求连接 alice-home-linux-ssh:22。
8. relay 检查 alice 是否有权限访问 alice-home-linux。
9. relay 找到已在线的 alice-home-linux agent。
10. relay 向 agent 打开 forwarded-tcpip channel。
11. agent 按 alice-home-linux-ssh:22 对应的 target 连接本机或内网目标，例如 127.0.0.1:22。
12. relay 在用户 SSH channel 和 agent SSH channel 之间双向转发字节。
13. 手机 SSH 客户端与 PC sshd 完成标准 SSH 登录。
```

如果两层用户登录都使用公钥认证，用户通常不需要输入两次用户名密码。relay 层不支持密码登录，因此不会出现 relay 密码提示。PC 层是否提示密码取决于 PC sshd 的配置。

## iPhone 客户端要求

iPhone SSH 客户端必须支持：

- SSH 连接模式。
- SSH Jump Host / ProxyJump / Bastion host 等等价能力。
- relay 层和 PC 层的认证配置。

MVP 不要求支持 Mosh 模式。Mosh 通常需要 SSH 启动后再走 UDP，会让 relay 设计从 TCP SSH 转发扩展到 UDP relay，不作为第一阶段目标。

## Relay 行为

relay 作为标准 SSH server 暴露给用户 SSH 客户端，同时接收 agent SSH client 连接。

必须支持：

- SSH publickey authentication。
- 用户侧 `direct-tcpip` channel。
- agent 侧 `tcpip-forward` global request。
- relay 到 agent 的 `forwarded-tcpip` channel。
- 根据 agent 注册的 `agent_id-name:port` runtime route 解析所属 agent。
- 用户到 agent 的 ACL 校验。
- agent 注册和下线清理。
- 同一个 agent 上多个并发 SSH 会话。

必须拒绝：

- password authentication。
- shell session。
- exec command。
- scp/sftp 子系统。
- 未授权的端口转发。
- 未注册的目标服务转发。
- agent 注册不属于自身 `agent_id-` 前缀的 remote forward。

## PC Agent 行为

`slay agent` 在内网机器上运行，主动连接 relay。

职责：

- 校验 relay SSH host key。
- 使用 agent 私钥向 relay 认证。
- 为每个 `forward_targets` 条目注册 SSH remote forwarding。
- 接收 relay 打开的 `forwarded-tcpip` channel。
- 对每个请求连接该 `agent_id-name:port` 对应的本机或内网 `target`。
- 在 relay SSH channel 与本地 TCP stream 之间做双向 copy。
- 支持多个并发转发流。
- 网络断开后自动重连。

## 配置示例

relay 配置示例：

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

agent 配置示例：

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
  { name = "web", port = 8080, target = "127.0.0.1:8080" }
]
reconnect_secs = 5
```

## Rust 技术选型

建议的基础组件：

- `tokio`：异步运行时和 TCP IO。
- `russh`：实现 relay SSH server、agent SSH client、`direct-tcpip`、`tcpip-forward` 和 `forwarded-tcpip` channel。
- `serde` + `toml`：配置解析。
- `tracing`：结构化日志。

## MVP 范围

第一阶段实现：

- `slay` 二进制。
- `slay relay` 子命令。
- `slay agent` 子命令。
- `slay config init` 一次生成匹配的 relay/agent 配置；自动生成 relay 用户 key pair、agent private key 和 relay host key，并写入 relay 用户 authorized keys 和 agent authorized keys。
- `slay config validate` 校验 relay/agent 配置。
- relay 用户 SSH 公钥认证。
- agent SSH 公钥认证。
- `[agents.<agent_id>]` 配置加载和唯一性校验。
- agent 在线状态管理。
- `direct-tcpip` 到已注册 forward target 所属 agent 的路由。
- relay 到 agent 的 `forwarded-tcpip` channel。
- agent 到本机或内网 `target` 的 TCP 转发。
- 基于配置文件的 ACL。
- 基础日志和错误处理。

命令行的具体使用方式维护在 `docs/cli.md`；PRD 只记录产品需求和架构边界。

第一阶段暂不实现：

- Web 管理后台。
- 动态用户和 agent 注册。
- relay 密码登录。
- UDP/Mosh 支持。
- P2P 直连。
- relay 端 shell。
- relay 代替用户登录 PC。
- 一台 PC 暴露多个服务。

## 安全要求

- relay 不保存 PC 登录私钥或 PC 登录密码。
- relay 不支持密码登录，只允许 SSH 公钥认证。
- agent 不保存 relay 私钥，只保存 relay SSH known_hosts 条目用于校验。
- 每个 agent 使用独立 agent SSH key。
- relay 只保存 agent public key，不保存 agent private key。
- 每个 relay 用户配置可访问的 agent allowlist。
- agent 只能注册自身 `agent_id-` 前缀下的 `<name>:port`。
- `agent_id` 必须全局唯一，且不能和 relay 用户名冲突。
- 日志不能记录 SSH payload、私钥或用户密码。
- 需要对认证失败、未知 agent、ACL 拒绝和 agent 断开进行审计日志记录。

## 后续扩展

后续版本可以考虑：

- Web 管理后台。
- 动态创建用户、agent 和 ACL。
- 一个 agent 暴露多个服务。
- 临时授权链接或一次性访问能力。
- UDP relay 或 Mosh 专用支持。
