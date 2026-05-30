# SSH Relay PRD

## 背景

用户的 PC 位于内网，手机位于另一个内网或 5G 移动网络。由于双方都可能没有公网入口，手机上的 SSH 客户端无法直接连接 PC。

目标是在公网 VPS 上运行一个 Rust 实现的 relay 程序。内网 PC 主动连接 relay，手机 SSH 客户端也连接 relay，由 relay 负责认证、路由和转发，使手机能够访问指定 PC 上的 sshd。

## 产品定位

本项目是一个 SSH 专用的反向 relay，不是通用内网穿透平台。

核心原则：

- relay 负责公网入口、认证、授权、机器路由和字节转发。
- machine agent 负责从内网主动连接 relay，并把 relay 请求转发到本机 sshd。MVP 中使用单个 `slay` 二进制，通过 `slay agent` 子命令运行。
- 手机到 PC 的 SSH 登录仍然由手机 SSH 客户端和 PC sshd 端到端完成。
- relay 不保存 PC 登录私钥、PC 登录密码，也不代表用户登录 PC。

## 目标

- 支持手机从公网访问不同内网中的 PC。
- 支持多台 PC 同时连接同一个 relay。
- 支持不同 PC 使用不同的机器身份和认证信息。
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

采用 SSH Jump Host 模式：

```text
手机 SSH 客户端
    |
    | 第 1 层 SSH：登录 relay，完成 relay 用户认证
    v
公网 VPS relay
    |
    | 已认证的 agent 长连接，多路复用转发流
    v
内网机器 slay agent
    |
    | 本机 TCP 连接
    v
PC sshd: 127.0.0.1:22
```

手机用户只执行一次连接操作，例如连接 `home-pc`。客户端内部会先登录 relay，然后通过 relay 打开到目标机器的转发通道，再在该通道内与 PC sshd 完成真正的 SSH 握手和登录。

## 最终设计决策

MVP 固定采用以下决策：

- relay 用户认证只支持 SSH 公钥认证，不支持密码登录。
- `slay agent` 到 relay 的认证使用每台机器独立的高熵 token。
- relay 只保存 agent token hash，不保存 token 明文。
- agent 到 relay 的公网长连接必须支持 TLS；本地开发可以临时关闭 TLS。
- 每台 PC 有不可变内部 `machine_id` 和可读 `machine_alias`。
- 手机 SSH 客户端使用 `machine_alias` 作为 Jump Host 目标 host。
- MVP 只支持转发到 PC 本机 sshd，即 `127.0.0.1:22`。
- relay 只支持 `direct-tcpip` 转发所需能力，不提供可交互 shell。

后续版本可以升级 agent 认证为私钥签名或 mTLS，也可以扩展一台 machine 暴露多个 service，但这些不进入 MVP。

## 认证模型

系统中存在三类身份：

- relay 用户：手机侧用户，例如 `alice`。
- machine：内网 PC 的 relay 内部机器身份，例如 `mch_01HX...`。
- PC SSH 用户：PC 操作系统上的 SSH 用户，例如 `pcuser`。

认证分三层：

```text
手机 -> relay：
  relay 用户认证。MVP 只支持 SSH publickey authentication。

slay agent -> relay：
  machine 认证。MVP 使用 machine_id + 高熵 token。

手机 -> PC sshd：
  标准 SSH 认证。relay 只转发字节流，不保存 PC 登录凭据。
```

relay 上只能保存公钥、token hash 和 ACL 配置，不保存 PC 登录私钥：

```text
手机：
  - relay 登录私钥
  - PC 登录私钥

relay/VPS：
  - relay 自己的 SSH host 私钥
  - relay 用户 public key
  - machine token hash
  - 用户到机器的 ACL

PC：
  - sshd host 私钥
  - PC 用户 authorized_keys
  - slay agent token 明文或本地安全存储中的 token
```

relay 用户和 PC SSH 用户属于不同安全边界。推荐给两层使用不同密钥：

```text
id_relay: 只允许登录 relay
id_pc:    只允许登录 PC
```

如果某些手机 SSH 客户端不方便为 relay 和 PC 分别配置不同密钥，MVP 允许用户临时共用同一把 SSH key，但配置模型仍按两层身份分离设计。

## Agent Token 认证

MVP 中，每台内网机器上的 `slay agent` 拥有独立 token：

```text
machine_id = "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW"
agent_token = "高熵随机字符串"
```

认证流程：

```text
1. `slay agent` 连接 relay 的 agent listener。
2. `slay agent` 发送 machine_id 和 agent_token。
3. relay 查找 machine_id。
4. relay 使用保存的 token hash 验证 agent_token。
5. 验证成功后，该连接注册为此 machine 的在线 agent。
```

安全要求：

- token 必须由高质量随机数生成。
- 每台 machine 使用独立 token。
- relay 配置中只保存 token hash。
- 日志不能输出 token 明文。
- token 泄漏后必须可以单独轮换，不影响其他 machine。

## 机器 ID 和别名

不能使用 PC 的真实 hostname 作为唯一标识，因为多台 PC 可能 hostname 相同。

每台 PC 在 relay 内部使用不可变 `machine_id`，同时配置一个给 SSH 客户端使用的可读 `machine_alias`：

```toml
machine_id = "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW"
machine_alias = "alice-home-linux"
display_name = "Alice Home Linux"
target = "127.0.0.1:22"
```

命名建议：

```text
alice-home-linux
alice-office-linux
bob-home-linux
```

`machine_alias` 必须全局唯一。推荐包含 owner 或 namespace 前缀，避免不同用户都创建 `home-linux` 这种冲突名称。

relay 维护在线机器表：

```text
alice-home-linux   -> mch_01HX... -> agent connection A
alice-office-linux -> mch_01HY... -> agent connection B
bob-home-linux     -> mch_01HZ... -> agent connection C
```

手机 SSH 客户端里的目标 host 字段使用 `machine_alias`，例如 `alice-home-linux`。relay 收到 jump host 的 `direct-tcpip` 请求后，将目标 host 当作 `machine_alias` 查找在线 agent，而不是做 DNS 解析。

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
  IdentityFile ~/.ssh/id_relay

Host home-pc
  HostName alice-home-linux
  Port 22
  User pcuser
  IdentityFile ~/.ssh/id_pc
  ProxyJump relay
```

实际流程：

```text
1. 手机 SSH 客户端连接 relay.example.com:2222。
2. relay 验证 alice 的公钥。
3. 客户端通过 relay 请求连接 alice-home-linux:22。
4. relay 检查 alice 是否有权限访问 alice-home-linux。
5. relay 找到已在线的 alice-home-linux agent。
6. relay 要求 agent 打开到 127.0.0.1:22 的本机连接。
7. relay 在手机 SSH channel 和 agent stream 之间双向转发字节。
8. 手机 SSH 客户端与 PC sshd 完成标准 SSH 登录。
```

如果两层都使用公钥认证，用户通常不需要输入两次用户名密码。relay 层不支持密码登录，因此不会出现 relay 密码提示。PC 层是否提示密码取决于 PC sshd 的配置。

## iPhone 客户端要求

iPhone SSH 客户端必须支持：

- SSH 连接模式。
- SSH Jump Host / ProxyJump / Bastion host 等等价能力。
- relay 层和 PC 层的认证配置。

MVP 不要求支持 Mosh 模式。Mosh 通常需要 SSH 启动后再走 UDP，会让 relay 设计从 TCP SSH 转发扩展到 UDP relay，不作为第一阶段目标。

## Relay 行为

relay 作为标准 SSH server 暴露给手机 SSH 客户端。

必须支持：

- SSH publickey authentication。
- `direct-tcpip` channel。
- 根据 `direct-tcpip` 的目标 host 字段解析 `machine_alias`。
- 用户到机器的 ACL 校验。
- machine agent 注册、心跳和下线清理。
- 同一台 machine 上多个并发 SSH 会话。

必须拒绝：

- password authentication。
- shell session。
- exec command。
- scp/sftp 子系统。
- 未授权的端口转发。
- 非 `127.0.0.1:22` 的目标服务转发。

## PC Agent 行为

`slay agent` 在内网机器上运行，主动连接 relay。

职责：

- 使用 `machine_id` 和 `agent_token` 向 relay 注册。
- 与 relay 保持长连接和心跳。
- 接收 relay 的 `open_stream` 请求。
- 对每个请求连接本机目标 `127.0.0.1:22`。
- 在 relay stream 与本地 TCP stream 之间做双向 copy。
- 支持多个并发转发流。
- 网络断开后自动重连。

## 配置示例

relay 配置示例：

```toml
[server]
ssh_listen = "0.0.0.0:2222"
agent_listen = "0.0.0.0:443"
ssh_host_key = "/etc/slay/relay_host_ed25519"
agent_tls_cert = "/etc/slay/agent_relay.crt"
agent_tls_key = "/etc/slay/agent_relay.key"

[users.alice]
public_keys = [
  "ssh-ed25519 AAAA..."
]
allowed_machines = [
  "alice-home-linux",
  "alice-office-linux"
]

[machines.alice_home]
machine_id = "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW"
machine_alias = "alice-home-linux"
display_name = "Alice Home Linux"
agent_token_hash = "argon2id:..."
target = "127.0.0.1:22"

[machines.alice_office]
machine_id = "mch_01HY3GEXXQ0G3MJ4XK2PG8R7AA"
machine_alias = "alice-office-linux"
display_name = "Alice Office Linux"
agent_token_hash = "argon2id:..."
target = "127.0.0.1:22"
```

agent 配置示例：

```toml
relay_addr = "relay.example.com:443"
relay_name = "relay.example.com"
relay_ca_cert = "/etc/slay/agent_relay_ca.crt"
machine_id = "mch_01HX9V4V7P6R4M8YJ7A9S0K2QW"
agent_token = "高熵随机字符串"
target = "127.0.0.1:22"
```

## Rust 技术选型

建议的基础组件：

- `tokio`：异步运行时和 TCP IO。
- `russh`：实现 relay 侧 SSH server 和 `direct-tcpip` channel。
- `rustls`：agent 到 relay 的 TLS。
- `yamux`：在 agent 长连接上承载多个并发 stream。
- `serde` + `toml`：配置解析。
- `tracing`：结构化日志。
- `argon2` 或同等级密码哈希库：保存 agent token hash。

## MVP 范围

第一阶段实现：

- `slay` 二进制。
- `slay relay` 子命令。
- `slay agent` 子命令。
- `slay config init` 生成 relay/agent 配置模板。
- `slay config validate` 校验 relay/agent 配置。
- `slay config hash-token` 生成 relay 侧保存的 agent token hash。
- relay 用户 SSH 公钥认证。
- `slay agent` token 认证。
- `machine_id` / `machine_alias` 配置加载和唯一性校验。
- machine 在线状态管理。
- `direct-tcpip` 到 machine agent 的路由。
- agent 到本机 `127.0.0.1:22` 的 TCP 转发。
- 基于配置文件的 ACL。
- 基础日志和错误处理。

命令行的具体使用方式维护在 `docs/cli.md`；PRD 只记录产品需求和架构边界。

第一阶段暂不实现：

- Web 管理后台。
- 动态用户和机器注册。
- relay 密码登录。
- agent 私钥签名认证。
- agent mTLS client certificate。
- UDP/Mosh 支持。
- P2P 直连。
- relay 端 shell。
- relay 代替用户登录 PC。
- 一台 PC 暴露多个服务。

## 安全要求

- relay 不保存 PC 登录私钥或 PC 登录密码。
- relay 不支持密码登录，只允许 SSH 公钥认证。
- 公网部署时 agent 到 relay 的长连接必须启用 TLS。
- 每台 machine 使用独立 agent token。
- relay 只保存 agent token hash，不保存 token 明文。
- 每个 relay 用户配置可访问的 machine allowlist。
- machine agent 只能注册配置中允许的 `machine_id`。
- `machine_alias` 必须全局唯一。
- 日志不能记录 SSH payload、私钥、token 明文或用户密码。
- 需要对认证失败、未知 machine、ACL 拒绝和 agent 断开进行审计日志记录。

## 后续扩展

后续版本可以考虑：

- agent 使用私钥签名挑战认证。
- agent 使用 mTLS client certificate 认证。
- Web 管理后台。
- 动态创建用户、machine 和 ACL。
- 一台 machine 暴露多个服务。
- 临时授权链接或一次性访问 token。
- UDP relay 或 Mosh 专用支持。
