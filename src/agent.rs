use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use russh::Channel;
use russh::client;
use russh::client::Msg;
use russh::keys::key::PrivateKeyWithHashAlg;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::{AgentConfig, fingerprint, forward_public_name, parse_private_key};

pub async fn run_agent(config: AgentConfig) -> Result<()> {
    loop {
        match connect_once(config.clone()).await {
            Ok(()) => warn!("agent SSH connection closed"),
            Err(err) => warn!(error = %err, "agent SSH connection failed"),
        }
        tokio::time::sleep(Duration::from_secs(config.reconnect_secs)).await;
    }
}

async fn connect_once(config: AgentConfig) -> Result<()> {
    let expected_relay_known_host_fingerprints = config.relay_known_host_fingerprints()?;
    let agent_key =
        parse_private_key(&config.agent_private_key).context("invalid agent_private_key")?;
    let client_config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        nodelay: true,
        ..Default::default()
    });
    let handler = AgentSshClient {
        expected_relay_known_host_fingerprints,
        agent_id: config.agent_id.clone(),
        forward_targets: config
            .forward_targets
            .iter()
            .map(|target| {
                (
                    (
                        forward_public_name(&config.agent_id, &target.name),
                        target.port,
                    ),
                    target.target.clone(),
                )
            })
            .collect(),
    };

    let mut session = client::connect(client_config, config.relay_addr.as_str(), handler)
        .await
        .context("failed to connect relay SSH")?;
    let hash_alg = session.best_supported_rsa_hash().await?.flatten();
    let auth = session
        .authenticate_publickey(
            config.agent_id.clone(),
            PrivateKeyWithHashAlg::new(Arc::new(agent_key), hash_alg),
        )
        .await
        .context("agent SSH public key authentication failed")?;
    if !auth.success() {
        bail!("relay rejected agent SSH public key authentication");
    }

    for target in &config.forward_targets {
        let public_name = forward_public_name(&config.agent_id, &target.name);
        session
            .tcpip_forward(public_name.clone(), target.port)
            .await
            .with_context(|| {
                format!(
                    "relay rejected agent reverse forwarding request for {}:{}",
                    public_name, target.port
                )
            })?;
        info!(
            agent_id = %config.agent_id,
            public_name = %public_name,
            forward_name = %target.name,
            forward_port = target.port,
            target = %target.target,
            "agent registered SSH reverse forwarding"
        );
    }

    session.await.context("agent SSH session ended")
}

struct AgentSshClient {
    expected_relay_known_host_fingerprints: HashSet<String>,
    agent_id: String,
    forward_targets: HashMap<(String, u32), String>,
}

impl client::Handler for AgentSshClient {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .expected_relay_known_host_fingerprints
            .contains(&fingerprint(server_public_key)))
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let Some(target) = self
            .forward_targets
            .get(&(connected_address.to_string(), connected_port))
        else {
            bail!(
                "relay opened unexpected forwarded channel to {connected_address}:{connected_port}"
            );
        };

        let target = target.clone();
        let agent_id = self.agent_id.clone();
        let public_name = connected_address.to_string();
        let forward_port = connected_port;
        let originator_address = originator_address.to_string();
        tokio::spawn(async move {
            if let Err(err) = forward_channel_to_target(channel, &target).await {
                debug!(
                    agent_id,
                    public_name,
                    forward_port,
                    originator_address,
                    originator_port,
                    error = %err,
                    "forwarded SSH channel ended"
                );
            }
        });
        Ok(())
    }
}

async fn forward_channel_to_target(channel: Channel<Msg>, target: &str) -> Result<()> {
    let mut target_stream = TcpStream::connect(target)
        .await
        .with_context(|| format!("failed to connect local target {target}"))?;
    let mut ssh_stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut ssh_stream, &mut target_stream)
        .await
        .context("agent forwarded channel copy failed")?;
    Ok(())
}
