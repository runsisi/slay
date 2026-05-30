use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    install_crypto_provider();
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid agent TLS certificate/key pair")?;
    Ok(Arc::new(config))
}

pub fn client_config(ca_cert_path: Option<&Path>) -> Result<Arc<ClientConfig>> {
    install_crypto_provider();
    let mut roots = RootCertStore::empty();
    if let Some(path) = ca_cert_path {
        for cert in load_certs(path)? {
            roots.add(cert).context("failed to add CA certificate")?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn install_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("failed to open cert {}", path.display()))?,
    );
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .context("failed to parse PEM certificates")?;
    if certs.is_empty() {
        bail!("{} does not contain any certificates", path.display());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("failed to open key {}", path.display()))?,
    );
    rustls_pemfile::private_key(&mut reader)
        .context("failed to parse PEM private key")?
        .with_context(|| format!("{} does not contain a private key", path.display()))
}
