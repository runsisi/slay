use anyhow::{Result, anyhow};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::Engine;
use rand_core::RngCore;

pub const GENERATED_TOKEN_BYTES: usize = 32;
pub const GENERATED_MACHINE_ID_BYTES: usize = 16;

pub fn generate_token() -> String {
    let mut bytes = [0_u8; GENERATED_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn generate_machine_id() -> String {
    let mut bytes = [0_u8; GENERATED_MACHINE_ID_BYTES];
    OsRng.fill_bytes(&mut bytes);
    format!(
        "mch_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

pub fn hash_token(token: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map_err(|err| anyhow!("failed to hash token: {err}"))?
        .to_string())
}

pub fn verify_token(token: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn validate_token_hash(hash: &str) -> Result<()> {
    let parsed =
        PasswordHash::new(hash).map_err(|err| anyhow!("invalid agent_token_hash: {err}"))?;
    if parsed.algorithm.as_str() != "argon2id" {
        return Err(anyhow!("invalid agent_token_hash: expected argon2id"));
    }
    if parsed.salt.is_none() || parsed.hash.is_none() {
        return Err(anyhow!(
            "invalid agent_token_hash: expected complete PHC string"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_argon2_token_hashes() {
        let hash = hash_token("01234567890123456789012345678901").unwrap();
        assert!(validate_token_hash(&hash).is_ok());
        assert!(verify_token("01234567890123456789012345678901", &hash));
        assert!(!verify_token("wrong-token", &hash));
    }

    #[test]
    fn rejects_invalid_token_hashes() {
        assert!(validate_token_hash("not-a-phc-hash").is_err());
        assert!(validate_token_hash("$scrypt$ln=17,r=8,p=1$salt$hash").is_err());
        assert!(validate_token_hash("$argon2id$v=19$m=19456,t=2,p=1$salt").is_err());
    }

    #[test]
    fn generates_url_safe_tokens() {
        let token = generate_token();
        assert!(token.len() >= 32);
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        );
        assert!(hash_token(&token).is_ok());
    }

    #[test]
    fn generates_machine_ids() {
        let machine_id = generate_machine_id();
        assert!(machine_id.starts_with("mch_"));
        assert!(
            machine_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        );
    }
}
