use anyhow::{Result, anyhow};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_argon2_token_hashes() {
        let hash = hash_token("01234567890123456789012345678901").unwrap();
        assert!(verify_token("01234567890123456789012345678901", &hash));
        assert!(!verify_token("wrong-token", &hash));
    }
}
