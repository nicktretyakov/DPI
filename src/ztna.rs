use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZtnaClaims {
    pub sub: String,
    pub email: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub device_posture_healthy: bool,
}

pub struct ZtnaValidator {
    secret: String,
}

impl ZtnaValidator {
    pub fn new(secret: &str) -> Self {
        Self {
            secret: secret.to_string(),
        }
    }

    pub fn validate_access(&self, token: &str, required_role: &str) -> Result<ZtnaClaims, String> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        let token_data = decode::<ZtnaClaims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )
        .map_err(|e| format!("JWT validation error: {e}"))?;

        if !token_data.claims.device_posture_healthy {
            return Err("Access denied: Device posture check failed".into());
        }

        if !token_data.claims.roles.contains(&required_role.to_string()) {
            return Err(format!("Access denied: Missing role '{required_role}'"));
        }

        Ok(token_data.claims)
    }
}
