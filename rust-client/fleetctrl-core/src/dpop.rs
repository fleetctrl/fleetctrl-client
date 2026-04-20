use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    SecretKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub d: String,
    pub kid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

pub fn generate_private_jwk() -> Result<StoredJwk> {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = point.x().ok_or_else(|| anyhow!("missing x coordinate"))?;
    let y = point.y().ok_or_else(|| anyhow!("missing y coordinate"))?;
    let x = URL_SAFE_NO_PAD.encode(x);
    let y = URL_SAFE_NO_PAD.encode(y);
    let d = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());
    let kid = compute_jkt(&x, &y)?;

    Ok(StoredJwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x,
        y,
        d,
        kid,
    })
}

pub fn public_jwk(stored: &StoredJwk) -> PublicJwk {
    PublicJwk {
        kty: stored.kty.clone(),
        crv: stored.crv.clone(),
        x: stored.x.clone(),
        y: stored.y.clone(),
        kid: Some(stored.kid.clone()),
    }
}

pub fn compute_jkt(x: &str, y: &str) -> Result<String> {
    let thumbprint = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let digest = Sha256::digest(thumbprint.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

pub fn create_dpop(
    method: &str,
    url: &str,
    access_token: Option<&str>,
    issued_at_unix: i64,
    key: &StoredJwk,
) -> Result<(String, String)> {
    let jti = Uuid::new_v4().to_string();
    let mut header = BTreeMap::new();
    header.insert("alg", serde_json::Value::String("ES256".to_string()));
    header.insert("typ", serde_json::Value::String("dpop+jwt".to_string()));
    header.insert("jwk", serde_json::to_value(public_jwk(key))?);

    let mut claims = BTreeMap::new();
    claims.insert("htm", serde_json::Value::String(method.to_ascii_uppercase()));
    claims.insert("htu", serde_json::Value::String(url.to_string()));
    claims.insert("iat", serde_json::Value::Number(issued_at_unix.into()));
    claims.insert("jti", serde_json::Value::String(jti.clone()));
    if let Some(token) = access_token.filter(|value| !value.is_empty()) {
        let digest = Sha256::digest(token.as_bytes());
        claims.insert("ath", serde_json::Value::String(URL_SAFE_NO_PAD.encode(digest)));
    }

    let header_json = serde_json::to_vec(&header)?;
    let claims_json = serde_json::to_vec(&claims)?;
    let encoded_header = URL_SAFE_NO_PAD.encode(header_json);
    let encoded_claims = URL_SAFE_NO_PAD.encode(claims_json);
    let signing_input = format!("{encoded_header}.{encoded_claims}");

    let signing_key = signing_key_from_stored(key)?;
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok((format!("{signing_input}.{encoded_signature}"), jti))
}

fn signing_key_from_stored(key: &StoredJwk) -> Result<SigningKey> {
    let bytes = URL_SAFE_NO_PAD.decode(&key.d)?;
    let secret = SecretKey::from_slice(&bytes)?;
    Ok(SigningKey::from(secret))
}

#[cfg(test)]
mod tests {
    use super::{create_dpop, generate_private_jwk};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::Value;

    #[test]
    fn dpop_contains_expected_shape() {
        let key = generate_private_jwk().unwrap();
        let (token, _) = create_dpop("post", "https://fleet.example.com/token/recover", None, 1_700_000_000, &key).unwrap();
        let mut parts = token.split('.');
        let header = parts.next().unwrap();
        let claims = parts.next().unwrap();
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).unwrap()).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["jwk"]["crv"], "P-256");
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://fleet.example.com/token/recover");
        assert!(claims["jti"].as_str().is_some());
    }
}
