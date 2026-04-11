use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::pkcs8::DecodePrivateKey;
use x509_parser::prelude::*;

// Sign `x25519_key || mlkem_ek` with the client's ECDSA P-256 TLS private key.
// Returns a 64-byte fixed-size (r, s) signature.
pub fn sign_e2e_keys(
    key_pem: &str,
    x25519_key: &[u8; 32],
    mlkem_ek: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_pkcs8_pem(key_pem)?;
    let data = signed_data(x25519_key, mlkem_ek);
    let sig: Signature = signing_key.sign(&data);
    Ok(sig.to_bytes().to_vec())
}

// Verify a peer's E2E public key set
pub fn verify_peer_e2e_keys(
    ca_cert_der: &[u8],
    peer_cert_der: &[u8],
    expected_cn: &str,
    x25519_key: &[u8; 32],
    mlkem_ek: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    let (_, ca_cert) = parse_x509_certificate(ca_cert_der)
        .map_err(|e| format!("CA cert parse error: {e:?}"))?;
    let (_, peer_cert) = parse_x509_certificate(peer_cert_der)
        .map_err(|e| format!("peer cert parse error: {e:?}"))?;

    // Step 1: verify the peer cert was issued by trusted CA
    peer_cert
        .verify_signature(Some(&ca_cert.tbs_certificate.subject_pki))
        .map_err(|e| format!("peer cert CA verification failed: {e}"))?;

    // Step 2: verify the cert's CN matches client identity
    let cn = peer_cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .ok_or_else(|| "peer cert has no common name".to_string())?;
    if cn != expected_cn {
        return Err(format!(
            "peer cert CN '{cn}' does not match expected client ID '{expected_cn}'"
        ));
    }

    // Step 3: verify the E2E key signature
    let pk_bytes = peer_cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref()
        .to_vec();
    let verifying_key = VerifyingKey::from_sec1_bytes(&pk_bytes)
        .map_err(|e| format!("peer cert public key parse error: {e}"))?;

    let data = signed_data(x25519_key, mlkem_ek);
    let signature = Signature::try_from(sig)
        .map_err(|e| format!("invalid signature encoding: {e}"))?;
    verifying_key
        .verify(&data, &signature)
        .map_err(|e| format!("E2E key signature verification failed: {e}"))?;

    Ok(())
}

fn signed_data(x25519_key: &[u8; 32], mlkem_ek: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + mlkem_ek.len());
    data.extend_from_slice(x25519_key);
    data.extend_from_slice(mlkem_ek);
    data
}
