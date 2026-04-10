use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::crypto::aws_lc_rs as provider;

// build crypto provider for mTLS that uses hybrid combined Post-qunatum & classical crypto
// order of kx groups ensures that if the combined kyber-kem + ecc fails we fall back to ecc25519, then to p256 gracefully
#[must_use]
pub fn build_crypto_provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: vec![
            provider::kx_group::X25519MLKEM768,
            provider::kx_group::X25519,
            provider::kx_group::SECP256R1,
        ],
        ..provider::default_provider()
    }
}