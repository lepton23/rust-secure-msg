use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::fs;
use std::path::Path;

// `cargo run --bin gen-certs`.
pub fn generate_test_certs(output_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    // === Root CA ===
    // The CA is the trust anchor. Its cert goes into both the server's and
    // client's root stores. The `IsCa::Ca(BasicConstraints::Unconstrained)`
    // flag is critical — without it, Rustls's WebPKI verifier will reject
    // any certs it signs, because X.509 path validation requires the CA
    // basic constraint on issuer certificates.
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "SecureMsg Dev");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    write_pem(output_dir, "ca.pem", &ca_cert.pem())?;
    // The CA private key stays here for signing; in production, guard it carefully
    // or use a hardware security module.
    write_pem(output_dir, "ca-key.pem", &ca_key.serialize_pem())?;

    // === Server Certificate ===
    // The Subject Alternative Name (SAN) is what Rustls actually checks during
    // hostname verification — the CN is legacy. We add "localhost" so the
    // client's ServerName::try_from("localhost") matches during development.
    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server_params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    let server_key = KeyPair::generate()?;
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    write_pem(output_dir, "server.pem", &server_cert.pem())?;
    write_pem(output_dir, "server-key.pem", &server_key.serialize_pem())?;

    // === Client Certificate ===
    // The CN here becomes the client_id extracted in extract_client_id().
    // Each client in your system would get a unique CN in their cert —
    // "alice", "bob", etc. This ties identity to PKI.
    generate_client_cert(output_dir, "alice", &ca_cert, &ca_key)?;

    println!("Test certificates written to {}/", output_dir);
    Ok(())
}

/// Generate a client certificate signed by the CA.
/// Call this for each test user you want.
pub fn generate_client_cert(
    output_dir: &str,
    client_name: &str,
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, client_name);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    let client_key = KeyPair::generate()?;
    let client_cert = params.signed_by(&client_key, ca_cert, ca_key)?;

    let prefix = format!("client-{}", client_name);
    write_pem(output_dir, &format!("{}.pem", prefix), &client_cert.pem())?;
    write_pem(
        output_dir,
        &format!("{}-key.pem", prefix),
        &client_key.serialize_pem(),
    )?;

    Ok(())
}

fn write_pem(dir: &str, filename: &str, content: &str) -> Result<(), std::io::Error> {
    let path = Path::new(dir).join(filename);
    fs::write(&path, content)?;
    println!("  wrote {}", path.display());
    Ok(())
}
