use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType, Issuer,
};
use std::fs;
use std::path::Path;

pub fn generate_certs(output_dir: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let ca_cert_path = Path::new(output_dir).join("ca.pem");
    let ca_key_path = Path::new(output_dir).join("ca-key.pem");

    let (ca_params, ca_key) = if ca_cert_path.exists() && ca_key_path.exists() {
        println!("Using existing CA certificate");
        // Load existing CA key and recreate minimal params
        let ca_key_pem = fs::read_to_string(&ca_key_path)?;
        let ca_key = KeyPair::from_pem(&ca_key_pem)?;
        
        // Recreate minimal CA params for signing (we only need this for the signing issuer)
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "SecureMsg Dev");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        
        (ca_params, ca_key)
    } else {
        // Generate new CA
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
        write_pem(output_dir, "ca-key.pem", &ca_key.serialize_pem())?;
        
        (ca_params, ca_key)
    };

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

    if name == "default" {
        let server_key = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_key, &Issuer::from_params(&ca_params, &ca_key))?;

        write_pem(output_dir, "server.pem", &server_cert.pem())?;
        write_pem(output_dir, "server-key.pem", &server_key.serialize_pem())?;
    } else {
        generate_client_cert(output_dir, name, &ca_params, &ca_key)?;
    }

    println!("Certificates written to {}/", output_dir);
    Ok(())
}

// generate client certificate signed by CA
pub fn generate_client_cert(
    output_dir: &str,
    client_name: &str,
    ca_params: &CertificateParams,
    ca_key: &KeyPair,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, client_name);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    let client_key = KeyPair::generate()?;
    let client_cert = params.signed_by(&client_key, &Issuer::from_params(&ca_params, &ca_key))?;

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
