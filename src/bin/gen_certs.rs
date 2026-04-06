fn main() {
    if let Err(e) = crate::tls::certs::generate_test_certs("certs") {
        eprintln!("Failed to generate certificates: {}", e);
        std::process::exit(1);
    }
}