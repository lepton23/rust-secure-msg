use p2_message::crypto::certs::*;
use p2_message::processes::{client, server};
use user_input::get_input;

#[tokio::main]
async fn main() {
    let prompt = "Start server, or start client? (s/c):";
    let choice = get_input(prompt);

    let result = match choice.as_str() {
        "s" => {
            let machine_name = machine_hostname();
            println!("Using machine name '{machine_name}' as server cert SAN");
            let _ = generate_certs("certs", "default", &[machine_name]);
            let port_str = get_input("Enter port to listen on (e.g. 8080):");
            let port: u16 = port_str.parse().unwrap_or(8080);
            server::run("certs/ca.pem", "certs/server.pem", "certs/server-key.pem", port).await
        }
        "c" => {
            let name = get_input("Enter your client name (e.g. Alice/Bob):");

            // Only generate certs if CA doesn't exist
            if !std::path::Path::new("certs/ca.pem").exists() {
                let _ = generate_certs("certs", "default", &[]);
            }

            // Generate client if it doesn't exist
            let cert_path = format!("certs/client-{name}.pem");
            if !std::path::Path::new(&cert_path).exists() {
                let _ = generate_certs("certs", &name, &[]);
            }
            let key_path = format!("certs/client-{name}-key.pem");
            let server_hostname = get_input("Enter server hostname (e.g. pc2-111-l / lyrane / palain):");
            let port_str = get_input("Enter server port (e.g. 8080):");
            let port: u16 = port_str.parse().unwrap_or(8080);
            let server_addr = format!("{server_hostname}:{port}");
            client::run(
                "certs/ca.pem",
                &cert_path,
                &key_path,
                &server_hostname,
                &server_addr,
                &name,
            )
            .await
        }
        _ => {
            println!("Invalid choice");
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Fatal error: {e}");
        std::process::exit(1);
    }
}

fn machine_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

mod user_input {
    use std::io;

    pub fn get_input(prompt: &str) -> String {
        println!("{prompt}");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("error: unable to read user input");

        input.trim().to_string()
    }
}
