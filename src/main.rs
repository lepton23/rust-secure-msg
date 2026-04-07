use p2_message::crypto::certs::*;
use p2_message::processes::{client, server};
use user_input::get_input;

#[tokio::main]
async fn main() {
    let prompt = "Start server, or start client? (s/c):";
    let choice = get_input(prompt);

    let result = match choice.as_str() {
        "s" => {
            // Only generate certs if CA doesn't exist
            if !std::path::Path::new("certs/ca.pem").exists() {
                let _ = generate_certs("certs", "default");
            }
            server::run("certs/ca.pem", "certs/server.pem", "certs/server-key.pem").await
        }
        "c" => {
            let name = get_input("Enter your client name (e.g. Alice/Bob):");

            // Only generate certs if CA doesn't exist
            if !std::path::Path::new("certs/ca.pem").exists() {
                let _ = generate_certs("certs", "default");
            }

            // Generate client if it doesn't exist
            let cert_path = format!("certs/client-{}.pem", name);
            if !std::path::Path::new(&cert_path).exists() {
                let _ = generate_certs("certs", &name);
            }
            let key_path = format!("certs/client-{}-key.pem", name);
            client::run(
                "certs/ca.pem",
                &cert_path,
                &key_path,
                "localhost",
                "127.0.0.1:8080",
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
        eprintln!("Fatal error: {}", e);
        std::process::exit(1);
    }
}

mod user_input {
    use std::io;

    pub fn get_input(prompt: &str) -> String {
        println!("{}", prompt);
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("error: unable to read user input");

        input.trim().to_string()
    }
}
