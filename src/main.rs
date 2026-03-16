mod processes;
mod protocol;

use crate::processes::{client, server};
use user_input::get_input;

#[tokio::main]
async fn main() {
    let prompt = "Initialise client, or server? (c/s):";
    let choice = get_input(prompt);

    match choice.as_str() {
        "s" => server::run().await,
        "c" => client::run().await,
        _ => println!("Invalid choice"),
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
