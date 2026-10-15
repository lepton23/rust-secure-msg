# Rust secure private messaging client & server

### Developed for uni project

Navigate to root directory, i.e. Containing src/, target/, Cargo.lock, Cargo.toml, README.md

To build: run `cargo build --release` - this may take up to a minute for required libraries to install

To run: run `target/release/p2-message`, you will be prompted to start a server or a client

Server operation:
- Enter "s" and press enter.
- The server will notify you of the hostname needed to connect to it. It should be the name of the host machine (e.g. pc2-111-l, lyrane, palain).
- Enter the port you would like to host the server on (e.g. 8080) and press enter.
- The server will start, log messages will be displayed as they come in.
- The server can be closed by pressing Ctrl-C.

Client operation:
- Enter "c" and press enter.
- Enter the name of the client you'd like to connect with (e.g. "Alice", "Bob", "Mallory") and press enter.
- Enter the hostname of the server to connect to (e.g. "pc2-111-l", "lyrane", "palain") and press enter.
- Enter the port to connect to (e.g. 8080) and press enter.
- The client will open an alternate UI window - see UI operation below.

Messaging UI operation:
- Your inputs are displayed at the bottom of the screen. Message and telemetry is logged in the main panel, and online clients are on the right column.
- Type ":l" to request a list of online clients from the server, the "Online" list will be updated on the right.
- Type ":s <Name of Target> <Message>" to send a message to a target client (e.g. ":s Bob Hello There!" to send Bob a "Hello There!" message).
- Type ":q" or press Ctrl-C to quit the client and deregister from the server.

In order to see communication between multiple clients, initialise a server, and connect two client instances to the server. \
Enter ":l" on a client to verify the server is aware of both clients, and send a message with the ":s" command to message the other client. \
This can be performed between different lab machines, or locally in separate shells. \
Any errors (e.g. sending a message to a non-existant client) will result in an error popup which can be dismissed by pressing ESC.
