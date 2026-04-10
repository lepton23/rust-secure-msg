use std::collections::HashMap;
use std::io;
use std::panic;

use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures::StreamExt;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
};
use tokio::io::{AsyncWrite, BufReader};

use crate::crypto::e2e::E2EKeys;
use crate::protocol::message::Message;

struct TerminalGuard;

impl TerminalGuard {
    fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

enum ChatEntry {
    Sent { to: String, content: String },
    Received { from: String, content: String },
    System(String),
    Error(String),
}

struct AppState {
    messages: Vec<ChatEntry>,
    input: String,
    should_quit: bool,
    e2e: E2EKeys,
    // Cached peer hybrid public keys: client_id → (X25519 key, ML-KEM-768 ek bytes).
    peer_keys: HashMap<String, ([u8; 32], Vec<u8>)>,
    // Messages queued to send once a peer's key arrives.
    pending_outbound: HashMap<String, Vec<String>>,
    // Encrypted messages queued to decrypt once a sender's key arrives.
    pending_inbound: HashMap<String, Vec<Vec<u8>>>,
    online_clients: Vec<String>,
    error_popup: Option<String>,
    inbound_seq: HashMap<String, u64>,
    outbound_seq: HashMap<String, u64>,
}

impl AppState {
    fn new(e2e: E2EKeys) -> Self {
        Self {
            messages: vec![
                ChatEntry::System("Commands: :l list online, :s <to> <msg> send, :q quit".into()),
            ],
            input: String::new(),
            should_quit: false,
            e2e,
            peer_keys: HashMap::new(),
            pending_outbound: HashMap::new(),
            pending_inbound: HashMap::new(),
            online_clients: Vec::new(),
            error_popup: None,
            inbound_seq: HashMap::new(),
            outbound_seq: HashMap::new(),
        }
    }

    fn push_sent(&mut self, to: String, content: String) {
        self.messages.push(ChatEntry::Sent { to, content });
    }

    fn push_received(&mut self, from: String, content: String) {
        self.messages.push(ChatEntry::Received { from, content });
    }

    fn push_system(&mut self, msg: String) {
        self.messages.push(ChatEntry::System(msg));
    }

    fn push_error(&mut self, msg: String) {
        self.messages.push(ChatEntry::Error(msg.clone()));
        self.error_popup = Some(msg);
    }
}

// interactive loop and read task
pub async fn run_tui<R, W>(
    client_id: &str,
    reader: &mut BufReader<R>,
    writer: &mut W,
    e2e: E2EKeys,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    install_panic_hook();
    let _guard = TerminalGuard::new()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new(e2e);
    let mut term_events = EventStream::new();

    // main loop
    loop {
        // draw current state
        terminal.draw(|f| ui(f, &state, client_id))?;

        if state.should_quit {
            break;
        }

        tokio::select! {
            // branch 1: terminal input
            maybe_event = term_events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) => {
                        handle_key(key, &mut state, client_id, writer).await?;
                    }
                    Some(Err(_)) | None => break,
                    _ => {} // ignore mouse/resize for now
                }
            }

            // branch 2: incoming server message
            result = Message::read_framed(reader) => {
                match result {
                    Ok(msg) => handle_incoming(msg, &mut state, writer).await?,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        state.push_error("Server closed connection.".into());
                        state.should_quit = true;
                    }
                    Err(e) => {
                        state.push_error(format!("Read error: {e}"));
                        state.should_quit = true;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_key<W: AsyncWrite + Unpin>(
    key: KeyEvent,
    state: &mut AppState,
    client_id: &str,
    writer: &mut W,
) -> io::Result<()> {
    if !key.kind.is_press() {
        return Ok(());
    }
    match key.code {
        KeyCode::Esc => {
            // dismiss error popup if one is showing
            state.error_popup = None;
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.should_quit = true;
        }
        KeyCode::Char(c) => {
            state.input.push(c);
        }
        KeyCode::Backspace => {
            state.input.pop();
        }
        KeyCode::Enter => {
            let line = state.input.drain(..).collect::<String>();
            let trimmed = line.trim();

            if trimmed == ":q" {
                let _ = Message::Deregister {
                    client_id: client_id.to_string(),
                }
                .write_framed(writer)
                .await;
                state.should_quit = true;
            } else if trimmed == ":l" {
                Message::List.write_framed(writer).await?;
            } else if let Some(rest) = trimmed.strip_prefix(":s ") {
                if let Some((to, content)) = rest.split_once(' ') {
                    // Clone key data before any mutable state access.
                    let key_data = state.peer_keys.get(to).map(|(k, e)| (*k, e.clone()));
                    if let Some((x25519_key, mlkem_ek)) = key_data {
                        // Both keys cached — encrypt with hybrid scheme and send.
                        // add seq to aead plaintext to defend against replay attacks
                        let seq = state.outbound_seq.entry(to.to_string()).or_insert(0);
                        *seq += 1;
                        let plaintext_with_seq = format!("{:016x}:{content}", seq);
                        let ct = state.e2e.encrypt(&x25519_key, &mlkem_ek, &plaintext_with_seq);
                        state.push_sent(to.to_string(), content.to_string());
                        Message::Send {
                            to: to.to_string(),
                            content: ct,
                        }
                        .write_framed(writer)
                        .await?;
                    } else {
                        // Keys not yet cached — queue plaintext and request them.
                        let pending = state.pending_outbound.entry(to.to_string()).or_default();
                        let is_first = pending.is_empty();
                        pending.push(content.to_string());
                        if is_first {
                            Message::RequestKey {
                                client_id: to.to_string(),
                            }
                            .write_framed(writer)
                            .await?;
                            state.push_system(format!("Fetching key for {to}..."));
                        }
                    }
                } else {
                    state.push_system("Usage: :s <recipient> <message>".into());
                }
            } else if !trimmed.is_empty() {
                state.push_system(format!("Unknown command: {trimmed}"));
            }
        }
        _ => {}
    }
    Ok(())
}

async fn handle_incoming<W: AsyncWrite + Unpin>(
    msg: Message,
    state: &mut AppState,
    writer: &mut W,
) -> io::Result<()> {
    match msg {
        Message::Receive { from, content } => {
            // Only sender's X25519 key needed for decryption
            let x25519_key = state.peer_keys.get(&from).map(|(k, _)| *k);
            if let Some(x25519_key) = x25519_key {
                match state.e2e.decrypt(&x25519_key, &content) {
                    Some(plain) => {
                        // replay attack protection
                        if let Some((seq_str, msg)) = plain.split_once(":") {
                            if let Ok(seq) = u64::from_str_radix(seq_str, 16) {
                                let last = state.inbound_seq.entry(from.clone()).or_insert(0);
                                if seq <= *last {
                                    state.push_error(format!("[{from}]: replayed message rejected"));
                                    return Ok(());
                                }
                                *last = seq;
                                state.push_received(from, msg.to_string());
                            }
                        }
                    }
                    None => state.push_error(format!("[{from}]: decryption failed")),
                }
            } else {
                // Buffer ct and request sender's hybrid public key.
                let pending = state.pending_inbound.entry(from.clone()).or_default();
                let is_first = pending.is_empty();
                pending.push(content);
                if is_first {
                    Message::RequestKey { client_id: from }
                        .write_framed(writer)
                        .await?;
                }
            }
        }

        Message::KeyResponse { client_id, x25519_key, mlkem_ek } => {
            state.peer_keys.insert(client_id.clone(), (x25519_key, mlkem_ek.clone()));

            // encrypt with hybrid scheme.
            if let Some(msgs) = state.pending_outbound.remove(&client_id) {
                for plaintext in msgs {
                    let seq = state.outbound_seq.entry(client_id.to_string()).or_insert(0);
                    *seq += 1;
                    let plaintext_with_seq = format!("{:016x}:{plaintext}", seq);
                    let ct = state.e2e.encrypt(&x25519_key, &mlkem_ek, &plaintext_with_seq);
                    state.push_sent(client_id.clone(), plaintext);
                    Message::Send {
                        to: client_id.clone(),
                        content: ct,
                    }
                    .write_framed(writer)
                    .await?;
                }
            }

            // Decrypt inbound messages with the sender's X25519 key.
            if let Some(cts) = state.pending_inbound.remove(&client_id) {
                for ct in cts {
                    match state.e2e.decrypt(&x25519_key, &ct) {
                        Some(plain) => {
                            // replay attack protection
                            if let Some((seq_str, msg)) = plain.split_once(":") {
                                if let Ok(seq) = u64::from_str_radix(seq_str, 16) {
                                    let last = state.inbound_seq.entry(client_id.clone()).or_insert(0);
                                    if seq <= *last {
                                        state.push_error(format!("[{client_id}]: replayed message rejected"));
                                        return Ok(());
                                    }
                                    *last = seq;
                                    state.push_received(client_id.clone(), msg.to_string());
                                }
                            }
                        }
                        None => state.push_error(format!("[{client_id}]: decryption failed")),
                    }
                }
            }
        }

        Message::ClientsList(clients) => {
            state.online_clients = clients;
        }
        Message::Error(err) => {
            state.push_error(format!("Server error: {err}"));
        }
        other => {
            state.push_system(format!("Unexpected: {other:?}"));
        }
    }
    Ok(())
}

// app layout
fn ui(f: &mut ratatui::Frame, state: &AppState, client_id: &str) {
    let area = f.area();

    // Outer split: top content area + input bar
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // messages + sidebar
            Constraint::Length(3), // input bar
        ])
        .split(area);

    // Content split: message log (left) + clients sidebar (right)
    let content = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(1),      // messages fill remaining space
            Constraint::Length(22),  // sidebar fixed width
        ])
        .split(outer[0]);

    render_messages(f, state, content[0]);
    render_sidebar(f, state, content[1]);
    render_input(f, state, client_id, outer[1]);

    if let Some(err) = &state.error_popup {
        render_error_popup(f, area, err);
    }
}

fn render_messages(f: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let items: Vec<ListItem> = state
        .messages
        .iter()
        .map(|entry| match entry {
            ChatEntry::Sent { to, content } => ListItem::new(Line::from(vec![
                Span::styled(
                    format!("  you -> {to}: "),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::styled(content.as_str(), Style::default().fg(Color::Cyan)),
            ])),
            ChatEntry::Received { from, content } => ListItem::new(Line::from(vec![
                Span::styled(
                    format!("  {from}: "),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::styled(content.as_str(), Style::default().fg(Color::Yellow)),
            ])),
            ChatEntry::System(msg) => ListItem::new(Line::from(Span::styled(
                format!("  {msg}"),
                Style::default().fg(Color::DarkGray),
            ))),
            ChatEntry::Error(msg) => ListItem::new(Line::from(Span::styled(
                format!("  ! {msg}"),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ))),
        })
        .collect();

    // Scroll so the latest messages are always visible.
    let visible_height = area.height.saturating_sub(2) as usize; // subtract border rows
    let offset = items.len().saturating_sub(visible_height);
    let visible: Vec<ListItem> = items.into_iter().skip(offset).collect();

    let widget = List::new(visible).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(" Messages "),
    );
    f.render_widget(widget, area);
}

fn render_sidebar(f: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let count = state.online_clients.len();
    let title = format!(" Online ({count}) ");

    let items: Vec<ListItem> = if state.online_clients.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "  no clients",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        state
            .online_clients
            .iter()
            .map(|id| {
                ListItem::new(Line::from(vec![
                    Span::styled(" \u{25CF} ", Style::default().fg(Color::Green)), // ● green dot
                    Span::styled(id.as_str(), Style::default().fg(Color::White)),
                ]))
            })
            .collect()
    };

    let widget = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green))
            .title(title),
    );
    f.render_widget(widget, area);
}

fn render_input(f: &mut ratatui::Frame, state: &AppState, client_id: &str, area: Rect) {
    let title = format!(" {client_id} ");
    let widget = Paragraph::new(Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(&state.input),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(title),
    );
    f.render_widget(widget, area);

    // place cursor at end of input text
    f.set_cursor_position((
        area.x + 3 + state.input.len() as u16, // +3 for "> " and border
        area.y + 1,                             // +1 for border
    ));
}

fn render_error_popup(f: &mut ratatui::Frame, area: Rect, message: &str) {
    let popup_area = centered_rect(60, 30, area);

    let text = format!("\n  {message}\n\n  Press Esc to dismiss");
    let widget = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            .title(Span::styled(
                " Error ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
    );

    f.render_widget(Clear, popup_area);
    f.render_widget(widget, popup_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vert[1])[1]
}

fn install_panic_hook() {
    let original_hook = panic::take_hook();

    panic::set_hook(Box::new(move |panic_info| {
        // Best-effort terminal restoration
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);

        // Now delegate to the default handler so the user
        // still sees the backtrace and panic message.
        original_hook(panic_info);
    }));
}
