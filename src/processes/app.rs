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
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use tokio::io::{AsyncWrite, BufReader};

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

struct AppState {
    messages: Vec<String>, // chat log
    input: String,         // current input buffer
    should_quit: bool,
}

impl AppState {
    fn new() -> Self {
        Self {
            messages: vec![
                "Commands (list, send, quit)".into(),
                "  :l | :s <to> <message> | :q".into(),
                "".into(),
            ],
            input: String::new(),
            should_quit: false,
        }
    }

    fn push_msg(&mut self, msg: String) {
        self.messages.push(msg);
    }
}

// interactive loop and read task
pub async fn run_tui<R, W>(
    client_id: &str,
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    install_panic_hook();
    let _guard = TerminalGuard::new()?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new();
    let mut term_events = EventStream::new();

    // main loop
    loop {
        // draw current state
        terminal.draw(|f| ui(f, &state))?;

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
                    Ok(msg) => handle_incoming_tui(msg, &mut state),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        state.push_msg("Server closed connection.".into());
                        state.should_quit = true;
                    }
                    Err(e) => {
                        state.push_msg(format!("Read error: {e}"));
                        state.should_quit = true;
                    }
                }
            }
        }
    }

    // teardown
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

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
                // send deregister before quitting
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
                    state.push_msg(format!("[you -> {to}]: {content}"));
                    Message::Send {
                        to: to.to_string(),
                        content: content.to_string(),
                    }
                    .write_framed(writer)
                    .await?;
                } else {
                    state.push_msg("Usage: :s <recipient> <message>".into());
                }
            } else if !trimmed.is_empty() {
                state.push_msg(format!("Unknown command: {trimmed}"));
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_incoming_tui(msg: Message, state: &mut AppState) {
    match msg {
        Message::Receive { from, content } => {
            state.push_msg(format!("[{from}]: {content}"));
        }
        Message::ClientsList(clients) => {
            state.push_msg(format!("Online: {}", clients.join(", ")));
        }
        Message::Error(err) => {
            state.push_msg(format!("Server error: {err}"));
        }
        other => {
            state.push_msg(format!("Unexpected: {other:?}"));
        }
    }
}

// Layout: message log on top, input bar on bottom.
fn ui(f: &mut ratatui::Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // messages fill available space
            Constraint::Length(3), // input bar fixed height
        ])
        .split(f.area());

    // message log
    let items: Vec<ListItem> = state
        .messages
        .iter()
        .map(|m| ListItem::new(Line::from(m.as_str())))
        .collect();

    let messages_widget =
        List::new(items).block(Block::default().borders(Borders::ALL).title("Messages"));

    f.render_widget(messages_widget, chunks[0]);

    // input bar
    let input_widget = Paragraph::new(Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::Green)),
        Span::raw(&state.input),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Input"));

    f.render_widget(input_widget, chunks[1]);

    // place cursor at end of input text
    f.set_cursor_position((
        chunks[1].x + 3 + state.input.len() as u16, // +2 for "> "
        chunks[1].y + 1,                            // +1 for border
    ));
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
