use std::{
    borrow::Cow,
    collections::HashSet,
    fs,
    io::Read,
    os::{fd::AsFd, unix::process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Stdio},
};

use clap::{CommandFactory, Parser, Subcommand};
use libc::{VMIN, VTIME};
use nix::sys::{
    signal::{killpg, SigHandler, Signal},
    termios::{self, LocalFlags, SetArg},
};
use reedline::{
    default_emacs_keybindings, ColumnarMenu, DefaultCompleter, Emacs, FileBackedHistory, KeyCode,
    KeyModifiers, MenuBuilder, Prompt, PromptHistorySearchStatus, Reedline, ReedlineEvent,
    ReedlineMenu,
};

use crate::ns::Ns;

const PCAP_DIR: &str = "/tmp/erez-pcaps";

#[derive(Debug, Parser)]
enum Command {
    /// Show info about all namespaces in the topology.
    Info,
    /// Run a command inside a namespace.
    Exec {
        /// Namespace display name.
        ns: String,
        /// Command and arguments to run.
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Stream live log output from all namespaces.
    Logs,
    /// Manage packet captures across all network namespaces.
    Pcap {
        #[command(subcommand)]
        command: PcapCommand,
    },
    /// Clear the terminal.
    Clear,
    /// Exit the REPL.
    Exit,
}

#[derive(Debug, Subcommand)]
enum PcapCommand {
    /// Start packet capture in all network namespaces.
    Start {
        /// Tcpdump filter expression.
        #[arg(long, default_value = "tcp or udp or ip6 proto 47 or icmp or icmp6")]
        filter: String,
    },
    /// Stop active packet captures.
    Stop,
    /// Copy packet capture files to a normal directory.
    Export {
        /// Destination directory.
        dir: PathBuf,
    },
}

pub fn run(namespaces: &[&Ns]) -> anyhow::Result<()> {
    let mut line_editor = build_line_editor(namespaces)?;
    let prompt = ReplPrompt {};
    let mut pcap_state = PcapState::new();

    loop {
        let sig = line_editor.read_line(&prompt);

        use reedline::Signal as S;
        let line = match sig {
            Ok(S::Success(l)) => l,
            Ok(S::CtrlC) => continue,
            Ok(S::CtrlD) => break,
            Err(e) => {
                eprintln!("REPL error: {e:?}");
                continue;
            }
        };
        if line.is_empty() {
            continue;
        }

        // Clap expects the first argument to be the program
        // name, we just specify an empty string instead.
        let mut args = shlex::split(&line).ok_or(anyhow::anyhow!("shlex parsing failed"))?;
        args.insert(0, String::new());
        match Command::try_parse_from(args) {
            Ok(cmd) => match cmd {
                Command::Info => dispatch_info(namespaces),
                Command::Exec { ns, cmd } => dispatch_exec(namespaces, &ns, &cmd),
                Command::Logs => dispatch_logs(),
                Command::Pcap { command } => match command {
                    PcapCommand::Start { filter } => pcap_state.start(namespaces, &filter),
                    PcapCommand::Stop => pcap_state.stop(),
                    PcapCommand::Export { dir } => pcap_state.export(&dir),
                },
                Command::Clear => dispatch_clear(&mut line_editor),
                Command::Exit => break,
            },
            Err(e) => {
                let _ = e.print();
            }
        }
    }

    Ok(())
}

struct PcapState {
    children: Vec<PcapChild>,
    dir: PathBuf,
}

struct PcapChild {
    child: Child,
}

impl PcapState {
    fn new() -> Self {
        Self {
            children: Vec::new(),
            dir: PathBuf::from(PCAP_DIR),
        }
    }

    fn start(&mut self, namespaces: &[&Ns], filter: &str) {
        if !self.children.is_empty() {
            eprintln!("pcap capture is already running");
            return;
        }

        let result: anyhow::Result<()> = (|| {
            fs::create_dir_all(&self.dir)?;
            self.remove_capture_files()?;

            let mut seen_netns = HashSet::new();

            for ns in namespaces {
                if !seen_netns.insert(ns.net_ns().system_name().to_string()) {
                    continue;
                }

                let name = ns.net_ns().display_name().to_string();
                let pcap_path = self.dir.join(format!("{name}.pcap"));
                let stderr = fs::File::create(self.dir.join(format!("{name}.tcpdump.log")))?;

                // Enter the target's net namespace, but not the mount
                // namespace, so we can write to /tmp in the host.
                let mut command = std::process::Command::new("nsenter");
                command.args([
                    "--target",
                    &ns.pid().to_string(),
                    "--net",
                    "--",
                    "tcpdump",
                    "-i",
                    "any",
                    "-nn",
                    "-s",
                    "0",
                    "-U",
                    "-w",
                ]);
                command.arg(&pcap_path);
                command.arg(filter);
                command.stdin(Stdio::null());
                command.stdout(Stdio::null());
                command.stderr(stderr);
                command.process_group(0);

                let child = command.spawn()?;
                self.children.push(PcapChild { child });
            }

            println!(
                "started {} tcpdump captures in {}; filter: {filter}; written to {PCAP_DIR}",
                self.children.len(),
                self.dir.display()
            );
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("{e:#}");
        }
    }

    fn stop(&mut self) {
        if self.children.is_empty() {
            println!("no pcap capture is running");
            return;
        }

        for child in &self.children {
            let pgid = nix::unistd::Pid::from_raw(child.child.id() as i32);
            let _ = killpg(pgid, Signal::SIGTERM);
        }

        for mut child in self.children.drain(..) {
            let _ = child.child.wait();
        }

        println!("stopped pcap captures");
    }

    fn export(&self, dir: &Path) {
        let result: anyhow::Result<()> = (|| {
            fs::create_dir_all(dir)?;
            let files = self.capture_files()?;
            if files.is_empty() {
                anyhow::bail!("no capture files found in {}", self.dir.display());
            }

            for path in &files {
                let Some(file_name) = path.file_name() else {
                    continue;
                };
                fs::copy(path, dir.join(file_name))?;
            }

            println!("exported {} files to {}", files.len(), dir.display());
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("{e:#}");
        }
    }

    fn capture_files(&self) -> anyhow::Result<Vec<PathBuf>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }

        let mut files = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.is_file() {
                files.push(path);
            }
        }
        files.sort();
        Ok(files)
    }

    fn remove_capture_files(&self) -> anyhow::Result<()> {
        for path in self.capture_files()? {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

impl Drop for PcapState {
    fn drop(&mut self) {
        if !self.children.is_empty() {
            self.stop();
        }
    }
}

fn dispatch_info(namespaces: &[&Ns]) {
    info::print_overview(namespaces);
}

mod info {
    use crate::ns::Ns;

    pub fn print_overview(namespaces: &[&Ns]) {
        print_table(
            "Overview",
            &["NAME", "NETNS PATH", "PID"],
            &namespaces
                .iter()
                .map(|ns| {
                    [
                        ns.display_name().to_string(),
                        ns.net_ns().path(),
                        ns.pid().to_string(),
                    ]
                })
                .collect::<Vec<_>>(),
        );
    }

    fn print_table<const N: usize>(title: &str, headers: &[&str; N], rows: &[[String; N]]) {
        let mut widths = [0; N];
        for (i, header) in headers.iter().enumerate() {
            widths[i] = header.len();
        }
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cell.len());
            }
        }

        println!("{title}:");

        let header_line: String = headers
            .iter()
            .enumerate()
            .map(|(i, h)| format!("{:<w$}", h, w = widths[i]))
            .collect::<Vec<_>>()
            .join("  ");
        println!("  {header_line}");

        for row in rows {
            let line: String = row
                .iter()
                .enumerate()
                .map(|(i, cell)| format!("{:<w$}", cell, w = widths[i]))
                .collect::<Vec<_>>()
                .join("  ");
            println!("  {line}");
        }
    }
}

fn dispatch_exec(namespaces: &[&Ns], ns_name: &str, cmd: &[String]) {
    let Some(ns) = namespaces.iter().find(|ns| ns.display_name() == ns_name) else {
        eprintln!("Unknown ns: {ns_name}");
        return;
    };

    let mut nsenter = std::process::Command::new("nsenter");
    nsenter.args(["--target", &ns.pid().to_string(), "--all", "--"]);
    nsenter.args(cmd);

    // Inherit the real terminal for full interactivity.
    nsenter.stdin(std::process::Stdio::inherit());
    nsenter.stdout(std::process::Stdio::inherit());
    nsenter.stderr(std::process::Stdio::inherit());

    // Ignore SIGINT in the REPL process so Ctrl+C only kills the child.
    let prev =
        unsafe { nix::sys::signal::signal(nix::sys::signal::Signal::SIGINT, SigHandler::SigIgn) }
            .unwrap();

    let _ = nsenter.status();

    // Restore previous SIGINT handler.
    unsafe {
        let _ = nix::sys::signal::signal(nix::sys::signal::Signal::SIGINT, prev);
    };
}

fn dispatch_logs() {
    println!("Streaming live output from all namespaces (press 'q' to stop)...");

    let stdin = std::io::stdin();
    let fd = stdin.as_fd();
    let orig = termios::tcgetattr(fd).expect("tcgetattr");
    let mut raw = orig.clone();

    // See: https://man7.org/linux/man-pages/man3/termios.3.html

    // Make terminal input immediately available to read, instead
    // of buffering until a line-delimiter character is typed.
    raw.local_flags.remove(LocalFlags::ICANON);
    // Don't echo keypresses back to the terminal.
    raw.local_flags.remove(LocalFlags::ECHO);
    // Don't generate SIGINT, (and other signals) when receiving
    // the appropriate characters.
    raw.local_flags.remove(LocalFlags::ISIG);

    // Block indefinitely until at least one byte of information
    // is readable.
    raw.control_chars[VMIN] = 1;
    raw.control_chars[VTIME] = 0;

    // Apply immediately (TCSANOW) rather than draining output first,
    // since we want the input side to switch right away.
    termios::tcsetattr(fd, SetArg::TCSANOW, &raw).expect("tcsetattr");

    crate::ns::set_stderr_suppressed(false);

    // Read loop; only 'q' exits.
    let mut buf = [0u8; 1];
    while let Ok(1) = stdin.lock().read(&mut buf) {
        if buf[0] == b'q' {
            break;
        }
    }

    crate::ns::set_stderr_suppressed(true);
    termios::tcsetattr(fd, SetArg::TCSANOW, &orig).expect("tcsetattr restore");

    println!("Returning to REPL...");
}

fn dispatch_clear(line_editor: &mut Reedline) {
    let _ = line_editor.clear_screen();
}

fn build_line_editor(namespaces: &[&Ns]) -> anyhow::Result<Reedline> {
    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );

    let line_editor = Reedline::create()
        .with_history(Box::new(FileBackedHistory::with_file(
            1000,
            "/tmp/.erez_console_history".into(),
        )?))
        .with_completer(build_completer(namespaces))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(
            ColumnarMenu::default().with_name("completion_menu"),
        )))
        .with_edit_mode(Box::new(Emacs::new(keybindings)));

    Ok(line_editor)
}

// reedline expects a boxed completer, so we box
// it when building instead of at a later point.
#[allow(clippy::unnecessary_box_returns)]
fn build_completer(namespaces: &[&Ns]) -> Box<DefaultCompleter> {
    let mut completions: Vec<String> = Vec::new();
    for sub in Command::command().get_subcommands() {
        let name = sub.get_name().to_string();

        let takes_ns = sub.get_arguments().any(|arg| arg.get_id() == "ns");
        if takes_ns {
            for ns in namespaces {
                completions.push(format!("{name} {}", ns.display_name()));
            }
        }

        completions.push(name);
    }
    for subcommand in ["start", "stop", "merge", "dump", "files", "clear", "export"] {
        completions.push(format!("pcap {subcommand}"));
    }

    // Some namespace names have an underscore or hyphen
    // in them, so we need to explicitly allow completing
    // against these characters; the default is a-z, A-Z.
    let mut completer = DefaultCompleter::with_inclusions(&['_', '-', ':']);
    completer.insert(completions);
    Box::new(completer)
}

struct ReplPrompt {}

impl Prompt for ReplPrompt {
    fn render_prompt_left(&self) -> Cow<str> {
        Cow::Borrowed("")
    }

    fn render_prompt_right(&self) -> Cow<str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(
        &self,
        _prompt_mode: reedline::PromptEditMode,
    ) -> std::borrow::Cow<str> {
        Cow::Borrowed(">> ")
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<str> {
        Cow::Borrowed("::: ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: reedline::PromptHistorySearch,
    ) -> std::borrow::Cow<str> {
        let term = match history_search.status {
            PromptHistorySearchStatus::Passing => {
                if history_search.term.is_empty() {
                    String::new()
                } else {
                    format!("({}) ", history_search.term)
                }
            }
            PromptHistorySearchStatus::Failing => format!("(failing: {}) ", history_search.term),
        };
        Cow::Owned(term)
    }
}
