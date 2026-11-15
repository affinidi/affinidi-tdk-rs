pub mod affinidi_logo;
pub mod did;

/// Finishing an interactive `dialoguer` prompt without panicking.
///
/// `dialoguer` returns an error when the user presses Ctrl-C at a prompt, or
/// when stdin is not a terminal. Either way there is nothing sensible to
/// continue with, so [`unwrap_or_exit`](PromptResultExt::unwrap_or_exit)
/// restores the cursor (a prompt hides it), says why, and exits: status 130 for
/// an interrupt (the shell convention for SIGINT), 1 for anything else.
pub trait PromptResultExt<T> {
    /// The prompt's value, or a clean process exit if the prompt failed.
    fn unwrap_or_exit(self) -> T;
}

impl<T> PromptResultExt<T> for dialoguer::Result<T> {
    fn unwrap_or_exit(self) -> T {
        match self {
            Ok(value) => value,
            Err(e) => {
                let _ = console::Term::stdout().show_cursor();
                let _ = console::Term::stderr().show_cursor();
                eprintln!();
                let dialoguer::Error::IO(io) = &e;
                if io.kind() == std::io::ErrorKind::Interrupted {
                    eprintln!("Interrupted, exiting.");
                    std::process::exit(130);
                }
                eprintln!("Prompt failed ({e}); an interactive terminal is required. Exiting.");
                std::process::exit(1);
            }
        }
    }
}
