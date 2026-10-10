//! rousterctl — the Rouster operator CLI (see the library docs).

use std::process::ExitCode;

use rousterctl::args;
use rousterctl::run;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match args::parse(&argv) {
        Ok(cli) => ExitCode::from(run::dispatch(&cli)),
        Err(message) => {
            eprintln!("rousterctl: {message}");
            eprintln!();
            eprint!("{}", args::help_text());
            ExitCode::from(run::EXIT_USAGE)
        }
    }
}
