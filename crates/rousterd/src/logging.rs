//! Daemon logging init: ANSI color only for humans on a terminal.
//!
//! `tracing_subscriber::fmt::init()` enables ANSI escapes unconditionally,
//! so redirecting a daemon's stdout to a file (container logs, smoke-test
//! quarantine) baked escape bytes into the file — the Z4 smoke's greps had
//! to `sed` them away (commit 5fc0446). The daemons now decide at init
//! instead: color when stdout is a TTY, plain bytes when it is a file or
//! pipe. The smoke script's ANSI-tolerant greps stay as belt and braces.

use std::io::IsTerminal;

/// Installs the global tracing subscriber with TTY-detected ANSI.
pub fn init() {
    init_with_ansi(std::io::stdout().is_terminal());
}

/// The install path, parameterized on the ANSI decision so tests can pin
/// both configurations.
pub fn init_with_ansi(ansi: bool) {
    tracing_subscriber::fmt().with_ansi(ansi).init();
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    /// A `MakeWriter` capturing everything the subscriber emits, standing
    /// in for the redirected file (or the TTY) on the other side of
    /// stdout.
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for Capture {
        type Writer = Capture;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured_log(ansi: bool) -> String {
        let sink = Capture(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(ansi)
            .with_writer(sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("zapi: listening");
        });
        let bytes = sink.0.lock().unwrap().clone();
        String::from_utf8(bytes).expect("log output is UTF-8")
    }

    /// The redirected-file case (the fix): no escape bytes in the output.
    #[test]
    fn non_tty_output_is_ansi_free() {
        let log = captured_log(false);
        assert!(log.contains("zapi: listening"), "message survives");
        assert!(
            !log.contains('\u{1b}'),
            "redirected files must not carry ANSI escapes: {log:?}"
        );
    }

    /// The interactive case: the same config with ANSI on does color the
    /// level tag — proving the switch is the only difference, not a lost
    /// writer or format.
    #[test]
    fn ansi_output_is_colored() {
        let log = captured_log(true);
        assert!(log.contains("zapi: listening"));
        assert!(
            log.contains('\u{1b}'),
            "TTY output keeps its ANSI coloring: {log:?}"
        );
    }
}
