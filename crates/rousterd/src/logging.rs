//! Daemon logging init: ANSI color only for humans on a terminal.
//!
//! `tracing_subscriber::fmt::init()` enables ANSI escapes unconditionally,
//! so redirecting a daemon's stdout to a file (container logs, smoke-test
//! quarantine) baked escape bytes into the file — the Z4 smoke's greps had
//! to `sed` them away (commit 5fc0446). The daemons now decide at init
//! instead: color when stdout is a TTY, plain bytes when it is a file or
//! pipe. The smoke script's ANSI-tolerant greps stay as belt and braces.
//!
//! `ROUSTERD_LOG` (PERF-P2): an operational level knob in the FRR
//! `--log-level` spirit — `trace|debug|info|warn|error`, default `info`
//! (the pre-knob behavior, byte-for-byte). An unparsable value warns and
//! falls back to `info` rather than silently disabling logging. The knob
//! is how the CPU campaign's census ablates the per-route info lines
//! without touching the emitted-format contract the smokes grep.

use std::io::IsTerminal;

/// The default level: `info`, the behavior before the knob existed.
const DEFAULT_LEVEL: &str = "info";

/// Installs the global tracing subscriber with TTY-detected ANSI.
pub fn init() {
    init_with_ansi(std::io::stdout().is_terminal());
}

/// The install path, parameterized on the ANSI decision so tests can pin
/// both configurations.
pub fn init_with_ansi(ansi: bool) {
    tracing_subscriber::fmt()
        .with_ansi(ansi)
        .with_max_level(level_from_env())
        .init();
}

/// `ROUSTERD_LOG` → [`tracing_subscriber::filter::LevelFilter`]; absent
/// or unparsable → `info` (a warning on the unparsable case so a typo
/// is visible, not a silent level change).
fn level_from_env() -> tracing_subscriber::filter::LevelFilter {
    use tracing_subscriber::filter::LevelFilter;
    let raw = match std::env::var("ROUSTERD_LOG") {
        Ok(raw) if !raw.is_empty() => raw,
        _ => return LevelFilter::INFO,
    };
    match raw.parse::<LevelFilter>() {
        Ok(level) => level,
        Err(_) => {
            // eprintln, not tracing: the subscriber is not installed
            // yet, and this line is for the operator that typo'd.
            eprintln!(
                "rousterd: ROUSTERD_LOG={raw:?} is not a level \
                 (trace|debug|info|warn|error); using {DEFAULT_LEVEL}"
            );
            LevelFilter::INFO
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::filter::LevelFilter;

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

    /// The knob (PERF-P2): the env table parses to the matching filter,
    /// absent keeps the historical `info` default, and a typo falls back
    /// to `info` (never `off`, never `trace`).
    #[test]
    fn log_level_env_table() {
        // SAFETY-ish test note: level_from_env reads the process env;
        // these tests run single-threaded per process in the default
        // harness and restore the var, so no cross-test interference.
        let guard = EnvGuard::unset();

        assert_eq!(level_from_env(), LevelFilter::INFO, "absent → info");

        for (raw, want) in [
            ("trace", LevelFilter::TRACE),
            ("debug", LevelFilter::DEBUG),
            ("info", LevelFilter::INFO),
            ("warn", LevelFilter::WARN),
            ("error", LevelFilter::ERROR),
        ] {
            std::env::set_var("ROUSTERD_LOG", raw);
            assert_eq!(level_from_env(), want, "ROUSTERD_LOG={raw}");
        }

        std::env::set_var("ROUSTERD_LOG", "loud");
        assert_eq!(
            level_from_env(),
            LevelFilter::INFO,
            "unparsable → info fallback"
        );

        drop(guard);
    }

    /// Restores `ROUSTERD_LOG` on drop (unset if it was unset).
    struct EnvGuard(Option<String>);

    impl EnvGuard {
        fn unset() -> Self {
            let prior = std::env::var("ROUSTERD_LOG").ok();
            std::env::remove_var("ROUSTERD_LOG");
            Self(prior)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => std::env::set_var("ROUSTERD_LOG", v),
                None => std::env::remove_var("ROUSTERD_LOG"),
            }
        }
    }
}
