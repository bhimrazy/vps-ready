//! [`Defer`]: holds back the signals that end the wizard while it has
//! something to clean up first.

use std::ffi::c_int;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

/// SIGHUP, SIGINT and SIGTERM, which end the process as usual except
/// between [`Defer::hold`] and [`Defer::release`], where they are only
/// noted. The handlers stay for the life of the process: unregistering
/// one would leave its signal ignored, not back to its default.
#[derive(Debug, Clone)]
pub struct Defer {
    /// Shared with [`super::Terminal`]: while set, SIGINT ends the process.
    sigint_ends: Arc<AtomicBool>,
    /// While set, SIGHUP and SIGTERM end the process.
    others_end: Arc<AtomicBool>,
    /// The last signal noted, or 0.
    caught: Arc<AtomicUsize>,
}

impl Defer {
    /// Installs the handlers. SIGINT's default is `sigint_ends`', which
    /// [`super::Terminal`] installs.
    pub(super) fn register(sigint_ends: Arc<AtomicBool>) -> io::Result<Self> {
        let defer = Self::new(sigint_ends);
        for sig in [SIGHUP, SIGTERM] {
            signal_hook::flag::register_conditional_default(sig, Arc::clone(&defer.others_end))?;
        }
        for sig in [SIGHUP, SIGINT, SIGTERM] {
            let value = usize::try_from(sig).unwrap_or_default();
            signal_hook::flag::register_usize(sig, Arc::clone(&defer.caught), value)?;
        }
        Ok(defer)
    }

    fn new(sigint_ends: Arc<AtomicBool>) -> Self {
        Self {
            sigint_ends,
            others_end: Arc::new(AtomicBool::new(true)),
            caught: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// One with no handlers, for tests.
    #[cfg(test)]
    pub(crate) fn unregistered() -> Self {
        Self::new(Arc::new(AtomicBool::new(true)))
    }

    /// Notes `sig` as if it arrived, for tests.
    #[cfg(test)]
    pub(crate) fn note(&self, sig: c_int) {
        let value = usize::try_from(sig).unwrap_or_default();
        self.caught.store(value, Ordering::SeqCst);
    }

    /// From now on the signals are only noted. One noted before can only
    /// have come during a question, whose Ctrl-C ends the wizard anyway.
    pub fn hold(&self) {
        self.sigint_ends.store(false, Ordering::SeqCst);
        self.others_end.store(false, Ordering::SeqCst);
    }

    /// Whether a signal was noted.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.caught.load(Ordering::SeqCst) != 0
    }

    /// The signals end the process again. Returns the last one noted, for
    /// the caller to end with once it has cleaned up.
    pub fn release(&self) -> Option<c_int> {
        self.sigint_ends.store(true, Ordering::SeqCst);
        self.others_end.store(true, Ordering::SeqCst);
        let sig = self.caught.swap(0, Ordering::SeqCst);
        c_int::try_from(sig).ok().filter(|&s| s != 0)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::time::Duration;

    use super::*;

    const CHILD: &str = "VPS_READY_DEFER_CHILD";

    /// In a child process, as the signals are real: one held is noted, and
    /// after the release SIGHUP ends the process as its default does.
    #[test]
    fn released_signals_end_the_process_again() {
        if std::env::var_os(CHILD).is_some() {
            let defer = Defer::register(Arc::new(AtomicBool::new(true))).unwrap();
            defer.hold();
            signal_hook::low_level::raise(SIGTERM).unwrap();
            assert_eq!(defer.release(), Some(SIGTERM));
            signal_hook::low_level::raise(SIGHUP).unwrap();
            std::thread::sleep(Duration::from_secs(5));
            panic!("SIGHUP did not end the process");
        }
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tui::defer::tests::released_signals_end_the_process_again",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_eq!(
            out.status.signal(),
            Some(SIGHUP),
            "{out:?}\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
