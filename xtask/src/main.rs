//! Build-time tasks, run with `cargo xtask <task>`. A separate crate so that
//! the generators add no dependencies to the shipped binary.
//!
//! - `gen-docs <DIR>`: writes the man pages to `DIR/man` and the bash, zsh and
//!   fish completions to `DIR/completions`, all from the real clap command.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::CommandFactory;
use clap_complete::Shell;

/// The command name the man pages and completions are written for.
const BIN: &str = "vps-ready";

/// The shells to write completions for.
const SHELLS: [Shell; 3] = [Shell::Bash, Shell::Zsh, Shell::Fish];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [task, dir] if task == "gen-docs" => gen_docs(Path::new(dir)),
        _ => {
            eprintln!("usage: cargo xtask gen-docs <DIR>");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(files) => {
            for f in files {
                println!("{}", f.display());
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Writes the man pages and completions under `dir` and returns the files
/// written, sorted. Empties `dir/man` and `dir/completions` first, so stale
/// pages from a renamed subcommand don't ship.
fn gen_docs(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let man = dir.join("man");
    let completions = dir.join("completions");
    for d in [&man, &completions] {
        match std::fs::remove_dir_all(d) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        std::fs::create_dir_all(d)?;
    }

    // One page for the command and one per visible subcommand.
    clap_mangen::generate_to(vps_ready::cli::Cli::command(), &man)?;
    for shell in SHELLS {
        clap_complete::generate_to(
            shell,
            &mut vps_ready::cli::Cli::command(),
            BIN,
            &completions,
        )?;
    }

    let mut files = Vec::new();
    for d in [&man, &completions] {
        for entry in std::fs::read_dir(d)? {
            files.push(entry?.path());
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `gen_docs` into a fresh temporary directory.
    fn generate() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        gen_docs(dir.path()).unwrap();
        dir
    }

    fn visible_subcommands() -> Vec<String> {
        vps_ready::cli::Cli::command()
            .get_subcommands()
            .filter(|s| !s.is_hide_set())
            .map(|s| s.get_name().to_owned())
            .collect()
    }

    #[test]
    fn writes_a_page_per_visible_subcommand_and_each_completion() {
        let tmp = generate();
        let dir = tmp.path();
        let mut want = vec![format!("man/{BIN}.1")];
        for sub in visible_subcommands() {
            want.push(format!("man/{BIN}-{sub}.1"));
        }
        want.extend([
            format!("completions/{BIN}.bash"),
            format!("completions/_{BIN}"),
            format!("completions/{BIN}.fish"),
        ]);
        for w in &want {
            assert!(dir.join(w).is_file(), "missing {w}");
        }
    }

    #[test]
    fn removes_stale_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("man")).unwrap();
        let stale = tmp.path().join("man/vps-ready-gone.1");
        std::fs::write(&stale, "").unwrap();
        let files = gen_docs(tmp.path()).unwrap();
        assert!(!stale.exists());
        assert!(files.iter().all(|f| f.exists()));
    }

    #[test]
    fn output_matches_the_cli() {
        let tmp = generate();
        let dir = tmp.path();
        let read = |p: &str| std::fs::read_to_string(dir.join(p)).unwrap();
        let cmd = vps_ready::cli::Cli::command();

        let page = read(&format!("man/{BIN}.1"));
        assert!(page.contains(env!("CARGO_PKG_VERSION")));
        for arg in cmd.get_arguments().filter(|a| !a.is_hide_set()) {
            if let Some(long) = arg.get_long() {
                let roff = format!("\\-\\-{}", long.replace('-', "\\-"));
                assert!(page.contains(&roff), "man page lacks --{long}");
            }
        }
        for sub in visible_subcommands() {
            let link = format!("{BIN}-{sub}(1)").replace('-', "\\-");
            assert!(page.contains(&link), "no link to {sub}");
        }

        for file in [
            format!("completions/{BIN}.bash"),
            format!("completions/_{BIN}"),
            format!("completions/{BIN}.fish"),
        ] {
            let text = read(&file);
            for sub in visible_subcommands() {
                assert!(text.contains(&sub), "{file} lacks {sub}");
            }
        }
    }
}
