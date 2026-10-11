//! The `vps-ready` command. All logic lives in the library, so the
//! `vpsready` alias crate can ship the same command.

fn main() -> std::process::ExitCode {
    vps_ready::cli::main()
}
