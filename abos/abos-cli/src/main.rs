//! `abos` binary — thin wrapper around the `abos-cli` library.

fn main() {
    std::process::exit(abos_cli::run());
}
