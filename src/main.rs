mod bip32;
mod bip39;
mod cli;

fn main() -> std::io::Result<()> {
    cli::run()
}
