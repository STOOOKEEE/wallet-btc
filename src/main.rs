mod bip32;
mod bip39;
mod cli;
mod hex;

fn main() -> std::io::Result<()> {
    cli::run()
}
