#[tokio::main]
async fn main() {
    if let Err(error) = lattice_security::cli::run(std::env::args()).await {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
