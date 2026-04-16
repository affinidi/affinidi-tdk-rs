use affinidi_messaging_mediator::server::start;

#[tokio::main]
async fn main() {
    if let Err(err) = start().await {
        eprintln!("Mediator failed to start: {err}");
        std::process::exit(1);
    }
}
