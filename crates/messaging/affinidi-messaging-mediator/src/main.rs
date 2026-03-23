use affinidi_messaging_mediator::server::start;

#[tokio::main]
async fn main() {
    return start().await;
}
