#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sorrel_server::run().await
}
