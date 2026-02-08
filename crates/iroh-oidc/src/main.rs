#[tokio::main]
async fn main() -> anyhow::Result<()> {
    iroh_oidc::run().await
}
