use async_trait::async_trait;

#[async_trait]
pub trait Worker {
    async fn run(&self);
}
