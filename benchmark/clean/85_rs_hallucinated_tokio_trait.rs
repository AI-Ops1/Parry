use async_trait::async_trait;
#[async_trait]
trait Runner { async fn exec(&self); }
