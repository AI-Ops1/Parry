use tokio::time::{sleep, Duration};

pub async fn background_heartbeat() {
    sleep(Duration::from_millis(500)).await;
}
