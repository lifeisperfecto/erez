use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::get,
};
use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub async fn serve(
    addr: SocketAddr,
    registry: Registry,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(Arc::new(registry));
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics listener: {addr}"))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { token.cancelled().await })
        .await
        .context("failed serving metrics")
}

async fn metrics_handler(
    State(registry): State<Arc<Registry>>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut body = String::new();
    if let Err(error) = encode(&mut body, &registry) {
        warn!(%error, "failed encoding prometheus metrics");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok((
        [(
            CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        body,
    ))
}
