#![allow(dead_code, unused_imports)]
//! Real HTTP (reqwest) against a local axum mock server on 127.0.0.1; no
//! provider is ever contacted.
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use pelty_core::money::{Currency, Money};
use pelty_payments::*;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

type Log = Arc<Mutex<Vec<(String, String, String)>>>;

async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

fn req() -> PaymentRequest {
    PaymentRequest {
        payment_id: "p-1".into(),
        reference: "INV-1".into(),
        amount: Money::new(
            rust_decimal::Decimal::from_str("19.99").unwrap(),
            Currency::parse("EUR").unwrap(),
        ),
        description: "Hosting".into(),
        customer_email: None,
        success_url: "https://panel.example/ok".into(),
        cancel_url: "https://panel.example/no".into(),
        webhook_url: "https://panel.example/api/v1/webhooks/x".into(),
        idempotency_key: "idem-9".into(),
    }
}

fn reg() -> GatewayRegistry {
    let mut r = GatewayRegistry::with_transport(Arc::new(ReqwestTransport::new().unwrap()));
    r.register(
        pelty_addon_gateway_paypal::paypal::descriptor(),
        pelty_addon_gateway_paypal::paypal::factory,
    );
    r
}

#[tokio::test]
async fn paypal_order_capture_refund_over_http() {
    let app = Router::new()
        .route("/v1/oauth2/token", post(|| async { Json(json!({"access_token": "TOK"})) }))
        .route("/v2/checkout/orders", post(|h: HeaderMap, Json(b): Json<Value>| async move {
            assert_eq!(h["authorization"], "Bearer TOK");
            assert_eq!(b["purchase_units"][0]["amount"]["value"], "19.99");
            Json(json!({"id": "O1", "links": [{"rel": "payer-action", "href": "https://approve.example/O1"}]}))
        }))
        .route("/v2/checkout/orders/{id}/capture", post(|| async {
            (axum::http::StatusCode::CREATED, Json(json!({"status": "COMPLETED", "purchase_units": [{"payments": {"captures": [{"id": "CAP-1", "status": "COMPLETED"}]}}]})))
        }))
        .route("/v2/checkout/orders/{id}", get(|| async {
            Json(json!({"purchase_units": [{"payments": {"captures": [{"id": "CAP-1", "status": "COMPLETED"}]}}]}))
        }))
        .route("/v2/payments/captures/{id}/refund", post(|Path(id): Path<String>| async move {
            assert_eq!(id, "CAP-1");
            Json(json!({"id": "RF1", "status": "COMPLETED"}))
        }));
    let base = serve(app).await;
    let pubkey = include_str!("../src/paypal.rs")
        .split("PUB: &str = \"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();
    let cfg = GatewayConfig {
        config: json!({"api_base": base}),
        secrets: [
            ("client_id", "c"),
            ("client_secret", "s"),
            ("webhook_id", "w"),
            ("webhook_public_key", pubkey.as_str()),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        ..Default::default()
    };
    let gw = reg().build("paypal", &cfg).unwrap();
    assert_eq!(
        gw.create_payment(&req()).await.unwrap(),
        PaymentInit::Redirect {
            url: "https://approve.example/O1".into(),
            provider_ref: "O1".into()
        }
    );
    assert_eq!(
        gw.complete_payment("O1", &Default::default())
            .await
            .unwrap(),
        CompleteStatus::Succeeded
    );
    let r = gw
        .refund(
            "O1",
            Money::new(
                rust_decimal::Decimal::new(1999, 2),
                Currency::parse("EUR").unwrap(),
            ),
            "k",
        )
        .await
        .unwrap();
    assert_eq!(
        r,
        RefundResult {
            provider_ref: Some("RF1".into()),
            status: "succeeded".into()
        }
    );
}
