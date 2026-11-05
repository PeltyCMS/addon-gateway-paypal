//! PayPal gateway (Orders v2 + webhooks).
//!
//! Verified here (unit tests, offline test vectors only): webhook signature
//! verification (SHA256withRSA over
//! `"{transmission_id}|{transmission_time}|{webhook_id}|{crc32(body)}"`),
//! timestamp tolerance, event parsing, and Orders/OAuth request building.
//! NOT verified against PayPal (sandbox or live): no HTTP transport ships,
//! so `create_payment` returns a Provider error unless one is injected.
//! The signing public key is pinned by the operator (`webhook_public_key`,
//! SPKI PEM extracted from PayPal's signing cert); we never fetch
//! `paypal-cert-url`. Capture after approval and refunds are not implemented.
use base64::Engine;
use pelty_payments::http::{api_base, send_json};
use pelty_payments::*;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;
#[allow(unused_imports)]
use {
    pelty_core::money::Money,
    serde::{Deserialize, Serialize},
    std::collections::{BTreeMap, HashMap},
    std::future::Future,
    std::pin::Pin,
    std::sync::Arc,
};

pub const SANDBOX_BASE: &str = "https://api-m.sandbox.paypal.com";
pub const LIVE_BASE: &str = "https://api-m.paypal.com";
pub const DEFAULT_TOLERANCE_SECS: i64 = 300;

pub struct PaypalGateway {
    client_id: String,
    client_secret: String,
    webhook_id: String,
    key: VerifyingKey<Sha256>,
    base: String,
    tolerance: i64,
    transport: Arc<dyn HttpTransport>,
}

const SETTINGS: &[SettingField] = &[
    SettingField::of("live", "bool"),
    SettingField::of("api_base", "url"),
];

pub fn descriptor() -> GatewayDescriptor {
    GatewayDescriptor {
        id: "paypal",
        name: "PayPal",
        capabilities: Capabilities {
            checkout: true,
            webhooks: true,
            refunds: true,
            recurring: false,
        },
        secrets: &[
            "client_id",
            "client_secret",
            "webhook_id",
            "webhook_public_key",
        ],
        settings: SETTINGS,
        currencies: &[
            "AUD", "BRL", "CAD", "CNY", "CZK", "DKK", "EUR", "HKD", "HUF", "ILS", "JPY", "MYR",
            "MXN", "TWD", "NZD", "NOK", "PHP", "PLN", "GBP", "SGD", "SEK", "CHF", "THB", "USD",
        ],
    }
}

pub fn factory(cfg: &GatewayConfig) -> Result<Box<dyn PaymentGateway>, GatewayError> {
    // Sandbox unless the operator explicitly sets {"live": true}.
    let live = cfg.bool("live");
    let mut g = PaypalGateway::new(
        cfg.secret("client_id")?,
        cfg.secret("client_secret")?,
        cfg.secret("webhook_id")?,
        cfg.secret("webhook_public_key")?,
        live,
        cfg.transport.clone(),
    )?;
    g.base = api_base(&cfg.config, &g.base)?;
    Ok(Box::new(g))
}

impl PaypalGateway {
    pub fn new(
        client_id: &str,
        client_secret: &str,
        webhook_id: &str,
        public_key_pem: &str,
        live: bool,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, GatewayError> {
        let pk = RsaPublicKey::from_public_key_pem(public_key_pem.trim())
            .map_err(|_| GatewayError::Config("invalid webhook_public_key".into()))?;
        Ok(PaypalGateway {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            webhook_id: webhook_id.into(),
            key: VerifyingKey::<Sha256>::new(pk),
            base: if live { LIVE_BASE } else { SANDBOX_BASE }.to_string(),
            tolerance: DEFAULT_TOLERANCE_SECS,
            transport,
        })
    }

    pub fn token_request(&self) -> HttpRequestSpec {
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.client_id, self.client_secret));
        HttpRequestSpec {
            method: "POST",
            url: format!("{}/v1/oauth2/token", self.base),
            headers: vec![
                ("Authorization".into(), format!("Basic {basic}")),
                (
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
            ],
            body: "grant_type=client_credentials".into(),
        }
    }

    pub fn order_request(
        &self,
        token: &str,
        r: &PaymentRequest,
    ) -> Result<HttpRequestSpec, GatewayError> {
        let m = r.amount;
        let value = decimal_str(m)?;
        let body = serde_json::json!({
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": r.payment_id,
                "custom_id": r.payment_id,
                "invoice_id": r.reference,
                "description": r.description,
                "amount": {
                    "currency_code": m.currency.as_str(),
                    "value": value,
                },
            }],
            "payment_source": {"paypal": {"experience_context": {
                "return_url": r.success_url,
                "cancel_url": r.cancel_url,
                "user_action": "PAY_NOW",
            }}},
        });
        Ok(HttpRequestSpec {
            method: "POST",
            url: format!("{}/v2/checkout/orders", self.base),
            headers: vec![
                ("Authorization".into(), format!("Bearer {token}")),
                ("Content-Type".into(), "application/json".into()),
                ("PayPal-Request-Id".into(), r.idempotency_key.clone()),
            ],
            body: body.to_string(),
        })
    }

    /// Verify PayPal webhook signature headers against the pinned key.
    pub fn verify_signature(
        &self,
        headers: &Headers,
        body: &[u8],
        now: i64,
    ) -> Result<(), GatewayError> {
        let h = |k: &str| headers.get(k).ok_or(GatewayError::InvalidSignature);
        let tid = h("paypal-transmission-id")?;
        let ttime = h("paypal-transmission-time")?;
        let sig = h("paypal-transmission-sig")?;
        if let Some(a) = headers.get("paypal-auth-algo") {
            if !a.eq_ignore_ascii_case("SHA256withRSA") {
                return Err(GatewayError::InvalidSignature);
            }
        }
        let ts = time::OffsetDateTime::parse(ttime, &time::format_description::well_known::Rfc3339)
            .map_err(|_| GatewayError::InvalidSignature)?
            .unix_timestamp();
        if (now - ts).abs() > self.tolerance {
            return Err(GatewayError::InvalidSignature);
        }
        let msg = format!(
            "{tid}|{ttime}|{}|{}",
            self.webhook_id,
            crc32fast::hash(body)
        );
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sig.trim())
            .map_err(|_| GatewayError::InvalidSignature)?;
        let s = Signature::try_from(raw.as_slice()).map_err(|_| GatewayError::InvalidSignature)?;
        self.key
            .verify(msg.as_bytes(), &s)
            .map_err(|_| GatewayError::InvalidSignature)
    }

    fn bearer(&self, token: &str, idem: Option<&str>) -> Vec<(String, String)> {
        let mut h = vec![
            ("Authorization".into(), format!("Bearer {token}")),
            ("Content-Type".into(), "application/json".into()),
        ];
        if let Some(k) = idem {
            h.push(("PayPal-Request-Id".into(), k.into()));
        }
        h
    }

    async fn token(&self) -> Result<String, GatewayError> {
        let t = send_json(self.transport.as_ref(), self.token_request()).await?;
        t["access_token"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| GatewayError::Provider("missing access_token".into()))
    }

    pub fn capture_request(&self, token: &str, order_id: &str) -> HttpRequestSpec {
        HttpRequestSpec {
            method: "POST",
            url: format!(
                "{}/v2/checkout/orders/{}/capture",
                self.base,
                pelty_payments::http::url_encode(order_id)
            ),
            headers: self.bearer(token, Some(&format!("capture-{order_id}"))),
            body: "{}".into(),
        }
    }

    fn order_get(&self, token: &str, order_id: &str) -> HttpRequestSpec {
        HttpRequestSpec {
            method: "GET",
            url: format!(
                "{}/v2/checkout/orders/{}",
                self.base,
                pelty_payments::http::url_encode(order_id)
            ),
            headers: self.bearer(token, None),
            body: String::new(),
        }
    }
}

fn first_capture(v: &serde_json::Value) -> &serde_json::Value {
    &v["purchase_units"][0]["payments"]["captures"][0]
}

impl PaymentGateway for PaypalGateway {
    fn id(&self) -> &'static str {
        "paypal"
    }
    fn display_name(&self) -> &'static str {
        "PayPal"
    }
    fn capabilities(&self) -> Capabilities {
        descriptor().capabilities
    }
    fn create_payment<'a>(
        &'a self,
        req: &'a PaymentRequest,
    ) -> BoxFuture<'a, Result<PaymentInit, GatewayError>> {
        Box::pin(async move {
            let token = self.token().await?;
            let v = send_json(self.transport.as_ref(), self.order_request(&token, req)?).await?;
            let id = v["id"]
                .as_str()
                .ok_or_else(|| GatewayError::Provider("missing id".into()))?;
            let url = v["links"]
                .as_array()
                .and_then(|l| {
                    l.iter().find(|x| {
                        matches!(x["rel"].as_str(), Some("payer-action") | Some("approve"))
                    })
                })
                .and_then(|x| x["href"].as_str())
                .ok_or_else(|| GatewayError::Provider("missing approval link".into()))?;
            Ok(PaymentInit::Redirect {
                url: url.into(),
                provider_ref: id.into(),
            })
        })
    }
    fn parse_webhook(
        &self,
        headers: &Headers,
        body: &[u8],
        now: i64,
    ) -> Result<WebhookEvent, GatewayError> {
        self.verify_signature(headers, body, now)?;
        let v: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| GatewayError::MalformedPayload)?;
        let event_id = v["id"]
            .as_str()
            .ok_or(GatewayError::MalformedPayload)?
            .to_string();
        let event_type = v["event_type"]
            .as_str()
            .ok_or(GatewayError::MalformedPayload)?
            .to_string();
        let res = &v["resource"];
        let kind = match event_type.as_str() {
            "PAYMENT.CAPTURE.COMPLETED" => WebhookKind::PaymentSucceeded,
            "PAYMENT.CAPTURE.DENIED" | "PAYMENT.CAPTURE.DECLINED" => WebhookKind::PaymentFailed,
            "PAYMENT.CAPTURE.REFUNDED" => WebhookKind::Refunded,
            _ => WebhookKind::Ignored,
        };
        // Our provider_ref is the PayPal order id.
        let provider_ref = res["supplementary_data"]["related_ids"]["order_id"]
            .as_str()
            .or_else(|| {
                if event_type.starts_with("CHECKOUT.ORDER.") {
                    res["id"].as_str()
                } else {
                    None
                }
            })
            .map(str::to_string);
        let mut e = WebhookEvent::new(event_id, event_type, kind, provider_ref);
        e.payment_id = res["custom_id"].as_str().map(str::to_string);
        Ok(e)
    }
    fn complete_payment<'a>(
        &'a self,
        order_id: &'a str,
        _q: &'a HashMap<String, String>,
    ) -> BoxFuture<'a, Result<CompleteStatus, GatewayError>> {
        Box::pin(async move {
            let token = self.token().await?;
            let v = match send_json(
                self.transport.as_ref(),
                self.capture_request(&token, order_id),
            )
            .await
            {
                Ok(v) => v,
                // Already captured (webhook or retry): read the order instead.
                Err(GatewayError::Provider(m))
                    if m.contains("ORDER_ALREADY_CAPTURED") || m.starts_with("HTTP 422") =>
                {
                    send_json(self.transport.as_ref(), self.order_get(&token, order_id)).await?
                }
                Err(e) => return Err(e),
            };
            let cap = first_capture(&v)["status"].as_str().unwrap_or_default();
            Ok(match (v["status"].as_str(), cap) {
                (_, "COMPLETED") => CompleteStatus::Succeeded,
                (_, "DECLINED") | (_, "FAILED") | (Some("VOIDED"), _) => CompleteStatus::Failed,
                _ => CompleteStatus::Pending,
            })
        })
    }
    fn refund<'a>(
        &'a self,
        provider_ref: &'a str,
        amount: Money,
        idem: &'a str,
    ) -> BoxFuture<'a, Result<RefundResult, GatewayError>> {
        Box::pin(async move {
            let token = self.token().await?;
            // Our provider_ref is the order id; refunds go to its capture.
            let capture_id = if provider_ref.starts_with("CAP-") {
                provider_ref.to_string()
            } else {
                let o = send_json(
                    self.transport.as_ref(),
                    self.order_get(&token, provider_ref),
                )
                .await?;
                first_capture(&o)["id"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| GatewayError::Provider("order has no capture".into()))?
            };
            let body = serde_json::json!({
                "amount": {"value": decimal_str(amount)?, "currency_code": amount.currency.as_str()},
            });
            let v = send_json(
                self.transport.as_ref(),
                HttpRequestSpec {
                    method: "POST",
                    url: format!(
                        "{}/v2/payments/captures/{}/refund",
                        self.base,
                        pelty_payments::http::url_encode(&capture_id)
                    ),
                    headers: self.bearer(&token, Some(idem)),
                    body: body.to_string(),
                },
            )
            .await?;
            let status = match v["status"].as_str() {
                Some("COMPLETED") => "succeeded",
                Some("CANCELLED") => "canceled",
                Some("FAILED") => "failed",
                _ => "pending",
            };
            Ok(RefundResult {
                provider_ref: v["id"].as_str().map(str::to_string),
                status: status.into(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pelty_core::money::{Currency, Money};
    use rust_decimal::Decimal;
    use std::str::FromStr;

    // Offline test vector: key pair generated locally with openssl, NOT a
    // PayPal key. Signed message: "TX-1|2026-10-29T10:00:00Z|WH-ID-1|604322261".
    pub(super) const PUB: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6k6vIONntvAnjDOo9YHo
CacY6EXBL3JB9fUDHB+dxl2smxxmmheJighETcvUdeKL1p7JvRy7ksuqzuGbk5j9
Q3SU1k7uklFH6s20URd3AwgV4F9480X6twPtAkgLQGr8ebGVLT+ZswtGTKb+33wa
jKwTQKAq4K8cpMYBsOkU1zc8Kb+x2E2yNcbIMxAs+Q0EGHxxmTq7DEsBhmKwf2MW
HkvHk3N9s4Y5dA/0mBUuRLUHMuoxq8nzVomTkicK+a2fccNAlqYax66y4X0SrWsg
LMnhc67h+hqrhTQcTy8cApJF+Yeu/M37RRg/zmOSu5z5JkK8EgRzVNsgwO6eOpOE
rQIDAQAB
-----END PUBLIC KEY-----";
    const SIG: &str = "zTz+HRhrBYgqczHLaUIijQ0V8QqeV/T2EENWIQeQUeyvD2T9sM0xDBqnmyw0E9H0YyxEv8M0qmHhchW0im0i6xQEewkMD5VFBx6Fhqof04764gJt92C743T41XQHjUqRtdRYgE97BX/RhMezMxK9VkHbouaZPPE7XLgaQQcECTnH1uNHOaaiOH+vYp3HinznGb1mf7PnVXta4lAOlRbZhBtGkheHeO/pMYN2yJN2b+D9a/zRC/PGqupLfPsO+JQMtUfhQfBAI/kzwZIidp4VftKQJKjM0HHmcQ9yQHTExM7jNcWo5PcHnrK7DV+NX5AmiBcRC0qGtjBxi+qcLiYQ8w==";
    const BODY: &str = r#"{"id":"WH-TEST-1","event_type":"PAYMENT.CAPTURE.COMPLETED","resource":{"id":"CAP-1","supplementary_data":{"related_ids":{"order_id":"ORDER-1"}}}}"#;
    const NOW: i64 = 1793268000;

    fn gw() -> PaypalGateway {
        PaypalGateway::new("cid", "csec", "WH-ID-1", PUB, false, Arc::new(NoTransport)).unwrap()
    }
    fn hdrs(sig: &str, time: &str) -> Headers {
        [
            ("paypal-transmission-id", "TX-1"),
            ("paypal-transmission-time", time),
            ("paypal-transmission-sig", sig),
            ("paypal-auth-algo", "SHA256withRSA"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    #[test]
    fn crc32_standard_check_value() {
        assert_eq!(crc32fast::hash(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32fast::hash(BODY.as_bytes()), 604322261);
    }

    #[test]
    fn known_vector_passes_and_parses() {
        let e = gw()
            .parse_webhook(
                &hdrs(SIG, "2026-10-29T10:00:00Z"),
                BODY.as_bytes(),
                NOW + 10,
            )
            .unwrap();
        assert_eq!(e.event_id, "WH-TEST-1");
        assert_eq!(e.kind, WebhookKind::PaymentSucceeded);
        assert_eq!(e.provider_ref.as_deref(), Some("ORDER-1"));
    }

    #[test]
    fn tampering_replay_and_wrong_webhook_id_rejected() {
        let g = gw();
        let h = hdrs(SIG, "2026-10-29T10:00:00Z");
        let tampered = BODY.replace("CAP-1", "CAP-2");
        assert_eq!(
            g.parse_webhook(&h, tampered.as_bytes(), NOW),
            Err(GatewayError::InvalidSignature)
        );
        assert_eq!(
            g.parse_webhook(&h, BODY.as_bytes(), NOW + 301),
            Err(GatewayError::InvalidSignature)
        );
        let other =
            PaypalGateway::new("c", "s", "WH-OTHER", PUB, false, Arc::new(NoTransport)).unwrap();
        assert_eq!(
            other.parse_webhook(&h, BODY.as_bytes(), NOW),
            Err(GatewayError::InvalidSignature)
        );
        let mut bad_algo = h.clone();
        bad_algo.insert("paypal-auth-algo".into(), "SHA1withRSA".into());
        assert!(g.parse_webhook(&bad_algo, BODY.as_bytes(), NOW).is_err());
        let mut missing = h;
        missing.remove("paypal-transmission-sig");
        assert!(g.parse_webhook(&missing, BODY.as_bytes(), NOW).is_err());
    }

    #[test]
    fn invalid_key_is_config_error() {
        assert!(matches!(
            PaypalGateway::new("c", "s", "w", "nope", false, Arc::new(NoTransport)),
            Err(GatewayError::Config(_))
        ));
    }

    #[test]
    fn builds_sandbox_requests_with_exact_decimal() {
        let g = gw();
        assert_eq!(
            g.token_request().url,
            "https://api-m.sandbox.paypal.com/v1/oauth2/token"
        );
        let r = PaymentRequest {
            payment_id: "pay_1".into(),
            reference: "INV-7".into(),
            amount: Money::new(
                Decimal::from_str("12.50").unwrap(),
                Currency::parse("EUR").unwrap(),
            ),
            description: "Invoice INV-7".into(),
            customer_email: None,
            success_url: "https://panel.example/ok".into(),
            cancel_url: "https://panel.example/cancel".into(),
            webhook_url: String::new(),
            idempotency_key: "idem-1".into(),
        };
        let s = g.order_request("tok", &r).unwrap();
        assert_eq!(s.url, "https://api-m.sandbox.paypal.com/v2/checkout/orders");
        let v: serde_json::Value = serde_json::from_str(&s.body).unwrap();
        assert_eq!(v["purchase_units"][0]["amount"]["value"], "12.50");
        assert_eq!(v["purchase_units"][0]["amount"]["currency_code"], "EUR");
        assert!(s
            .headers
            .contains(&("PayPal-Request-Id".into(), "idem-1".into())));
    }
}

#[cfg(test)]
mod flow_tests {
    use super::*;
    use pelty_payments::test_util::*;

    fn g(t: &MockTransport) -> PaypalGateway {
        PaypalGateway::new("cid", "csec", "WH", tests_pub(), false, Arc::new(t.clone())).unwrap()
    }
    fn tests_pub() -> &'static str {
        super::tests::PUB
    }

    #[tokio::test]
    async fn create_capture_refund_flow() {
        let t = MockTransport::new();
        let tok = r#"{"access_token":"A21","expires_in":300}"#;
        t.push(200, tok).push(201, r#"{"id":"ORDER-9","status":"PAYER_ACTION_REQUIRED","links":[{"rel":"self","href":"x"},{"rel":"payer-action","href":"https://www.sandbox.paypal.com/checkoutnow?token=ORDER-9"}]}"#);
        let gw = g(&t);
        let init = gw.create_payment(&req("12.50", "EUR")).await.unwrap();
        assert_eq!(
            init,
            PaymentInit::Redirect {
                url: "https://www.sandbox.paypal.com/checkoutnow?token=ORDER-9".into(),
                provider_ref: "ORDER-9".into()
            }
        );

        t.push(200, tok).push(201, r#"{"id":"ORDER-9","status":"COMPLETED","purchase_units":[{"payments":{"captures":[{"id":"CAP-7","status":"COMPLETED"}]}}]}"#);
        assert_eq!(
            gw.complete_payment("ORDER-9", &HashMap::new())
                .await
                .unwrap(),
            CompleteStatus::Succeeded
        );

        // Retried capture: 422 → read the order.
        t.push(200, tok).push(422, r#"{"name":"UNPROCESSABLE_ENTITY","message":"ORDER_ALREADY_CAPTURED"}"#)
            .push(200, r#"{"id":"ORDER-9","status":"COMPLETED","purchase_units":[{"payments":{"captures":[{"id":"CAP-7","status":"COMPLETED"}]}}]}"#);
        assert_eq!(
            gw.complete_payment("ORDER-9", &HashMap::new())
                .await
                .unwrap(),
            CompleteStatus::Succeeded
        );

        t.push(200, tok).push(200, r#"{"id":"ORDER-9","purchase_units":[{"payments":{"captures":[{"id":"CAP-7","status":"COMPLETED"}]}}]}"#)
            .push(201, r#"{"id":"RF-1","status":"COMPLETED"}"#);
        let r = gw
            .refund("ORDER-9", money("2.5", "EUR"), "rk")
            .await
            .unwrap();
        assert_eq!(
            r,
            RefundResult {
                provider_ref: Some("RF-1".into()),
                status: "succeeded".into()
            }
        );

        let sent = t.requests();
        assert!(
            sent.iter().all(|r| r.url.starts_with(SANDBOX_BASE)),
            "never live"
        );
        assert_eq!(sent[0].header("authorization"), Some("Basic Y2lkOmNzZWM="));
        assert!(sent[3].url.ends_with("/v2/checkout/orders/ORDER-9/capture"));
        let last = sent.last().unwrap();
        assert!(last.url.ends_with("/v2/payments/captures/CAP-7/refund"));
        assert_eq!(last.header("paypal-request-id"), Some("rk"));
        let v: serde_json::Value = serde_json::from_str(&last.body).unwrap();
        assert_eq!(v["amount"]["value"], "2.50");
    }

    #[tokio::test]
    async fn declined_capture_is_failed() {
        let t = MockTransport::new();
        t.push(200, r#"{"access_token":"A"}"#).push(201, r#"{"status":"COMPLETED","purchase_units":[{"payments":{"captures":[{"id":"CAP-1","status":"DECLINED"}]}}]}"#);
        assert_eq!(
            g(&t).complete_payment("O", &HashMap::new()).await.unwrap(),
            CompleteStatus::Failed
        );
    }
}
