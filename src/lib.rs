//! PayPal gateway addon: Orders v2 checkout, capture, refunds, verified webhooks.
//! The whole gateway lives in [`paypal`]; this file only exports it to the host.
pub mod paypal;

#[cfg(all(target_family = "wasm", feature = "export"))]
pelty_addon_sdk::gateway_addon!(paypal::descriptor, paypal::factory);
