//! Bridges Rust `tracing` events to the App's event listener as Go-style
//! `{type:"log", data:{type,payload}}` messages, mirroring core/log.go's pump.

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::json;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

static LOG_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn start() {
    LOG_ENABLED.store(true, Ordering::Relaxed);
}

pub fn stop() {
    LOG_ENABLED.store(false, Ordering::Relaxed);
}

pub fn is_enabled() -> bool {
    LOG_ENABLED.load(Ordering::Relaxed)
}

struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }
}

pub struct AppLogLayer;

impl<S: Subscriber> Layer<S> for AppLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if !is_enabled() {
            return;
        }
        let mut visitor = MessageVisitor { message: String::new() };
        event.record(&mut visitor);
        let level = match *event.metadata().level() {
            Level::ERROR => "error",
            Level::WARN => "warning",
            Level::INFO => "info",
            Level::DEBUG => "debug",
            Level::TRACE => "trace",
        };
        // Match the App's Log model: LogLevel / Payload / dateTime.
        crate::jni::emit_event_json(&json!({
            "type": "log",
            "data": { "LogLevel": level, "Payload": visitor.message, "dateTime": "" }
        }).to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggles_state() {
        let before = is_enabled();
        start();
        assert!(is_enabled());
        stop();
        assert!(!is_enabled());
        if before { start(); }
    }
}
