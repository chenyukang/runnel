use std::{collections::BTreeMap, sync::OnceLock, time::SystemTime};

use tokio::sync::broadcast;
use tracing::{Event, Subscriber};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

#[derive(Clone, Debug)]
pub struct TraceEvent {
    pub at: SystemTime,
    pub level: String,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

static TRACE_EVENTS: OnceLock<broadcast::Sender<TraceEvent>> = OnceLock::new();

pub fn init_channel(capacity: usize) {
    let _ = TRACE_EVENTS.set(broadcast::channel(capacity).0);
}

pub fn subscribe() -> Option<broadcast::Receiver<TraceEvent>> {
    TRACE_EVENTS.get().map(|sender| sender.subscribe())
}

pub fn emit(
    level: impl Into<String>,
    message: impl Into<String>,
    fields: BTreeMap<String, String>,
) {
    let Some(sender) = TRACE_EVENTS.get() else {
        return;
    };

    let traced = TraceEvent {
        at: SystemTime::now(),
        level: level.into(),
        message: message.into(),
        fields,
    };
    let _ = sender.send(traced);
}

pub fn layer() -> TelemetryLayer {
    TelemetryLayer
}

pub struct TelemetryLayer;

impl<S> Layer<S> for TelemetryLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(sender) = TRACE_EVENTS.get() else {
            return;
        };

        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);

        let mut fields = visitor.fields;
        let message = fields
            .remove("message")
            .unwrap_or_else(|| event.metadata().name().to_owned());

        let traced = TraceEvent {
            at: SystemTime::now(),
            level: event.metadata().level().as_str().to_owned(),
            message,
            fields,
        };

        let _ = sender.send(traced);
    }
}

#[derive(Default)]
struct EventVisitor {
    fields: BTreeMap<String, String>,
}

impl tracing::field::Visit for EventVisitor {
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_owned(), format!("{value:?}"));
    }
}
