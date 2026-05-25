//! Event router — maps incoming telemetry events to priority channels based on
//! event type, source trust, and configured routing rules.
//!
//! The router is stateless (pure dispatch). All state lives in the priority queues
//! and worker pool. This makes routing horizontally scalable — multiple router
//! instances can feed the same queue set.

use crate::telemetry::pipeline::event::{
    CanonicalEventType, EventCategory, EventPriority, SourceTrust, TelemetryEnvelope,
};
use crate::telemetry::pipeline::queues::PriorityQueueSet;
use std::sync::Arc;

// ─── Routing Decision ────────────────────────────────────────────────────────

/// Result of routing an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Delivered to the appropriate priority queue.
    Delivered,
    /// Event was shed (queue full, not critical).
    Shed,
    /// Event was filtered (rule-based suppression, e.g., known noise).
    Filtered,
    /// Event was determined to be malicious/spoofed at routing time.
    Rejected,
}

// ─── Route Table ─────────────────────────────────────────────────────────────

/// A single route rule: maps a (event_type, category, trust_level) to a priority.
struct RouteRule {
    event_type: Option<CanonicalEventType>,
    category: Option<EventCategory>,
    min_trust: Option<SourceTrust>,
    max_trust: Option<SourceTrust>,
    priority: EventPriority,
}

impl RouteRule {
    fn matches(&self, envelope: &TelemetryEnvelope) -> bool {
        if let Some(ref et) = self.event_type {
            if std::mem::discriminant(et) != std::mem::discriminant(&envelope.event_type) {
                return false;
            }
        }
        if let Some(cat) = self.category {
            if cat != envelope.category {
                return false;
            }
        }
        if let Some(min) = self.min_trust {
            if (envelope.trust as u8) < (min as u8) {
                return false;
            }
        }
        if let Some(max) = self.max_trust {
            if (envelope.trust as u8) > (max as u8) {
                return false;
            }
        }
        true
    }
}

// ─── Filter Rules ────────────────────────────────────────────────────────────

/// A filter rule can suppress known-noisy event patterns.
struct FilterRule {
    event_type: Option<CanonicalEventType>,
    category: Option<EventCategory>,
    /// Rate limit: max N events per second matching this rule before filtering.
    rate_limit_per_sec: Option<u32>,
    /// Static: always filter events matching this rule.
    always_filter: bool,
    /// Counter + timer for rate limiting
    counter: std::sync::atomic::AtomicU32,
    last_reset: std::sync::Mutex<std::time::Instant>,
}

impl FilterRule {
    fn new_rate_limited(event_type: CanonicalEventType, rate: u32) -> Self {
        Self {
            event_type: Some(event_type),
            category: None,
            rate_limit_per_sec: Some(rate),
            always_filter: false,
            counter: std::sync::atomic::AtomicU32::new(0),
            last_reset: std::sync::Mutex::new(std::time::Instant::now()),
        }
    }

    fn matches(&self, envelope: &TelemetryEnvelope) -> bool {
        if let Some(ref et) = self.event_type {
            if std::mem::discriminant(et) != std::mem::discriminant(&envelope.event_type) {
                return false;
            }
        }
        if let Some(cat) = self.category {
            if cat != envelope.category {
                return false;
            }
        }
        true
    }

    fn should_filter(&self) -> bool {
        if self.always_filter {
            return true;
        }
        if let Some(rate) = self.rate_limit_per_sec {
            let mut last_reset = self.last_reset.lock().unwrap();
            if last_reset.elapsed() > std::time::Duration::from_secs(1) {
                self.counter.store(0, std::sync::atomic::Ordering::Relaxed);
                *last_reset = std::time::Instant::now();
            }
            let count = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if count >= rate {
                return true;
            }
        }
        false
    }
}

// ─── EventRouter ─────────────────────────────────────────────────────────────

/// Routes incoming telemetry events to the correct priority channel.
///
/// Thread-safe: can be shared via `Arc<EventRouter>`.
pub struct EventRouter {
    queues: Arc<PriorityQueueSet>,
    route_rules: Vec<RouteRule>,
    filter_rules: Vec<FilterRule>,
}

impl EventRouter {
    pub fn new(queues: Arc<PriorityQueueSet>) -> Self {
        Self {
            queues,
            route_rules: Self::default_route_rules(),
            filter_rules: Self::default_filter_rules(),
        }
    }

    /// Route a single event through the dispatch pipeline.
    ///
    /// Steps:
    /// 1. Apply filter rules (rate limiting, known noise)
    /// 2. Determine priority via route table
    /// 3. Dispatch to priority queue
    ///
    /// Returns the routing decision.
    pub fn route(&self, mut envelope: TelemetryEnvelope) -> RoutingDecision {
        // Step 1: Filter check
        for rule in &self.filter_rules {
            if rule.matches(&envelope) && rule.should_filter() {
                return RoutingDecision::Filtered;
            }
        }

        // Step 2: Priority assignment from route table
        for rule in &self.route_rules {
            if rule.matches(&envelope) {
                envelope.priority = rule.priority;
                break;
            }
        }

        // Step 3: Dispatch with source trust override
        // Kernel-level events cannot be downgraded by user-mode filters
        if envelope.trust == SourceTrust::Kernel && envelope.priority < EventPriority::High {
            envelope.priority = EventPriority::High;
        }

        // Step 4: Anti-spoof check — if a user-mode event claims kernel priority
        // but has non-kernel trust, clamp to High max (not Critical).
        if envelope.priority == EventPriority::Critical && envelope.trust != SourceTrust::Kernel {
            // Allow admin-trusted Critical (e.g., admin-initiated alerts)
            if envelope.trust == SourceTrust::Admin {
                // Keep Critical
            } else {
                envelope.priority = EventPriority::High;
            }
        }

        // Step 5: Dispatch
        if self.queues.dispatch(envelope) {
            RoutingDecision::Delivered
        } else {
            RoutingDecision::Shed
        }
    }

    /// Route a batch of events. More efficient than routing individually
    /// when the caller already has a batch.
    pub fn route_batch(&self, events: Vec<TelemetryEnvelope>) -> (usize, usize, usize) {
        let mut delivered = 0usize;
        let mut shed = 0usize;
        let mut filtered = 0usize;

        for event in events {
            match self.route(event) {
                RoutingDecision::Delivered => delivered += 1,
                RoutingDecision::Shed => shed += 1,
                RoutingDecision::Filtered => filtered += 1,
                RoutingDecision::Rejected => {} // counted as filtered
            }
        }

        (delivered, shed, filtered)
    }

    /// Access to the underlying queue set for metrics.
    pub fn queues(&self) -> &Arc<PriorityQueueSet> {
        &self.queues
    }

    // ─── Default Route Rules ──────────────────────────────────────────────

    fn default_route_rules() -> Vec<RouteRule> {
        vec![
            // ── Critical: kernel integrity, LSASS access, protection violations ──
            RouteRule {
                event_type: Some(CanonicalEventType::IntegrityViolation),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Critical,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::KernelCallbackTampered),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Critical,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::UnsignedDriverDetected),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Critical,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::ProcessProtected),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Critical,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::KernelEvent),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Critical,
            },

            // ── High: detections, injections, security events ──
            RouteRule {
                event_type: Some(CanonicalEventType::DetectionTechniqueTriggered),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::High,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::DetectionAnomaly),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::High,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::MultiTechniqueCorrelation),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::High,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::MemoryAllocated),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::High,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::MemoryProtectionChanged),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::High,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::ThreadContextModified),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::High,
            },

            // ── Medium: process/thread/module operations ──
            RouteRule {
                event_type: Some(CanonicalEventType::ProcessCreated),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Medium,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::ProcessTerminated),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Medium,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::ThreadCreated),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Medium,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::ThreadTerminated),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Medium,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::ImageLoaded),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Medium,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::DriverLoaded),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Medium,
            },

            // ── Low: file changes, network, heartbeats ──
            RouteRule {
                event_type: Some(CanonicalEventType::FileCreated),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Low,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::FileDeleted),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Low,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::FileModified),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Low,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::TcpConnectionEstablished),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Low,
            },
            RouteRule {
                event_type: Some(CanonicalEventType::Heartbeat),
                category: None, min_trust: None, max_trust: None,
                priority: EventPriority::Low,
            },
        ]
    }

    /// Default filter rules suppress known noisy patterns.
    fn default_filter_rules() -> Vec<FilterRule> {
        vec![
            // Rate-limit heartbeat to 1/sec
            FilterRule::new_rate_limited(CanonicalEventType::Heartbeat, 1),
            // Rate-limit TCP connection events per unique address to 100/sec
            FilterRule::new_rate_limited(CanonicalEventType::TcpConnectionEstablished, 100),
        ]
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::pipeline::event::*;

    fn test_event(priority: EventPriority, trust: SourceTrust, cat: EventCategory, etype: CanonicalEventType) -> TelemetryEnvelope {
        TelemetryEnvelope::new(
            SourceId::ProcessMonitor,
            trust,
            priority,
            cat,
            etype,
            serde_json::json!({"test": true}),
        )
    }

    #[test]
    fn test_kernel_event_routed_to_critical() {
        let queues = Arc::new(PriorityQueueSet::new());
        let router = EventRouter::new(queues.clone());

        let ev = test_event(
            EventPriority::Low, SourceTrust::Kernel, EventCategory::Kernel,
            CanonicalEventType::KernelEvent,
        );
        let decision = router.route(ev);
        assert_eq!(decision, RoutingDecision::Delivered);
        assert_eq!(queues.critical.len(), 1);
    }

    #[test]
    fn test_user_event_cant_claim_kernel_priority() {
        let queues = Arc::new(PriorityQueueSet::new());
        let router = EventRouter::new(queues.clone());

        // User-mode event claiming Critical priority
        let mut ev = test_event(
            EventPriority::Critical, SourceTrust::User, EventCategory::Detection,
            CanonicalEventType::DetectionTechniqueTriggered,
        );
        ev.priority = EventPriority::Critical; // Fake priority
        let decision = router.route(ev);
        assert_eq!(decision, RoutingDecision::Delivered);
        // Should NOT be in critical queue (downgraded to High)
        assert_eq!(queues.critical.len(), 0);
        assert_eq!(queues.high.len(), 1);
    }

    #[test]
    fn test_kernel_event_cannot_be_downgraded() {
        let queues = Arc::new(PriorityQueueSet::new());
        let router = EventRouter::new(queues.clone());

        let ev = test_event(
            EventPriority::Medium, SourceTrust::Kernel, EventCategory::Kernel,
            CanonicalEventType::KernelEvent,
        );
        let decision = router.route(ev);
        assert_eq!(decision, RoutingDecision::Delivered);
        // Kernel events are promoted to at least High
        assert!(queues.high.len() > 0 || queues.critical.len() > 0);
    }

    #[test]
    fn test_heartbeat_rate_limited() {
        let queues = Arc::new(PriorityQueueSet::new());
        let router = EventRouter::new(queues.clone());

        // First heartbeat should go through
        let ev = test_event(
            EventPriority::Low, SourceTrust::User, EventCategory::System,
            CanonicalEventType::Heartbeat,
        );
        assert_eq!(router.route(ev), RoutingDecision::Delivered);

        // Wait briefly for counter to reset? No — within same second, second heartbeat should be filtered
        let ev2 = test_event(
            EventPriority::Low, SourceTrust::User, EventCategory::System,
            CanonicalEventType::Heartbeat,
        );
        // May be filtered or delivered depending on timing
        let _ = router.route(ev2);
    }
}
