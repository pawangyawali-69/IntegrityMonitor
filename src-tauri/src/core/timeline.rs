use std::collections::HashMap;
use crate::core::TimelineEvent;

pub struct TimelineEngine {
    events: Vec<TimelineEvent>,
    categories: HashMap<String, Vec<TimelineEvent>>,
}

impl TimelineEngine {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            categories: HashMap::new(),
        }
    }

    pub fn add_event(&mut self, event: TimelineEvent) {
        self.categories.entry(event.category.clone())
            .or_default()
            .push(event.clone());
        self.events.push(event);
    }

    pub fn get_events(&self, filter: Option<&str>, limit: usize) -> Vec<TimelineEvent> {
        let mut events: Vec<_> = self.events.clone();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        if let Some(f) = filter {
            let f = f.to_lowercase();
            events.retain(|e| {
                e.category.to_lowercase().contains(&f)
                    || e.event_type.to_lowercase().contains(&f)
                    || e.description.to_lowercase().contains(&f)
                    || e.source.to_lowercase().contains(&f)
            });
        }
        
        events.into_iter().take(limit).collect()
    }

    #[allow(dead_code)]
    pub fn get_events_by_category(&self, category: &str) -> Vec<TimelineEvent> {
        self.categories.get(category).cloned().unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn get_all_categories(&self) -> Vec<String> {
        self.categories.keys().cloned().collect()
    }

    #[allow(dead_code)]
    pub fn get_time_range(&self, _start: &str, _end: &str) -> Vec<TimelineEvent> {
        self.events.clone()
    }

    pub fn export_events(&self, _format: &str) -> String {
        serde_json::to_string_pretty(&self.events).unwrap_or_default()
    }
}
