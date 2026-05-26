use crate::core::{SuspicionScore, SuspicionCategory};
use std::collections::HashMap;

/// Bayesian scorer that combines indicator probabilities with temporal decay
/// and graph-based propagation. Formula:
/// P = 1 - Π(1 - P_i * decay(t_i)) where each P_i is the base probability
/// of an indicator and decay(t) = 2^(-age / half_life).
pub struct BayesianScorer {
    indicators: HashMap<String, IndicatorDef>,
    half_life_secs: f64,
    threshold_low: f64,
    threshold_medium: f64,
    threshold_high: f64,
}

struct IndicatorDef {
    category: &'static str,
    base_prob: f64,
    description: &'static str,
}

impl BayesianScorer {
    pub fn new(half_life_secs: f64) -> Self {
        let mut indicators = HashMap::new();
        for ind in Self::default_indicators() {
            indicators.insert(ind.0.to_string(), IndicatorDef {
                category: ind.1,
                base_prob: ind.2,
                description: ind.3,
            });
        }
        Self {
            indicators,
            half_life_secs,
            threshold_low: 0.2,
            threshold_medium: 0.45,
            threshold_high: 0.75,
        }
    }

    fn default_indicators() -> Vec<(&'static str, &'static str, f64, &'static str)> {
        vec![
            ("unsigned_dll", "unsigned_modules", 0.35, "Unsigned DLL loaded"),
            ("unsigned_driver", "unsigned_modules", 0.55, "Unsigned driver loaded"),
            ("hidden_process", "process_behavior", 0.75, "Hidden process detected"),
            ("suspicious_parent", "process_behavior", 0.25, "Suspicious parent-child relationship"),
            ("remote_thread", "process_behavior", 0.65, "Remote thread detected"),
            ("deleted_executable", "file_activity", 0.45, "Executable deleted after execution"),
            ("cleanup_script", "file_activity", 0.55, "Cleanup script detected"),
            ("timestamp_anomaly", "file_activity", 0.25, "Timestamp modification detected"),
            ("injected_dll", "emulator_integrity", 0.65, "DLL injected into emulator"),
            ("suspicious_overlay", "emulator_integrity", 0.55, "Suspicious overlay detected"),
            ("modified_emulator_file", "emulator_integrity", 0.45, "Emulator files modified"),
            ("suspicious_memory", "memory_integrity", 0.45, "Suspicious memory permissions"),
            ("injected_code", "memory_integrity", 0.75, "Code injection detected"),
            ("high_detection_risk", "detection_engine", 0.85, "High overall detection risk"),
            ("multiple_techniques_detected", "detection_engine", 0.65, "Multiple detection techniques triggered"),
            ("high_bypass_risk", "detection_engine", 0.25, "Techniques with high bypass risk"),
        ]
    }

    /// Bayesian combination: P = 1 - Π(1 - P_i * decay)
    /// where decay accounts for event age relative to half-life.
    pub fn calculate_score(&self, active_indicators: &[(String, f64)]) -> SuspicionScore {
        let mut combined_prob = 0.0;
        let mut category_scores: HashMap<&str, Vec<f64>> = HashMap::new();
        let mut all_flags = Vec::new();

        for (name, age_secs) in active_indicators {
            if let Some(def) = self.indicators.get(name.as_str()) {
                let decay = (-age_secs / self.half_life_secs).exp();
                let adj_prob = def.base_prob * decay;
                combined_prob = 1.0 - (1.0 - combined_prob) * (1.0 - adj_prob);
                category_scores.entry(def.category)
                    .or_default()
                    .push(adj_prob);
                all_flags.push(name.clone());
            }
        }

        let mut categories = Vec::new();
        for (&cat_name, probs) in &category_scores {
            let mut cat_prob = 0.0;
            for &p in probs {
                cat_prob = 1.0 - (1.0 - cat_prob) * (1.0 - p);
            }
            categories.push(SuspicionCategory {
                name: cat_name.to_string(),
                score: cat_prob,
                weight: 1.0 / category_scores.len() as f64,
                indicators: probs.iter().map(|p| format!("p={:.3}", p)).collect(),
            });
        }

        let risk_level = if combined_prob < self.threshold_low {
            "low"
        } else if combined_prob < self.threshold_medium {
            "medium"
        } else if combined_prob < self.threshold_high {
            "high"
        } else {
            "critical"
        };

        SuspicionScore {
            overall_score: combined_prob.clamp(0.0, 1.0),
            categories,
            flags: all_flags,
            risk_level: risk_level.to_string(),
        }
    }
}

/// Legacy ScoringEngine wrapper that delegates to BayesianScorer.
pub struct ScoringEngine {
    scorer: BayesianScorer,
}

impl ScoringEngine {
    pub fn new() -> Self {
        Self { scorer: BayesianScorer::new(3600.0) }
    }

    pub fn calculate_score(&self, active_indicators: &[String]) -> SuspicionScore {
        let indicators: Vec<(String, f64)> = active_indicators.iter()
            .map(|name| (name.clone(), 0.0))
            .collect();
        self.scorer.calculate_score(&indicators)
    }
}
