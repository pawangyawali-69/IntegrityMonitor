use crate::core::{SuspicionScore, SuspicionCategory};

pub struct ScoringEngine {
    weights: Vec<ScoringWeight>,
}

struct ScoringWeight {
    category: String,
    weight: f64,
    indicators: Vec<SuspicionIndicator>,
}

struct SuspicionIndicator {
    name: String,
    score: f64,
    description: String,
}

impl ScoringEngine {
    pub fn new() -> Self {
        Self {
            weights: vec![
                ScoringWeight {
                    category: "unsigned_modules".into(),
                    weight: 0.25,
                    indicators: vec![
                        SuspicionIndicator { name: "unsigned_dll".into(), score: 0.4, description: "Unsigned DLL loaded".into() },
                        SuspicionIndicator { name: "unsigned_driver".into(), score: 0.6, description: "Unsigned driver loaded".into() },
                    ],
                },
                ScoringWeight {
                    category: "process_behavior".into(),
                    weight: 0.20,
                    indicators: vec![
                        SuspicionIndicator { name: "hidden_process".into(), score: 0.8, description: "Hidden process detected".into() },
                        SuspicionIndicator { name: "suspicious_parent".into(), score: 0.3, description: "Suspicious parent-child relationship".into() },
                        SuspicionIndicator { name: "remote_thread".into(), score: 0.7, description: "Remote thread detected".into() },
                    ],
                },
                ScoringWeight {
                    category: "file_activity".into(),
                    weight: 0.20,
                    indicators: vec![
                        SuspicionIndicator { name: "deleted_executable".into(), score: 0.5, description: "Executable deleted after execution".into() },
                        SuspicionIndicator { name: "cleanup_script".into(), score: 0.6, description: "Cleanup script detected".into() },
                        SuspicionIndicator { name: "timestamp_anomaly".into(), score: 0.3, description: "Timestamp modification detected".into() },
                    ],
                },
                ScoringWeight {
                    category: "emulator_integrity".into(),
                    weight: 0.20,
                    indicators: vec![
                        SuspicionIndicator { name: "injected_dll".into(), score: 0.7, description: "DLL injected into emulator".into() },
                        SuspicionIndicator { name: "suspicious_overlay".into(), score: 0.6, description: "Suspicious overlay detected".into() },
                        SuspicionIndicator { name: "modified_emulator_file".into(), score: 0.5, description: "Emulator files modified".into() },
                    ],
                },
                ScoringWeight {
                    category: "memory_integrity".into(),
                    weight: 0.15,
                    indicators: vec![
                        SuspicionIndicator { name: "suspicious_memory".into(), score: 0.5, description: "Suspicious memory permissions".into() },
                        SuspicionIndicator { name: "injected_code".into(), score: 0.8, description: "Code injection detected".into() },
                    ],
                },
                ScoringWeight {
                    category: "detection_engine".into(),
                    weight: 0.25,
                    indicators: vec![
                        SuspicionIndicator { name: "high_detection_risk".into(), score: 0.9, description: "High overall detection risk score".into() },
                        SuspicionIndicator { name: "multiple_techniques_detected".into(), score: 0.7, description: "Multiple detection techniques triggered".into() },
                        SuspicionIndicator { name: "high_bypass_risk".into(), score: 0.3, description: "Techniques with high bypass risk".into() },
                    ],
                },
            ],
        }
    }

    pub fn calculate_score(&self, active_indicators: &[String]) -> SuspicionScore {
        let mut total_score = 0.0;
        let mut categories = Vec::new();
        let mut all_flags = Vec::new();

        for weight in &self.weights {
            let mut category_score = 0.0;
            let mut category_indicators = Vec::new();
            
            for indicator in &weight.indicators {
                if active_indicators.iter().any(|i| i == &indicator.name) {
                    category_score += indicator.score;
                    category_indicators.push(indicator.description.clone());
                    all_flags.push(indicator.name.clone());
                }
            }

            category_score = (category_score / weight.indicators.len() as f64).clamp(0.0, 1.0);
            total_score += category_score * weight.weight;

            categories.push(SuspicionCategory {
                name: weight.category.clone(),
                score: category_score,
                weight: weight.weight,
                indicators: category_indicators,
            });
        }

        total_score = total_score.clamp(0.0, 1.0);
        
        let risk_level = if total_score < 0.2 {
            "low"
        } else if total_score < 0.5 {
            "medium"
        } else if total_score < 0.8 {
            "high"
        } else {
            "critical"
        };

        SuspicionScore {
            overall_score: total_score,
            categories,
            flags: all_flags,
            risk_level: risk_level.to_string(),
        }
    }
}
