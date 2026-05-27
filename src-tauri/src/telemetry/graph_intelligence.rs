//! Graph Intelligence Layer — unified graph engine that connects:
//! - ForensicGraphEngine (in-memory forensic property graph)
//! - GraphStore (SQLite attack chain adjacency list)
//! - Graphify knowledge graph (external export)
//! - Live telemetry event graph (realtime entity relationships)

use crate::telemetry::envelope::*;
use crate::telemetry::fabric::{CanonicalTelemetryEvent, EventFabric};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

// ─── Graph Node Types ─────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GraphNodeKind {
    Process,
    Thread,
    File,
    Directory,
    Network,
    Registry,
    Detection,
    Integrity,
    Module,
    Driver,
    MemoryRegion,
    Artifact,
    Entity,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    pub id: String,
    pub kind: GraphNodeKind,
    pub label: String,
    pub properties: HashMap<String, String>,
    pub first_seen_ns: u128,
    pub last_seen_ns: u128,
    pub trust_score: f64,
    pub risk_score: f64,
    pub event_count: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub relation: String,
    pub weight: f64,
    pub first_seen_ns: u128,
    pub last_seen_ns: u128,
    pub properties: HashMap<String, String>,
}

// ─── Graph Intelligence Layer ─────────────────────────────────────

pub struct GraphIntelligenceLayer {
    nodes: Arc<DashMap<String, GraphNode>>,
    edges: Arc<DashMap<String, GraphEdge>>,
    adjacency: Arc<DashMap<String, Vec<(String, String, f64)>>>,
    event_fabric: Option<Arc<EventFabric>>,
    node_count: AtomicU64,
    edge_count: AtomicU64,
    max_nodes: usize,
    max_edges: usize,
}

impl GraphIntelligenceLayer {
    pub fn new(max_nodes: usize, max_edges: usize) -> Self {
        Self {
            nodes: Arc::new(DashMap::with_capacity(max_nodes / 10)),
            edges: Arc::new(DashMap::with_capacity(max_edges / 10)),
            adjacency: Arc::new(DashMap::with_capacity(max_nodes / 10)),
            event_fabric: None,
            node_count: AtomicU64::new(0),
            edge_count: AtomicU64::new(0),
            max_nodes,
            max_edges,
        }
    }

    pub fn with_fabric(mut self, fabric: Arc<EventFabric>) -> Self {
        self.event_fabric = Some(fabric);
        self
    }

    /// Ingest a canonical event and update the graph
    pub fn ingest_event(&self, event: &CanonicalTelemetryEvent) {
        let entity_id = self.ensure_entity_node(event);

        // Create edges based on event type
        match &event.payload {
            TelemetryPayload::ProcessCreated { pid, parent_pid, .. } => {
                let child_id = format!("process:{}", pid);
                let parent_entity_id = format!("process:{}", parent_pid);
                self.ensure_node(GraphNodeKind::Process, &parent_entity_id, format!("PID {}", parent_pid));
                self.add_edge(&parent_entity_id, &child_id, "parent_child", 1.5, event);
            }
            TelemetryPayload::ImageLoaded { pid, image_path, .. } => {
                let proc_id = format!("process:{}", pid);
                let mod_id = format!("module:{}", image_path);
                self.ensure_node(GraphNodeKind::Module, &mod_id, image_path.clone());
                self.add_edge(&proc_id, &mod_id, "loaded_module", 1.0, event);
            }
            TelemetryPayload::ThreadCreated { pid, tid, .. } => {
                let proc_id = format!("process:{}", pid);
                let thread_id = format!("thread:{}", tid);
                self.ensure_node(GraphNodeKind::Thread, &thread_id, format!("TID {}", tid));
                self.add_edge(&proc_id, &thread_id, "has_thread", 0.8, event);
            }
            TelemetryPayload::FileChanged { path, event_type, .. } => {
                let file_id = format!("file:{}", path);
                self.ensure_node(GraphNodeKind::File, &file_id, path.clone());
                let proc = &event.process_lineage;
                let proc_id = format!("process:{}", proc.pid);
                self.add_edge(&proc_id, &file_id, &format!("file_{}", event_type), 1.0, event);
            }
            TelemetryPayload::NetworkConnection { remote_addr, remote_port, .. } => {
                let net_id = format!("network:{}:{}", remote_addr, remote_port);
                self.ensure_node(GraphNodeKind::Network, &net_id, format!("{}:{}", remote_addr, remote_port));
                let proc = &event.process_lineage;
                let proc_id = format!("process:{}", proc.pid);
                self.add_edge(&proc_id, &net_id, "network_connection", 0.9, event);
            }
            TelemetryPayload::RegistryModified { key_path, .. } => {
                let reg_id = format!("registry:{}", key_path);
                self.ensure_node(GraphNodeKind::Registry, &reg_id, key_path.clone());
            }
            TelemetryPayload::SuspiciousActivity { ref rule_name, .. } => {
                let det_id = format!("detection:{}", rule_name);
                self.ensure_node(GraphNodeKind::Detection, &det_id, rule_name.clone());
                let proc = &event.process_lineage;
                let proc_id = format!("process:{}", proc.pid);
                self.add_edge(&det_id, &proc_id, "triggered_on", event.risk_score.max(0.5), event);
            }
            TelemetryPayload::DetectionTriggered { ref technique, .. } => {
                let det_id = format!("detection:{}", technique);
                self.ensure_node(GraphNodeKind::Detection, &det_id, technique.clone());
                let proc = &event.process_lineage;
                let proc_id = format!("process:{}", proc.pid);
                self.add_edge(&det_id, &proc_id, "triggered_on", event.risk_score.max(0.5), event);
            }
            TelemetryPayload::MemoryChanged { base_address, .. } => {
                let proc = &event.process_lineage;
                let proc_id = format!("process:{}", proc.pid);
                let mem_id = format!("memory:{}:0x{:x}", proc.pid, base_address);
                self.ensure_node(GraphNodeKind::MemoryRegion, &mem_id, format!("PID {} memory", proc.pid));
                self.add_edge(&proc_id, &mem_id, "memory_change", event.severity as u8 as f64 / 4.0, event);
            }
            _ => {}
        }

        // Emit graph health update back into fabric if connected
        if let Some(ref fabric) = self.event_fabric {
            let _ = entity_id;
        }
    }

    fn ensure_entity_node(&self, event: &CanonicalTelemetryEvent) -> String {
        let eid = format!("entity:{}:{}", event.event_id, event.category as u8 as u64);
        self.ensure_node(GraphNodeKind::Entity, &eid, event.entity.label.clone());
        eid
    }

    fn ensure_node(&self, kind: GraphNodeKind, id: &str, label: String) {
        if self.nodes.contains_key(id) {
            if let Some(mut node) = self.nodes.get_mut(id) {
                node.last_seen_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                node.event_count += 1;
            }
            return;
        }

        if self.nodes.len() >= self.max_nodes {
            evict_oldest(&self.nodes, self.max_nodes / 4);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        self.nodes.insert(id.to_string(), GraphNode {
            id: id.to_string(),
            kind,
            label,
            properties: HashMap::new(),
            first_seen_ns: now,
            last_seen_ns: now,
            trust_score: 0.5,
            risk_score: 0.0,
            event_count: 1,
        });
        self.node_count.fetch_add(1, Ordering::Relaxed);
    }

    fn add_edge(&self, source_id: &str, target_id: &str, relation: &str, weight: f64, event: &CanonicalTelemetryEvent) {
        let edge_id = format!("{}--{}--{}", source_id, relation, target_id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        if let Some(mut edge) = self.edges.get_mut(&edge_id) {
            edge.weight = (edge.weight + weight) / 2.0;
            edge.last_seen_ns = now;
            edge.properties.insert("last_event".into(), event.event_id.to_string());
            return;
        }

        if self.edges.len() >= self.max_edges {
            evict_oldest_edge(&self.edges, self.max_edges / 4);
        }

        self.edges.insert(edge_id.clone(), GraphEdge {
            id: edge_id.clone(),
            source_id: source_id.to_string(),
            target_id: target_id.to_string(),
            relation: relation.to_string(),
            weight,
            first_seen_ns: now,
            last_seen_ns: now,
            properties: HashMap::new(),
        });
        self.edge_count.fetch_add(1, Ordering::Relaxed);

        self.adjacency.entry(source_id.to_string())
            .or_default()
            .push((target_id.to_string(), relation.to_string(), weight));
        self.adjacency.entry(target_id.to_string())
            .or_default()
            .push((source_id.to_string(), relation.to_string(), weight));
    }

    /// BFS traversal from a node to find attack chains
    pub fn traverse(&self, start_id: &str, max_depth: usize) -> Vec<(GraphNode, Vec<GraphEdge>)> {
        let mut visited = std::collections::HashSet::new();
        let mut result = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((start_id.to_string(), 0));

        while let Some((node_id, depth)) = queue.pop_front() {
            if depth > max_depth || !visited.insert(node_id.clone()) {
                continue;
            }

            if let Some(node) = self.nodes.get(&node_id) {
                let mut edges = Vec::new();
                if let Some(adj) = self.adjacency.get(&node_id) {
                    for (target, relation, _) in adj.value().iter() {
                        if let Some(edge) = self.edges.get(&format!("{}--{}--{}", node_id, relation, target)) {
                            edges.push(edge.clone());
                        }
                        queue.push_back((target.clone(), depth + 1));
                    }
                }
                result.push((node.clone(), edges));
            }
        }

        result
    }

    /// Get the full subgraph for a process
    pub fn process_subgraph(&self, pid: u32) -> Vec<(GraphNode, Vec<GraphEdge>)> {
        let proc_id = format!("process:{}", pid);
        self.traverse(&proc_id, 3)
    }

    /// Export for Graphify integration
    pub fn export_graphify(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "knowledge_graph",
            "version": "2.0",
            "clusters": [{
                "id": "integrity_monitor_graph",
                "label": "Live Telemetry Intelligence Graph",
                "node_count": self.node_count.load(Ordering::Relaxed),
                "edge_count": self.edge_count.load(Ordering::Relaxed),
                "nodes": self.nodes.iter().map(|n| serde_json::json!({
                    "id": n.id,
                    "type": format!("{:?}", n.kind),
                    "label": n.label,
                    "properties": n.properties,
                    "first_seen": n.first_seen_ns,
                    "last_seen": n.last_seen_ns,
                    "trust_score": n.trust_score,
                    "risk_score": n.risk_score,
                })).collect::<Vec<_>>(),
                "edges": self.edges.iter().map(|e| serde_json::json!({
                    "id": e.id,
                    "source": e.source_id,
                    "target": e.target_id,
                    "label": e.relation,
                    "weight": e.weight,
                })).collect::<Vec<_>>(),
            }],
        })
    }

    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "node_count": self.node_count.load(Ordering::Relaxed),
            "edge_count": self.edge_count.load(Ordering::Relaxed),
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
        })
    }
}

// ─── Eviction helpers ─────────────────────────────────────────────

fn evict_oldest(map: &DashMap<String, GraphNode>, count: usize) {
    let mut oldest: Vec<(String, u128)> = map.iter()
        .map(|n| (n.id.clone(), n.last_seen_ns))
        .collect();
    oldest.sort_by(|a, b| a.1.cmp(&b.1));
    for (id, _) in oldest.iter().take(count) {
        map.remove(id);
    }
}

fn evict_oldest_edge(map: &DashMap<String, GraphEdge>, count: usize) {
    let mut oldest: Vec<(String, u128)> = map.iter()
        .map(|e| (e.id.clone(), e.last_seen_ns))
        .collect();
    oldest.sort_by(|a, b| a.1.cmp(&b.1));
    for (id, _) in oldest.iter().take(count) {
        map.remove(id);
    }
}
