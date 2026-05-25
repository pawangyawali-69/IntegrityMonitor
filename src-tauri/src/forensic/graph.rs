use crate::forensic::*;
use crate::forensic::correlation::CorrelationChain;
use crate::forensic::anti_forensic::AntiForensicFinding;
use std::collections::HashMap;

/// Graph-based forensic intelligence engine.
/// Builds a property graph of all forensic artifacts for:
/// - Attack-chain visualization (Graphify/Ruflo)
/// - File lineage reconstruction
/// - Process ancestry mapping
/// - Cross-artifact relationship exploration
pub struct ForensicGraphEngine {
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
    node_map: HashMap<String, usize>,  // node_id → index
    max_nodes: usize,
}

impl ForensicGraphEngine {
    pub fn new() -> Self {
        Self {
            nodes: Vec::with_capacity(10000),
            edges: Vec::with_capacity(50000),
            node_map: HashMap::new(),
            max_nodes: 100_000,
        }
    }

    fn ensure_node(&mut self, node: GraphNode) -> usize {
        if let Some(&idx) = self.node_map.get(&node.id) {
            return idx;
        }
        if self.nodes.len() >= self.max_nodes {
            // Evict oldest node and its edges
            let removed = self.nodes.remove(0);
            self.node_map.remove(&removed.id);
            self.edges.retain(|e| e.source != removed.id && e.target != removed.id);
        }
        let idx = self.nodes.len();
        self.node_map.insert(node.id.clone(), idx);
        self.nodes.push(node);
        idx
    }

    fn add_edge(&mut self, source: String, target: String, edge_type: GraphEdgeType, weight: f64, properties: HashMap<String, String>) {
        self.edges.push(GraphEdge {
            source,
            target,
            edge_type,
            weight,
            properties,
        });
    }

    /// Ingest filesystem events and build graph relationships
    pub fn ingest_events(&mut self, events: &[FilesystemEvent]) {
        for ev in events {
            let reason = UsnReason::from_bits_truncate(ev.usn_reason);

            // Create/reference the file node
            let file_id = format!("file:{}", ev.file_reference);
            self.ensure_node(GraphNode {
                id: file_id.clone(),
                node_type: GraphNodeType::File,
                label: ev.filename.clone(),
                properties: {
                    let mut m = HashMap::new();
                    m.insert("fileReference".into(), format!("{:016x}", ev.file_reference));
                    m.insert("parentReference".into(), format!("{:016x}", ev.parent_reference));
                    m.insert("size".into(), "0".into());
                    m
                },
                timestamp: ev.timestamp.clone(),
            });

            // Create/reference the parent directory node
            let parent_id = format!("dir:{}", ev.parent_reference);
            self.ensure_node(GraphNode {
                id: parent_id.clone(),
                node_type: GraphNodeType::Directory,
                label: ev.parent_path.clone().unwrap_or_else(|| format!("{:016x}", ev.parent_reference)),
                properties: HashMap::new(),
                timestamp: ev.timestamp.clone(),
            });

            // CONTAINS edge (Directory → File)
            self.add_edge(
                parent_id.clone(),
                file_id.clone(),
                GraphEdgeType::Contains,
                1.0,
                HashMap::new(),
            );

            // Relationship based on reason
            if reason.contains(UsnReason::FILE_CREATE) {
                // Look for a process node
                if let Some(pid) = ev.process_pid {
                    let proc_id = format!("process:{}", pid);
                    self.ensure_node(GraphNode {
                        id: proc_id.clone(),
                        node_type: GraphNodeType::Process,
                        label: ev.process_name.clone().unwrap_or_else(|| format!("PID {}", pid)),
                        properties: {
                            let mut m = HashMap::new();
                            m.insert("pid".into(), pid.to_string());
                            m
                        },
                        timestamp: ev.timestamp.clone(),
                    });

                    self.add_edge(
                        proc_id,
                        file_id.clone(),
                        GraphEdgeType::CreatedBy,
                        1.0,
                        HashMap::new(),
                    );
                }
            }

            if reason.contains(UsnReason::FILE_DELETE) {
                if let Some(pid) = ev.process_pid {
                    let proc_id = format!("process:{}", pid);
                    self.ensure_node(GraphNode {
                        id: proc_id.clone(),
                        node_type: GraphNodeType::Process,
                        label: ev.process_name.clone().unwrap_or_else(|| format!("PID {}", pid)),
                        properties: {
                            let mut m = HashMap::new();
                            m.insert("pid".into(), pid.to_string());
                            m
                        },
                        timestamp: ev.timestamp.clone(),
                    });

                    self.add_edge(
                        proc_id,
                        file_id.clone(),
                        GraphEdgeType::DeletedBy,
                        1.0,
                        HashMap::new(),
                    );
                }
            }

            if reason.contains(UsnReason::RENAME_OLD_NAME) || reason.contains(UsnReason::RENAME_NEW_NAME) {
                // RENAMED edge — link to previous filename
                let prev_file_id = format!("file:{}:{}", ev.file_reference, ev.usn - 1);
                self.ensure_node(GraphNode {
                    id: prev_file_id.clone(),
                    node_type: GraphNodeType::File,
                    label: format!("{}_prev", ev.filename),
                    properties: {
                        let mut m = HashMap::new();
                        m.insert("fileReference".into(), format!("{:016x}", ev.file_reference));
                        m.insert("usn".into(), (ev.usn - 1).to_string());
                        m
                    },
                    timestamp: ev.timestamp.clone(),
                });

                self.add_edge(
                    prev_file_id,
                    file_id.clone(),
                    GraphEdgeType::Renamed,
                    1.0,
                    HashMap::new(),
                );
            }

            if reason.contains(UsnReason::DATA_OVERWRITE) || reason.contains(UsnReason::DATA_EXTEND) {
                if let Some(pid) = ev.process_pid {
                    let proc_id = format!("process:{}", pid);
                    self.add_edge(
                        proc_id,
                        file_id.clone(),
                        GraphEdgeType::ModifiedBy,
                        0.7,
                        HashMap::new(),
                    );
                }
            }
        }
    }

    /// Ingest correlation chains as graph edges
    pub fn ingest_chains(&mut self, chains: &[CorrelationChain]) {
        for chain in chains {
            let chain_id = format!("chain:{}", chain.id);
            for ev in &chain.events {
                let file_id = format!("file:{}", ev.file_reference);
                self.add_edge(
                    chain_id.clone(),
                    file_id,
                    GraphEdgeType::Correlated,
                    chain.confidence,
                    {
                        let mut m = HashMap::new();
                        m.insert("rule".into(), chain.rule_name.clone());
                        m.insert("description".into(), chain.description.clone());
                        m
                    },
                );
            }
        }
    }

    /// Ingest anti-forensic findings as graph nodes
    pub fn ingest_findings(&mut self, findings: &[AntiForensicFinding]) {
        for finding in findings {
            let finding_id = format!("finding:{}", uuid::Uuid::new_v4());
            self.ensure_node(GraphNode {
                id: finding_id.clone(),
                node_type: GraphNodeType::Detection,
                label: format!("{:?}: {}", finding.finding_type, finding.description),
                properties: {
                    let mut m = HashMap::new();
                    m.insert("type".into(), format!("{:?}", finding.finding_type));
                    m.insert("severity".into(), format!("{:?}", finding.severity));
                    m.insert("confidence".into(), format!("{:.2}", finding.confidence));
                    m
                },
                timestamp: finding.timestamp.clone(),
            });

            for affected in &finding.affected_artifacts {
                let target_id = format!("artifact:{}", affected);
                self.ensure_node(GraphNode {
                    id: target_id.clone(),
                    node_type: GraphNodeType::File,
                    label: affected.clone(),
                    properties: HashMap::new(),
                    timestamp: finding.timestamp.clone(),
                });

                self.add_edge(
                    finding_id.clone(),
                    target_id,
                    GraphEdgeType::Correlated,
                    finding.confidence,
                    HashMap::new(),
                );
            }
        }
    }

    /// Query the graph for attack-chain subgraphs
    pub fn get_subgraph_for_file(&self, frn: FileReference, depth: usize) -> ForensicGraph {
        let file_id = format!("file:{}", frn);
        let start_idx = match self.node_map.get(&file_id) {
            Some(&i) => i,
            None => return ForensicGraph { nodes: vec![], edges: vec![] },
        };

        let mut visited_nodes = std::collections::HashSet::new();
        let mut visited_edges = std::collections::HashSet::new();
        let mut queue: Vec<(usize, usize)> = vec![(start_idx, 0)];
        let mut result_nodes = Vec::new();
        let mut result_edges = Vec::new();

        while let Some((idx, d)) = queue.pop() {
            if d > depth || visited_nodes.contains(&idx) { continue; }
            visited_nodes.insert(idx);
            result_nodes.push(self.nodes[idx].clone());

            let node_id = &self.nodes[idx].id;
            for (ei, edge) in self.edges.iter().enumerate() {
                if visited_edges.contains(&ei) { continue; }
                if edge.source == *node_id {
                    visited_edges.insert(ei);
                    result_edges.push(edge.clone());
                    if let Some(&target_idx) = self.node_map.get(&edge.target) {
                        queue.push((target_idx, d + 1));
                    }
                }
                if edge.target == *node_id {
                    visited_edges.insert(ei);
                    result_edges.push(edge.clone());
                    if let Some(&source_idx) = self.node_map.get(&edge.source) {
                        queue.push((source_idx, d + 1));
                    }
                }
            }
        }

        ForensicGraph {
            nodes: result_nodes,
            edges: result_edges,
        }
    }

    /// Get all process-file relationships
    pub fn process_file_graph(&self) -> ForensicGraph {
        let nodes: Vec<GraphNode> = self.nodes.iter()
            .filter(|n| n.node_type == GraphNodeType::Process || n.node_type == GraphNodeType::File)
            .cloned()
            .collect();

        let edges: Vec<GraphEdge> = self.edges.iter()
            .filter(|e| {
                matches!(e.edge_type,
                    GraphEdgeType::CreatedBy |
                    GraphEdgeType::DeletedBy |
                    GraphEdgeType::ModifiedBy |
                    GraphEdgeType::Executed |
                    GraphEdgeType::Injected
                )
            })
            .cloned()
            .collect();

        ForensicGraph { nodes, edges }
    }

    /// Export entire graph for visualization tools (Graphify/Ruflo)
    pub fn export_graph(&self) -> serde_json::Value {
        serde_json::json!({
            "nodes": self.nodes.iter().map(|n| serde_json::json!({
                "id": n.id,
                "type": format!("{:?}", n.node_type),
                "label": n.label,
                "properties": n.properties,
                "timestamp": n.timestamp.to_rfc3339(),
            })).collect::<Vec<_>>(),
            "edges": self.edges.iter().map(|e| serde_json::json!({
                "source": e.source,
                "target": e.target,
                "type": format!("{:?}", e.edge_type),
                "weight": e.weight,
                "properties": e.properties,
            })).collect::<Vec<_>>(),
            "metadata": {
                "node_count": self.nodes.len(),
                "edge_count": self.edges.len(),
                "generated_at": Timestamp::now().to_rfc3339(),
            },
        })
    }

    /// Export for Graphify knowledge graph integration
    pub fn export_graphify(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "knowledge_graph",
            "version": "1.0",
            "clusters": [{
                "id": "forensic_artifacts",
                "label": "Forensic Artifact Graph",
                "nodes": self.nodes.iter().map(|n| {
                    serde_json::json!({
                        "id": n.id,
                        "type": format!("{:?}", n.node_type),
                        "label": n.label,
                        "properties": n.properties,
                    })
                }).collect::<Vec<_>>(),
                "edges": self.edges.iter().map(|e| {
                    serde_json::json!({
                        "source": e.source,
                        "target": e.target,
                        "label": format!("{:?}", e.edge_type),
                        "weight": e.weight,
                    })
                }).collect::<Vec<_>>(),
            }],
        })
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Clear and reset the graph
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.edges.clear();
        self.node_map.clear();
    }
}
