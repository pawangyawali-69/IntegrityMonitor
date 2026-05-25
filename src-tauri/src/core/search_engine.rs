use crate::core::SearchResult;
use std::path::PathBuf;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::*;
use tantivy::{doc, Index, IndexWriter, ReloadPolicy, TantivyDocument};

pub struct SearchEngine {
    index: Index,
    #[allow(dead_code)]
    schema: Schema,
    writer: Option<IndexWriter>,
    id_field: Field,
    title_field: Field,
    description_field: Field,
    category_field: Field,
    timestamp_field: Field,
    path_field: Field,
    content_field: Field,
    indexed_count: usize,
}

impl SearchEngine {
    pub fn new() -> Self {
        let mut schema_builder = Schema::builder();
        let id_field = schema_builder.add_text_field("id", STRING | STORED);
        let title_field = schema_builder.add_text_field("title", TEXT | STORED);
        let description_field = schema_builder.add_text_field("description", TEXT | STORED);
        let category_field = schema_builder.add_text_field("category", STRING | STORED);
        let timestamp_field = schema_builder.add_text_field("timestamp", STRING | STORED);
        let path_field = schema_builder.add_text_field("path", STRING | STORED);
        let content_field = schema_builder.add_text_field("content", TEXT);
        let schema = schema_builder.build();

        let index_path = get_index_path();

        let index = if index_path.exists() {
            Index::open_in_dir(&index_path).unwrap_or_else(|_| {
                let _ = std::fs::remove_dir_all(&index_path);
                Index::create_in_dir(&index_path, schema.clone()).unwrap()
            })
        } else {
            std::fs::create_dir_all(&index_path).ok();
            Index::create_in_dir(&index_path, schema.clone()).unwrap()
        };

        let writer = index
            .writer(50_000_000)
            .ok();

        Self {
            index,
            schema,
            writer,
            id_field,
            title_field,
            description_field,
            category_field,
            timestamp_field,
            path_field,
            content_field,
            indexed_count: 0,
        }
    }

    pub fn search(&self, query_str: &str, limit: usize) -> Vec<SearchResult> {
        if query_str.trim().is_empty() {
            return Vec::new();
        }

        let reader = match self
            .index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()
        {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let searcher = reader.searcher();

        let fields = vec![
            self.title_field,
            self.description_field,
            self.content_field,
            self.category_field,
        ];

        let query_parser =
            QueryParser::for_index(&self.index, fields);

        let query = match query_parser.parse_query(query_str) {
            Ok(q) => q,
            Err(_) => return Vec::new(),
        };

        let top_docs = match searcher.search(&query, &TopDocs::with_limit(limit)) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };

        let mut results = Vec::new();
        for (score, doc_address) in top_docs {
            let doc: TantivyDocument = match searcher.doc::<TantivyDocument>(doc_address) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let get_str = |f: Field| -> String {
                doc.get_first(f)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };

            results.push(SearchResult {
                id: get_str(self.id_field),
                title: get_str(self.title_field),
                description: get_str(self.description_field),
                category: get_str(self.category_field),
                relevance: score as f64,
                timestamp: get_str(self.timestamp_field),
                path: {
                    let p = get_str(self.path_field);
                    if p.is_empty() { None } else { Some(p) }
                },
            });
        }

        results
    }

    pub fn index_document(&mut self, result: &SearchResult) {
        let writer = match self.writer.as_mut() {
            Some(w) => w,
            None => return,
        };

        let content = format!(
            "{} {} {} {:?}",
            result.title, result.description, result.category, result.path
        );

        let d = doc!(
            self.id_field => result.id.as_str(),
            self.title_field => result.title.as_str(),
            self.description_field => result.description.as_str(),
            self.category_field => result.category.as_str(),
            self.timestamp_field => result.timestamp.as_str(),
            self.path_field => result.path.as_deref().unwrap_or(""),
            self.content_field => content.as_str(),
        );

        if let Err(e) = writer.add_document(d) {
            log::warn!("Failed to index document: {}", e);
        }

        self.indexed_count += 1;

        if self.indexed_count % 100 == 0 {
            self.commit();
        }
    }

    pub fn commit(&mut self) {
        if let Some(writer) = self.writer.as_mut() {
            if let Err(e) = writer.commit() {
                log::warn!("Failed to commit search index: {}", e);
            }
        }
    }

    #[allow(dead_code)]
    pub fn get_indexed_count(&self) -> usize {
        self.indexed_count
    }
}

fn get_index_path() -> PathBuf {
    PathBuf::from(
        std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| "C:\\Users\\Default\\AppData\\Local".into()),
    )
    .join("IntegrityMonitor")
    .join("search_index")
}

impl Drop for SearchEngine {
    fn drop(&mut self) {
        self.commit();
    }
}
