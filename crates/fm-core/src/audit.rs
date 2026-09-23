use crate::entity::{Action, EntityKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaMeta {
    pub sha256: String,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySummary {
    pub kind: String,
    pub count: u32,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberDrop {
    pub path: String,
    pub bytes: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidualFinding {
    pub kind: String,
    pub member: String,
    pub confidence: String,
    pub snippet_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidualScan {
    pub status: String,
    pub findings: Vec<ResidualFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclaredDivergence {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub tool_version: String,
    pub profile: String,
    pub input: ShaMeta,
    pub output: ShaMeta,
    pub entities: Vec<EntitySummary>,
    pub members_dropped: Vec<MemberDrop>,
    pub members_unhandled: Vec<String>,
    pub declared_divergences: Vec<String>,
    pub residual_scan: ResidualScan,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

impl AuditReport {
    pub fn new(profile: &str, input_sha: String, input_bytes: u64, kind: &str) -> Self {
        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            profile: profile.to_string(),
            input: ShaMeta {
                sha256: input_sha,
                bytes: input_bytes,
                kind: Some(kind.to_string()),
            },
            output: ShaMeta {
                sha256: String::new(),
                bytes: 0,
                kind: None,
            },
            entities: Vec::new(),
            members_dropped: Vec::new(),
            members_unhandled: Vec::new(),
            declared_divergences: Vec::new(),
            residual_scan: ResidualScan {
                status: "pending".into(),
                findings: Vec::new(),
            },
            warnings: Vec::new(),
            limitations: vec![
                "Free-text log content is best-effort; arbitrary personal names may survive.".into(),
                "This tool removes identifiers; it does not remove behavioural fingerprints (app set, install times, crash patterns). Safe to share with someone who does not already know you — not anonymous to someone already investigating you.".into(),
            ],
        }
    }

    pub fn push_entity(&mut self, kind: EntityKind, count: u32, action: Action) {
        self.entities.push(EntitySummary {
            kind: kind.as_str().to_string(),
            count,
            action: format!("{action:?}").to_ascii_lowercase(),
        });
    }

    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| crate::Error::Other(e.to_string()))
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# fakeMustache anonymization report\n\n");
        md.push_str(&format!("- **Tool version:** {}\n", self.tool_version));
        md.push_str(&format!("- **Profile:** {}\n", self.profile));
        md.push_str(&format!(
            "- **Input:** {} ({} bytes, {:?})\n",
            self.input.sha256, self.input.bytes, self.input.kind
        ));
        md.push_str(&format!(
            "- **Output:** {} ({} bytes)\n",
            self.output.sha256, self.output.bytes
        ));
        md.push_str(&format!(
            "- **Residual scan:** {}\n\n",
            self.residual_scan.status
        ));
        md.push_str("## Entities\n\n");
        for e in &self.entities {
            md.push_str(&format!("- `{}`: {} ({})\n", e.kind, e.count, e.action));
        }
        md.push_str("\n## Dropped members\n\n");
        for m in &self.members_dropped {
            md.push_str(&format!(
                "- `{}` ({} bytes) — {}\n",
                m.path, m.bytes, m.reason
            ));
        }
        if !self.warnings.is_empty() {
            md.push_str("\n## Warnings\n\n");
            for w in &self.warnings {
                md.push_str(&format!("- {w}\n"));
            }
        }
        md.push_str("\n## Limitations\n\n");
        for l in &self.limitations {
            md.push_str(&format!("- {l}\n"));
        }
        md
    }
}
