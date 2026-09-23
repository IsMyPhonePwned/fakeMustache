use fm_core::{Action, AnonOptions, LogArchivePolicy};

#[derive(Debug, Clone)]
pub struct MemberAction {
    pub drop: bool,
    pub reason: String,
}

pub fn is_image_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".png")
        || p.ends_with(".jpg")
        || p.ends_with(".jpeg")
        || p.ends_with(".gif")
        || p.ends_with(".heic")
        || p.ends_with(".webp")
        || p.ends_with(".bmp")
}

pub fn member_action(path: &str, opts: &AnonOptions) -> MemberAction {
    if is_image_path(path) {
        return MemberAction {
            drop: true,
            reason: "image; always drop".into(),
        };
    }

    let lower = path.replace('\\', "/");
    let profile = opts.effective_profile();

    // Policy member rules (glob-ish)
    for rule in &profile.member_rules {
        if glob_match(&rule.match_pattern, &lower) {
            if rule.action == Action::Drop {
                return MemberAction {
                    drop: true,
                    reason: rule.reason.clone(),
                };
            }
        }
    }

    // Logarchive handling
    if lower.contains("system_logs.logarchive/") || lower.ends_with(".logarchive") {
        match opts.logarchive {
            LogArchivePolicy::Drop => {
                return MemberAction {
                    drop: true,
                    reason: "logarchive dropped (v1 default)".into(),
                };
            }
            LogArchivePolicy::Jsonl => {
                // Keep for decode path in fm-apple; binary still dropped later
                return MemberAction {
                    drop: true,
                    reason: "logarchive binary replaced by JSONL in apple pipeline".into(),
                };
            }
        }
    }

    // Safari / knowledgeC
    if lower.contains("safari") && (lower.ends_with(".db") || lower.contains("history")) {
        return MemberAction {
            drop: true,
            reason: "browsing history".into(),
        };
    }
    if lower.contains("knowledgec.db") {
        return MemberAction {
            drop: true,
            reason: "knowledgeC behavioural PII".into(),
        };
    }

    #[cfg(target_arch = "wasm32")]
    {
        if lower.ends_with(".db")
            || lower.ends_with(".sqlite")
            || lower.ends_with(".sqlite3")
            || lower.ends_with(".sqlitedb")
        {
            return MemberAction {
                drop: true,
                reason: "SQLite dropped on WASM".into(),
            };
        }
    }

    MemberAction {
        drop: false,
        reason: String::new(),
    }
}

fn glob_match(pattern: &str, path: &str) -> bool {
    // Minimal glob: ** and * 
    let pat = pattern.replace('\\', "/");
    if let Ok(g) = globset::Glob::new(&pat) {
        let matcher = g.compile_matcher();
        if matcher.is_match(path) {
            return true;
        }
        // Also try basename
        if let Some(base) = path.rsplit('/').next() {
            return matcher.is_match(base);
        }
    }
    path.contains(pattern.trim_start_matches("**/"))
}
