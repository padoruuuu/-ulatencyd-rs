//! Rule engine for ulatencyd-rs.
//!
//! Rules are loaded from TOML files in /etc/ulatencyd/rules/ and
//! /usr/lib/ulatencyd/rules/. Each rule has a set of match predicates
//! (AND-combined) and an action to apply when all predicates are satisfied.
//! Rules are sorted by priority (descending); the first match wins unless
//! `continue = true` is set.
//!
//! Profiles support inheritance: `inherits = "sound-server"` merges the
//! parent's action into the child before overrides are applied.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use wildmatch::WildMatch;

use procmon::ProcessInfo;

// ---------------------------------------------------------------------------
// Wire types (deserialized from TOML)
// ---------------------------------------------------------------------------

/// A complete rule file (array of [[rule]] entries plus optional [[profile]]).
#[derive(Debug, Deserialize, Default)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<RuleToml>,
    #[serde(default)]
    profile: Vec<ProfileToml>,
}

/// Raw TOML representation of a [[rule]].
#[derive(Debug, Deserialize)]
struct RuleToml {
    name:     String,
    #[serde(default = "default_priority")]
    priority: i32,
    #[serde(default)]
    r#match:  MatchToml,
    action:   ActionToml,
    #[serde(default)]
    r#continue: bool,
}

fn default_priority() -> i32 { 50 }

/// All optional match predicates (AND-combined).
#[derive(Debug, Deserialize, Default, Clone)]
pub struct MatchToml {
    #[serde(default)] pub comm:                Vec<String>,
    #[serde(default)] pub comm_prefix:         Vec<String>,
    #[serde(default)] pub cmdline_contains:    Vec<String>,
    #[serde(default)] pub exe_path:            Vec<String>,
    #[serde(default)] pub uid:                 Vec<u32>,
    #[serde(default)] pub env_set:             Vec<String>,
    pub min_threads:   Option<u32>,
    pub min_rss_mb:    Option<u64>,
    #[serde(default)] pub parent_comm:         Vec<String>,
    #[serde(default)] pub cgroup_path_contains: Vec<String>,
    /// Wildmatch glob, e.g. "/user.slice/*.service"
    pub cgroup_path:   Option<String>,
}

/// Action applied when a rule matches.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ActionToml {
    pub cgroup:              Option<String>,
    pub nice:                Option<i8>,
    pub sched_policy:        Option<String>,
    pub sched_priority:      Option<u8>,
    pub oom_score_adj:       Option<i32>,
    pub io_weight:           Option<u32>,
    pub recheck_secs:        Option<u64>,
    pub apply_to_children:   Option<bool>,
    pub script:              Option<String>,
}

/// A [[profile]] block (used for inheritance).
#[derive(Debug, Deserialize, Clone)]
struct ProfileToml {
    name:     String,
    inherits: Option<String>,
    #[serde(flatten)]
    action:   ActionToml,
}

// ---------------------------------------------------------------------------
// Compiled internal types
// ---------------------------------------------------------------------------

/// Compiled, resolved rule (no inheritance indirection).
#[derive(Debug, Clone)]
pub struct Rule {
    pub name:       String,
    pub priority:   i32,
    pub matchers:   Matchers,
    pub action:     Action,
    pub continue_:  bool,
}

/// Compiled match predicates.
#[derive(Debug, Clone, Default)]
pub struct Matchers {
    pub comm:                Vec<String>,
    pub comm_prefix:         Vec<String>,
    pub cmdline_contains:    Vec<String>,
    pub exe_path:            Vec<PathBuf>,
    pub uid:                 Vec<u32>,
    pub env_set:             Vec<String>,
    pub min_threads:         Option<u32>,
    pub min_rss_mb:          Option<u64>,
    pub parent_comm:         Vec<String>,
    pub cgroup_path_contains: Vec<String>,
    /// Pre-compiled wildmatch pattern (only when pattern contains * or ?).
    pub cgroup_path_glob:    Option<(String, WildMatch)>,
    /// Exact cgroup path (no glob characters).
    pub cgroup_path_exact:   Option<String>,
}

impl Matchers {
    fn matches(&self, proc: &ProcessInfo, parent_comm: Option<&str>) -> bool {
        if !self.comm.is_empty() && !self.comm.iter().any(|c| c == &proc.comm) {
            return false;
        }
        if !self.comm_prefix.is_empty() && !self.comm_prefix.iter().any(|p| proc.comm.starts_with(p.as_str())) {
            return false;
        }
        if !self.cmdline_contains.is_empty() {
            let joined = proc.cmdline.join(" ");
            if !self.cmdline_contains.iter().any(|s| joined.contains(s.as_str())) {
                return false;
            }
        }
        if !self.exe_path.is_empty() {
            let exe_match = proc.exe.as_ref()
                .map(|e| self.exe_path.iter().any(|p| p == e))
                .unwrap_or(false);
            if !exe_match { return false; }
        }
        if !self.uid.is_empty() && !self.uid.contains(&proc.uid) {
            return false;
        }
        if !self.env_set.is_empty() {
            if !self.env_set.iter().all(|k| proc.environ.contains_key(k.as_str())) {
                return false;
            }
        }
        if let Some(min_t) = self.min_threads {
            if proc.threads < min_t { return false; }
        }
        if let Some(min_rss) = self.min_rss_mb {
            if proc.vm_rss_kb / 1024 < min_rss { return false; }
        }
        if !self.parent_comm.is_empty() {
            let pc = parent_comm.unwrap_or("");
            if !self.parent_comm.iter().any(|c| c == pc) { return false; }
        }
        if let Some(ref cgroup) = proc.cgroup_path {
            if !self.cgroup_path_contains.is_empty() {
                if !self.cgroup_path_contains.iter().any(|s| cgroup.contains(s.as_str())) {
                    return false;
                }
            }
            if let Some((_, ref glob)) = self.cgroup_path_glob {
                if !glob.matches(cgroup) { return false; }
            }
            if let Some(ref exact) = self.cgroup_path_exact {
                if cgroup != exact { return false; }
            }
        } else if self.cgroup_path_glob.is_some() || self.cgroup_path_exact.is_some() {
            return false;
        }
        true
    }
}

/// Resolved action to apply to a process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Action {
    pub cgroup:            Option<String>,
    pub nice:              Option<i8>,
    pub sched_policy:      Option<String>,
    pub sched_priority:    Option<u8>,
    pub oom_score_adj:     Option<i32>,
    pub io_weight:         Option<u32>,
    pub recheck_secs:      Option<u64>,
    pub apply_to_children: bool,
    pub rule_name:         String,
}

// ---------------------------------------------------------------------------
// Exception list
// ---------------------------------------------------------------------------

/// Processes that must never be touched by the daemon.
pub struct ExceptionList {
    /// Exact process names.
    pub exact_names: HashSet<String>,
    /// If any ancestor has one of these names, this process is exempt.
    pub ancestor_names: HashSet<String>,
}

impl Default for ExceptionList {
    fn default() -> Self {
        let exact: &[&str] = &[
            "chrt", "dbus", "dbus-broker", "gamemoderun", "ionice",
            "nice", "rtkit-daemon", "taskset", "schedtool", "systemd",
        ];
        let anc: &[&str] = &[
            "chrt", "gamemoderun", "ionice", "nice", "taskset", "schedtool",
        ];
        Self {
            exact_names:    exact.iter().map(|s| s.to_string()).collect(),
            ancestor_names: anc.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl ExceptionList {
    /// Returns true if `proc` should be excluded from all management.
    pub fn is_exempt(&self, proc: &ProcessInfo, ancestor_comms: &[String]) -> bool {
        if self.exact_names.contains(&proc.comm) {
            return true;
        }
        // Check ancestors supplied by the caller (tree walk done externally).
        ancestor_comms.iter().any(|c| self.ancestor_names.contains(c))
    }
}

// ---------------------------------------------------------------------------
// Rule engine
// ---------------------------------------------------------------------------

pub struct RuleEngine {
    rules: Vec<Rule>,
    exceptions: ExceptionList,
}

impl RuleEngine {
    /// Load rules from a list of directories. Later directories take precedence.
    pub fn load(dirs: &[PathBuf]) -> Result<Self> {
        let rules = load_rules(dirs)?;
        Ok(Self {
            rules,
            exceptions: ExceptionList::default(),
        })
    }

    /// Classify a process. Returns the highest-priority matching action,
    /// or None if the process is exempt or no rule matches.
    pub fn classify(
        &self,
        proc: &ProcessInfo,
        ancestor_comms: &[String],
    ) -> Option<Action> {
        if self.exceptions.is_exempt(proc, ancestor_comms) {
            debug!("pid {} ({}) is exempt", proc.pid, proc.comm);
            return None;
        }

        // Also skip processes that already have a non-NORMAL sched policy
        // unless they're explicitly targeted by a high-priority rule.
        let has_rt = matches!(
            proc.sched_policy,
            procmon::SchedPolicy::Fifo(_) | procmon::SchedPolicy::RoundRobin(_) | procmon::SchedPolicy::Deadline
        );

        let parent = ancestor_comms.first().map(|s| s.as_str());
        let mut result: Option<Action> = None;

        for rule in &self.rules {
            if rule.matchers.matches(proc, parent) {
                let mut action = rule.action.clone();
                action.rule_name = rule.name.clone();

                // Never lower an RT policy set externally.
                if has_rt && action.sched_policy.as_deref() == Some("normal") {
                    action.sched_policy = None;
                }

                if let Some(ref mut prev) = result {
                    // Merge lower-priority action into result (first match wins for each field).
                    merge_action(prev, &action);
                    if !rule.continue_ { break; }
                } else {
                    result = Some(action);
                    if !rule.continue_ { break; }
                }
            }
        }

        result
    }

    /// Hot-reload rules from disk.
    pub fn reload(&mut self, dirs: &[PathBuf]) -> Result<()> {
        self.rules = load_rules(dirs)?;
        info!("rules reloaded: {} rules", self.rules.len());
        Ok(())
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ---------------------------------------------------------------------------
// Loading and compiling
// ---------------------------------------------------------------------------

fn load_rules(dirs: &[PathBuf]) -> Result<Vec<Rule>> {
    let mut profile_map: HashMap<String, ActionToml> = HashMap::new();
    let mut all_rules: Vec<Rule> = Vec::new();

    for dir in dirs {
        if !dir.exists() { continue; }
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("read rules dir {}", dir.display()))?
            .flatten()
            .filter(|e| e.path().extension().map_or(false, |x| x == "toml"))
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read rule file {}", path.display()))?;
            let rf: RuleFile = toml::from_str(&text)
                .with_context(|| format!("parse rule file {}", path.display()))?;

            // Register profiles first (build inheritance map).
            for prof in rf.profile {
                let resolved = resolve_profile_action(&prof, &profile_map);
                profile_map.insert(prof.name.clone(), resolved);
            }

            // Compile rules.
            for r in rf.rule {
                all_rules.push(compile_rule(r, &profile_map)?);
            }
        }
    }

    // Sort by priority descending (stable to preserve file order within same priority).
    all_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    info!("loaded {} rules from {} directories", all_rules.len(), dirs.len());
    Ok(all_rules)
}

fn resolve_profile_action(prof: &ProfileToml, map: &HashMap<String, ActionToml>) -> ActionToml {
    if let Some(ref parent) = prof.inherits {
        if let Some(base) = map.get(parent) {
            let mut merged = base.clone();
            // Override parent with prof's non-None fields.
            if prof.action.cgroup.is_some()          { merged.cgroup          = prof.action.cgroup.clone(); }
            if prof.action.nice.is_some()             { merged.nice             = prof.action.nice; }
            if prof.action.sched_policy.is_some()     { merged.sched_policy     = prof.action.sched_policy.clone(); }
            if prof.action.sched_priority.is_some()   { merged.sched_priority   = prof.action.sched_priority; }
            if prof.action.oom_score_adj.is_some()    { merged.oom_score_adj    = prof.action.oom_score_adj; }
            if prof.action.io_weight.is_some()        { merged.io_weight        = prof.action.io_weight; }
            if prof.action.recheck_secs.is_some()     { merged.recheck_secs     = prof.action.recheck_secs; }
            if prof.action.apply_to_children.is_some(){ merged.apply_to_children = prof.action.apply_to_children; }
            return merged;
        }
    }
    prof.action.clone()
}

fn compile_rule(r: RuleToml, _profiles: &HashMap<String, ActionToml>) -> Result<Rule> {
    let m = &r.r#match;

    let (cgroup_path_glob, cgroup_path_exact) =
        if let Some(ref pattern) = m.cgroup_path {
            if pattern.contains('*') || pattern.contains('?') {
                (Some((pattern.clone(), WildMatch::new(pattern))), None)
            } else {
                (None, Some(pattern.clone()))
            }
        } else {
            (None, None)
        };

    let matchers = Matchers {
        comm:                 m.comm.clone(),
        comm_prefix:          m.comm_prefix.clone(),
        cmdline_contains:     m.cmdline_contains.clone(),
        exe_path:             m.exe_path.iter().map(PathBuf::from).collect(),
        uid:                  m.uid.clone(),
        env_set:              m.env_set.clone(),
        min_threads:          m.min_threads,
        min_rss_mb:           m.min_rss_mb,
        parent_comm:          m.parent_comm.clone(),
        cgroup_path_contains: m.cgroup_path_contains.clone(),
        cgroup_path_glob,
        cgroup_path_exact,
    };

    let at = &r.action;
    let action = Action {
        cgroup:            at.cgroup.clone(),
        nice:              at.nice,
        sched_policy:      at.sched_policy.clone(),
        sched_priority:    at.sched_priority,
        oom_score_adj:     at.oom_score_adj,
        io_weight:         at.io_weight,
        recheck_secs:      at.recheck_secs,
        apply_to_children: at.apply_to_children.unwrap_or(false),
        rule_name:         r.name.clone(),
    };

    Ok(Rule {
        name:      r.name,
        priority:  r.priority,
        matchers,
        action,
        continue_: r.r#continue,
    })
}

/// Merge `src` into `dst`, only overriding fields that are None in dst.
fn merge_action(dst: &mut Action, src: &Action) {
    if dst.cgroup.is_none()         { dst.cgroup         = src.cgroup.clone(); }
    if dst.nice.is_none()           { dst.nice           = src.nice; }
    if dst.sched_policy.is_none()   { dst.sched_policy   = src.sched_policy.clone(); }
    if dst.sched_priority.is_none() { dst.sched_priority = src.sched_priority; }
    if dst.oom_score_adj.is_none()  { dst.oom_score_adj  = src.oom_score_adj; }
    if dst.io_weight.is_none()      { dst.io_weight      = src.io_weight; }
    if dst.recheck_secs.is_none()   { dst.recheck_secs   = src.recheck_secs; }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(comm: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 1234, ppid: 1, uid: 1000, gid: 1000,
            comm: comm.to_string(),
            cmdline: vec![comm.to_string()],
            exe: None, oom_score: 0, threads: 1, vm_rss_kb: 0,
            io_read_bytes: 0, io_write_bytes: 0,
            sched_policy: procmon::SchedPolicy::Normal,
            nice: 0, cgroup_path: None,
            environ: Default::default(),
        }
    }

    #[test]
    fn exception_list_exact_match() {
        let ex = ExceptionList::default();
        let proc = make_proc("chrt");
        assert!(ex.is_exempt(&proc, &[]));
    }

    #[test]
    fn exception_list_ancestor() {
        let ex = ExceptionList::default();
        let proc = make_proc("my-app");
        let ancestors = vec!["gamemoderun".to_string()];
        assert!(ex.is_exempt(&proc, &ancestors));
    }

    #[test]
    fn exception_list_normal_not_exempt() {
        let ex = ExceptionList::default();
        let proc = make_proc("firefox");
        assert!(!ex.is_exempt(&proc, &[]));
    }

    #[test]
    fn matchers_comm_match() {
        let m = Matchers {
            comm: vec!["pipewire".to_string()],
            ..Default::default()
        };
        let proc = make_proc("pipewire");
        assert!(m.matches(&proc, None));
    }

    #[test]
    fn matchers_comm_no_match() {
        let m = Matchers {
            comm: vec!["jackd".to_string()],
            ..Default::default()
        };
        let proc = make_proc("firefox");
        assert!(!m.matches(&proc, None));
    }

    #[test]
    fn wildmatch_cgroup_glob() {
        use wildmatch::WildMatch;
        let pattern = "/user.slice/*.service";
        let glob = WildMatch::new(pattern);
        assert!(glob.matches("/user.slice/app.service"));
        assert!(!glob.matches("/system.slice/app.service"));
    }
}
