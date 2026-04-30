use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use adblock::{
    Engine,
    lists::{FilterSet, ParseOptions, RuleTypes},
    request::Request,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

use super::socks5::TargetAddr;

const DEFAULT_UPDATE_INTERVAL_HOURS: u64 = 24;
const DEFAULT_DECISION_CACHE_TTL_SECS: u64 = 300;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AdblockConfig {
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<String>,
    pub cache_dir: Option<PathBuf>,
    pub update_interval_hours: u64,
    pub decision_cache_ttl_secs: u64,
    pub fail_open: bool,
}

impl Default for AdblockConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            lists: Vec::new(),
            cache_dir: None,
            update_interval_hours: DEFAULT_UPDATE_INTERVAL_HOURS,
            decision_cache_ttl_secs: DEFAULT_DECISION_CACHE_TTL_SECS,
            fail_open: true,
        }
    }
}

impl AdblockConfig {
    pub fn is_active(&self) -> bool {
        self.enabled.unwrap_or(!self.lists.is_empty()) && !self.lists.is_empty()
    }

    pub fn with_base_dir(&self, base_dir: &Path) -> Self {
        let mut resolved = self.clone();
        resolved.cache_dir = self
            .cache_dir
            .as_ref()
            .map(|path| resolve_path(base_dir, path));
        resolved.lists = self
            .lists
            .iter()
            .map(|source| resolve_source(base_dir, source))
            .collect();
        resolved
    }
}

pub struct Adblocker {
    engine: RwLock<Option<Engine>>,
    cache: Mutex<HashMap<String, CachedDecision>>,
    cache_ttl: Duration,
}

#[derive(Clone, Copy, Debug)]
struct CachedDecision {
    blocked: bool,
    expires_at: Instant,
}

impl Adblocker {
    pub async fn from_config(config: &AdblockConfig) -> Result<Option<Arc<Self>>> {
        if !config.is_active() {
            return Ok(None);
        }

        let adblocker = Arc::new(Self {
            engine: RwLock::new(None),
            cache: Mutex::new(HashMap::new()),
            cache_ttl: Duration::from_secs(config.decision_cache_ttl_secs),
        });
        spawn_loader(adblocker.clone(), config.clone());
        info!(
            lists = config.lists.len(),
            "adblock engine loading in background"
        );
        Ok(Some(adblocker))
    }

    pub async fn blocks_target(&self, target: &TargetAddr) -> bool {
        match target {
            TargetAddr::Domain(host, port) => self.blocks_domain_with_port(host, *port).await,
            TargetAddr::Ip(_, _) => false,
        }
    }

    pub async fn blocks_domain(&self, domain: &str) -> bool {
        self.blocks_domain_with_scheme(domain, "https").await
    }

    async fn blocks_domain_with_port(&self, domain: &str, port: u16) -> bool {
        let scheme = if port == 80 { "http" } else { "https" };
        self.blocks_domain_with_scheme(domain, scheme).await
    }

    async fn blocks_domain_with_scheme(&self, domain: &str, scheme: &str) -> bool {
        let domain = normalize_domain(domain);
        if domain.is_empty() || domain.parse::<IpAddr>().is_ok() {
            return false;
        }

        let cache_key = format!("{scheme}://{domain}");
        let now = Instant::now();
        if let Some(cached) = self.cache.lock().await.get(&cache_key).copied()
            && cached.expires_at > now
        {
            return cached.blocked;
        }

        let Some(blocked) = self.check_domain(&domain, scheme).await else {
            return false;
        };
        self.cache.lock().await.insert(
            cache_key,
            CachedDecision {
                blocked,
                expires_at: now + self.cache_ttl,
            },
        );
        blocked
    }

    async fn check_domain(&self, domain: &str, scheme: &str) -> Option<bool> {
        let engine = self.engine.read().await;
        let engine = engine.as_ref()?;
        let url = format!("{scheme}://{domain}/");
        let request = Request::preparsed(&url, domain, "", "other", true);
        let result = engine.check_network_request(&request);
        Some(result.matched && result.exception.is_none())
    }

    #[cfg(test)]
    pub(crate) fn from_rules_for_test(rules: &[&str]) -> Arc<Self> {
        let mut filter_set = FilterSet::new(true);
        filter_set.add_filters(
            rules,
            ParseOptions {
                rule_types: RuleTypes::NetworkOnly,
                ..ParseOptions::default()
            },
        );
        Arc::new(Self {
            engine: RwLock::new(Some(Engine::from_filter_set(filter_set, true))),
            cache: Mutex::new(HashMap::new()),
            cache_ttl: Duration::from_secs(DEFAULT_DECISION_CACHE_TTL_SECS),
        })
    }
}

fn spawn_loader(adblocker: Arc<Adblocker>, config: AdblockConfig) {
    drop(tokio::spawn(async move {
        match load_filter_engine(&config).await {
            Ok(Some((engine, loaded))) => {
                *adblocker.engine.write().await = Some(engine);
                adblocker.cache.lock().await.clear();
                info!(lists = loaded, "adblock engine loaded");
            }
            Ok(None) => {
                warn!(
                    "adblock is enabled but no filter lists were loaded; continuing without adblock"
                );
            }
            Err(err) => {
                warn!(error = %err, "adblock engine failed to load in background");
            }
        }
    }));
}

async fn load_filter_engine(config: &AdblockConfig) -> Result<Option<(Engine, usize)>> {
    let mut contents = Vec::new();
    for source in &config.lists {
        match load_list_source(source, config).await {
            Ok(Some(content)) => {
                contents.push(content);
            }
            Ok(None) => {}
            Err(err) if config.fail_open => {
                warn!(source = %source, error = %err, "adblock list skipped");
            }
            Err(err) => return Err(err),
        }
    }

    let loaded = contents.len();
    if loaded == 0 {
        return Ok(None);
    }

    let engine = tokio::task::spawn_blocking(move || build_filter_engine(contents))
        .await
        .context("adblock engine build task failed")?;
    Ok(Some((engine, loaded)))
}

fn build_filter_engine(contents: Vec<String>) -> Engine {
    let mut filter_set = FilterSet::new(false);
    for content in contents {
        filter_set.add_filter_list(
            &content,
            ParseOptions {
                rule_types: RuleTypes::NetworkOnly,
                ..ParseOptions::default()
            },
        );
    }
    Engine::from_filter_set(filter_set, true)
}

async fn load_list_source(source: &str, config: &AdblockConfig) -> Result<Option<String>> {
    if is_http_url(source) {
        load_url_list(source, config).await
    } else {
        load_local_list(source, config).await
    }
}

async fn load_local_list(source: &str, config: &AdblockConfig) -> Result<Option<String>> {
    match tokio::fs::read_to_string(source).await {
        Ok(content) => Ok(Some(content)),
        Err(err) if config.fail_open => {
            warn!(source = %source, error = %err, "adblock local list skipped");
            Ok(None)
        }
        Err(err) => Err(err).with_context(|| format!("failed to read adblock list {}", source)),
    }
}

async fn load_url_list(source: &str, config: &AdblockConfig) -> Result<Option<String>> {
    let cache_dir = config
        .cache_dir
        .clone()
        .unwrap_or_else(default_adblock_cache_dir);
    let cache_path = cache_dir.join(cache_file_name(source));
    if cache_is_fresh(&cache_path, config.update_interval_hours) {
        return tokio::fs::read_to_string(&cache_path)
            .await
            .map(Some)
            .with_context(|| {
                format!(
                    "failed to read cached adblock list {}",
                    cache_path.display()
                )
            });
    }

    match download_list(source).await {
        Ok(content) => {
            if let Err(err) = tokio::fs::create_dir_all(&cache_dir).await {
                warn!(path = %cache_dir.display(), error = %err, "failed to create adblock cache directory");
            } else if let Err(err) = tokio::fs::write(&cache_path, &content).await {
                warn!(path = %cache_path.display(), error = %err, "failed to write adblock cache");
            }
            Ok(Some(content))
        }
        Err(err) => {
            if cache_path.exists() {
                warn!(source = %source, error = %err, "using stale cached adblock list");
                return tokio::fs::read_to_string(&cache_path)
                    .await
                    .map(Some)
                    .with_context(|| {
                        format!(
                            "failed to read stale cached adblock list {}",
                            cache_path.display()
                        )
                    });
            }
            if config.fail_open {
                warn!(source = %source, error = %err, "adblock subscription skipped");
                Ok(None)
            } else {
                Err(err)
            }
        }
    }
}

async fn download_list(source: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .context("failed to build adblock list HTTP client")?;
    let response = client
        .get(source)
        .send()
        .await
        .with_context(|| format!("failed to download adblock list {source}"))?
        .error_for_status()
        .with_context(|| format!("adblock list {source} returned an error status"))?;
    response
        .text()
        .await
        .with_context(|| format!("failed to read adblock list {source}"))
}

fn cache_is_fresh(path: &Path, update_interval_hours: u64) -> bool {
    if update_interval_hours == 0 {
        return false;
    }
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    age <= Duration::from_secs(update_interval_hours.saturating_mul(3600))
}

fn cache_file_name(source: &str) -> String {
    let digest = Sha256::digest(source.as_bytes());
    format!("{}.txt", hex::encode(digest))
}

fn default_adblock_cache_dir() -> PathBuf {
    if let Some(cache_home) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(cache_home).join("runnel").join("adblock");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".cache")
            .join("runnel")
            .join("adblock");
    }
    std::env::temp_dir().join("runnel-adblock")
}

fn resolve_source(base_dir: &Path, source: &str) -> String {
    if is_http_url(source) {
        return source.to_owned();
    }
    resolve_path(base_dir, Path::new(source))
        .display()
        .to_string()
}

fn resolve_path(base_dir: &Path, path: &Path) -> PathBuf {
    if let Some(expanded) = expand_home(path) {
        return expanded;
    }
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn expand_home(path: &Path) -> Option<PathBuf> {
    let raw = path.to_string_lossy();
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    if raw == "~" {
        return Some(home);
    }
    raw.strip_prefix("~/").map(|rest| home.join(rest))
}

fn is_http_url(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

fn normalize_domain(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn adblocker_blocks_network_rule_domain() {
        let adblock = Adblocker::from_rules_for_test(&["||ads.example^"]);

        assert!(adblock.blocks_domain("ads.example").await);
        assert!(adblock.blocks_domain("cdn.ads.example").await);
        assert!(!adblock.blocks_domain("example.com").await);
    }

    #[tokio::test]
    async fn from_config_starts_before_lists_are_loaded() {
        let suffix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let config = AdblockConfig {
            lists: vec![
                std::env::temp_dir()
                    .join(format!("missing-runnel-adblock-{suffix}.txt"))
                    .display()
                    .to_string(),
            ],
            fail_open: false,
            ..AdblockConfig::default()
        };

        let adblock = Adblocker::from_config(&config).await.unwrap().unwrap();

        assert!(!adblock.blocks_domain("ads.example").await);
    }

    #[tokio::test]
    async fn from_config_loads_lists_in_background() {
        let suffix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "runnel-adblock-background-{}-{suffix}.txt",
            std::process::id()
        ));
        tokio::fs::write(&path, "||ads.example^\n").await.unwrap();
        let config = AdblockConfig {
            lists: vec![path.display().to_string()],
            ..AdblockConfig::default()
        };

        let adblock = Adblocker::from_config(&config).await.unwrap().unwrap();
        let mut loaded = false;
        for _ in 0..20 {
            if adblock.blocks_domain("ads.example").await {
                loaded = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let _ = tokio::fs::remove_file(path).await;
        assert!(loaded);
    }

    #[test]
    fn config_defaults_enable_when_lists_are_present() {
        let config = AdblockConfig {
            lists: vec!["easylist.txt".to_owned()],
            ..AdblockConfig::default()
        };

        assert!(config.is_active());
    }

    #[test]
    fn config_enabled_false_disables_lists() {
        let config = AdblockConfig {
            enabled: Some(false),
            lists: vec!["easylist.txt".to_owned()],
            ..AdblockConfig::default()
        };

        assert!(!config.is_active());
    }

    #[test]
    fn relative_sources_use_config_base_dir() {
        let config = AdblockConfig {
            lists: vec![
                "lists/easylist.txt".to_owned(),
                "https://example.com/easyprivacy.txt".to_owned(),
            ],
            cache_dir: Some(PathBuf::from("cache")),
            ..AdblockConfig::default()
        };
        let resolved = config.with_base_dir(Path::new("/tmp/runnel"));

        assert_eq!(resolved.lists[0], "/tmp/runnel/lists/easylist.txt");
        assert_eq!(resolved.lists[1], "https://example.com/easyprivacy.txt");
        assert_eq!(resolved.cache_dir, Some(PathBuf::from("/tmp/runnel/cache")));
    }

    #[test]
    fn tilde_sources_use_home_directory() {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return;
        };
        let config = AdblockConfig {
            lists: vec!["~/easylist.txt".to_owned()],
            ..AdblockConfig::default()
        };
        let resolved = config.with_base_dir(Path::new("/tmp/runnel"));

        assert_eq!(
            resolved.lists[0],
            home.join("easylist.txt").display().to_string()
        );
    }
}
