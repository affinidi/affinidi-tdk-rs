//! Every mediator entry packed into one physical secret.
//!
//! Per-key backends (AWS, GCP, Azure, Vault, keyring) used to get one
//! backend secret per well-known key, plus a short-lived one per probe
//! sentinel and bootstrap seed. [`BundledStore`] wraps such a backend and
//! keeps every entry inside the single [`SECRETS_BUNDLE`] secret instead:
//! a `secrets-bundle` envelope whose `entries` map each logical key to
//! its bytes (base64url). Callers still see the plain
//! [`SecretStore`] key/value surface.
//!
//! ## Migrating the per-key layout
//!
//! There is no way to keep running on the per-key layout: a deployment
//! that can't be moved fails with [`SecretStoreError::MigrationFailed`],
//! naming the cause and the fix, so the per-key code path can later be
//! removed without stranding anyone. The move itself is built so that a
//! failure at any point leaves a store that the current *and* an older
//! mediator run against unchanged: the per-key secrets stay the source of
//! truth until a mediator has started on the bundle. The bundle records how
//! far a migration got in its `state`:
//!
//! 1. **`staged`** — every per-key value is first checked to be a readable
//!    entry (nothing is written otherwise), then copied into a bundle
//!    marked `staged` and read back byte for byte. A staged bundle is
//!    never used: the next start copies the per-key secrets again.
//! 2. **`mirrored`** — the verified copy is re-marked and verified again.
//!    Reads now come from the bundle, but every write goes to the per-key
//!    secret *first* and then to the bundle, so the per-key secrets stay
//!    complete and an older mediator keeps working. Each start checks the
//!    bundle still matches them and copies again if not (an older
//!    mediator wrote in between, or a write reached only one side).
//! 3. **`active`** — [`BundledStore::confirm_cutover`], which the mediator
//!    calls once it has loaded its configuration from the bundle and bound
//!    its listener, checks the match a last time, marks the bundle active
//!    and deletes the per-key secrets (and stray `mediator_probe_<uuid>`
//!    sentinels). Deletes that fail are retried on later starts. Only from
//!    here does an older mediator stop working. Setup tooling never
//!    confirms.
//!
//! A step that fails deletes its partial bundle again before returning the
//! error. A bundle that exists but can't be parsed is an error too: it is
//! never overwritten.
//!
//! A deployment with neither layout is fresh and starts `active`.
//!
//! The copy covers the fixed well-known keys and the bootstrap seeds the
//! sweep index lists, plus — where the backend can enumerate its own keys
//! ([`SecretStore::list_keys`]) — seeds the index lost.
//!
//! ## Writers
//!
//! Every `put` / `delete` reads, modifies and rewrites the whole bundle
//! under a per-store lock, so writers in one process never lose each
//! other's updates. Two *processes* writing at the same instant can (the
//! trait has no compare-and-swap); the mediator is single-writer per the
//! HA design, and setup tooling runs while it is stopped.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::secrets::envelope::{ENVELOPE_VERSION, Envelope};
use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::{DynSecretStore, SecretStore};
use crate::secrets::well_known::{
    ADMIN_CREDENTIAL, BOOTSTRAP_EPHEMERAL_SEED_PREFIX, BOOTSTRAP_SEED_INDEX, BootstrapSeedIndex,
    JWT_SECRET, KIND_SEED_INDEX, OPERATING_DID_DOCUMENT, OPERATING_KEY_AGREEMENT,
    OPERATING_SECRETS, OPERATING_SIGNING, PROBE_SENTINEL_PREFIX, VTA_LAST_KNOWN_BUNDLE,
};

/// The one backend secret that holds every mediator entry on per-key
/// backends. Distinct from the pre-0.14 `security.mediator_secrets` TOML
/// field, whose operator-named secret could otherwise collide.
pub const SECRETS_BUNDLE: &str = "mediator_secrets_bundle";

const KIND_BUNDLE: &str = "secrets-bundle";

/// How long a read of the bundle is reused for `get` / `list_keys`. Cloud
/// secret stores bill per API call, and one `/readyz` poll alone reads
/// several entries. Writes always read fresh and refresh the cache, so a
/// process sees its own writes at once; another process's writes show up
/// within this window.
const READ_CACHE_TTL: Duration = Duration::from_secs(30);

/// Well-known keys that had their own backend secret before the bundle.
/// Bootstrap seeds are found through the index (and `list_keys`).
const LEGACY_KEYS: &[&str] = &[
    ADMIN_CREDENTIAL,
    JWT_SECRET,
    OPERATING_SECRETS,
    OPERATING_SIGNING,
    OPERATING_KEY_AGREEMENT,
    OPERATING_DID_DOCUMENT,
    VTA_LAST_KNOWN_BUNDLE,
    BOOTSTRAP_SEED_INDEX,
];

/// How far a migration got. See the module docs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum State {
    /// The bundle is the source of truth.
    #[default]
    Active,
    /// Copied but not yet verified: ignored, and rebuilt on the next start.
    Staged,
    /// Verified copy of the per-key secrets, which stay the source of truth
    /// (and are written first) until the cutover is confirmed.
    Mirrored,
}

impl State {
    fn is_active(&self) -> bool {
        *self == State::Active
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Bundle {
    #[serde(default, skip_serializing_if = "State::is_active")]
    state: State,
    /// Logical key → entry bytes, base64url without padding.
    entries: BTreeMap<String, String>,
    /// Per-key secrets this bundle replaces: mirrored until the cutover,
    /// then deleted (whatever is still listed once `active` is a delete
    /// that failed and is retried).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    legacy_keys: Vec<String>,
    /// Stray `mediator_probe_<uuid>` sentinels, deleted at the cutover.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    stray_keys: Vec<String>,
}

impl Bundle {
    fn open(bytes: &[u8]) -> Result<Self> {
        Envelope::open(bytes, SECRETS_BUNDLE, KIND_BUNDLE)
    }

    fn seal(&self) -> Result<Vec<u8>> {
        Envelope::new(KIND_BUNDLE, self).seal()
    }

    fn entry(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let Some(encoded) = self.entries.get(key) else {
            return Ok(None);
        };
        B64URL
            .decode(encoded.as_bytes())
            .map(Some)
            .map_err(|e| SecretStoreError::InvalidShape {
                key: format!("{SECRETS_BUNDLE}[{key}]"),
                reason: format!("bundle entry is not valid base64url: {e}"),
            })
    }

    /// Returns whether the entry changed.
    fn insert(&mut self, key: &str, value: &[u8]) -> bool {
        let encoded = B64URL.encode(value);
        if self.entries.get(key) == Some(&encoded) {
            return false;
        }
        self.entries.insert(key.to_string(), encoded);
        true
    }

    /// Whether `entries` holds exactly `legacy`, byte for byte.
    fn matches(&self, legacy: &BTreeMap<String, Vec<u8>>) -> bool {
        self.entries.len() == legacy.len()
            && legacy
                .iter()
                .all(|(key, value)| matches!(self.entry(key), Ok(Some(stored)) if &stored == value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// Every entry lives in [`SECRETS_BUNDLE`].
    Active,
    /// Reads from the bundle; writes to the per-key secrets, then the
    /// bundle. Until [`BundledStore::confirm_cutover`].
    Mirrored,
}

fn migration_failed(reason: impl Into<String>, action: impl Into<String>) -> SecretStoreError {
    SecretStoreError::MigrationFailed {
        reason: reason.into(),
        action: action.into(),
    }
}

/// [`SecretStore`] that packs every entry of a per-key backend into the
/// single [`SECRETS_BUNDLE`] secret. See the module docs.
pub struct BundledStore {
    inner: DynSecretStore,
    /// Decided on first use; the cutover moves it to `Active`.
    layout: std::sync::Mutex<Option<Layout>>,
    resolving: Mutex<()>,
    /// Last bundle read or written, and when. See [`READ_CACHE_TTL`].
    cached: std::sync::Mutex<Option<(Instant, Option<Bundle>)>>,
    write_lock: Mutex<()>,
}

impl BundledStore {
    pub fn new(inner: DynSecretStore) -> Self {
        Self {
            inner,
            layout: std::sync::Mutex::new(None),
            resolving: Mutex::new(()),
            cached: std::sync::Mutex::new(None),
            write_lock: Mutex::new(()),
        }
    }

    /// Decide the layout now, running a migration if the store still has
    /// the per-key layout, so a failure surfaces at a known point rather
    /// than on whichever read happens first. Errors with
    /// [`SecretStoreError::MigrationFailed`] when the store can't be moved.
    pub async fn ensure_migrated(&self) -> Result<()> {
        self.layout().await.map(|_| ())
    }

    /// Finish a migration once the mediator has started on the bundle:
    /// re-check that the bundle matches the per-key secrets, mark it the
    /// source of truth, and delete the per-key secrets. Returns `true` when
    /// this call made the cutover, `false` when there was none to make.
    /// Nothing is deleted unless the cutover was recorded and read back.
    pub async fn confirm_cutover(&self) -> Result<bool> {
        if self.layout().await? != Layout::Mirrored {
            return Ok(false);
        }
        let _guard = self.write_lock.lock().await;
        let Some(mut bundle) = self.read_bundle().await? else {
            return Err(migration_failed(
                format!("{SECRETS_BUNDLE} disappeared before the cutover. Nothing was deleted"),
                format!("check whether another process deletes {SECRETS_BUNDLE}"),
            ));
        };
        if bundle.state != State::Mirrored {
            return Ok(false);
        }
        let legacy = self.collect_legacy().await?;
        if !legacy.is_empty() && !bundle.matches(&legacy) {
            return Err(migration_failed(
                format!(
                    "the per-key secrets changed while this mediator was starting, so \
                     another process (likely an older mediator) is writing to them. \
                     Nothing was deleted: the per-key secrets and {SECRETS_BUNDLE} are \
                     both intact, and the next start copies them again"
                ),
                "stop every other mediator using this secret store",
            ));
        }

        let mirrored = bundle.seal()?;
        bundle.state = State::Active;
        self.forget();
        self.inner.put(SECRETS_BUNDLE, &bundle.seal()?).await?;
        if let Err(why) = self.verify(&bundle, &legacy).await {
            // An unverified `active` bundle would have the next start delete
            // the per-key secrets on its word: put the mirrored one back.
            self.forget();
            return Err(match self.inner.put(SECRETS_BUNDLE, &mirrored).await {
                Ok(()) => migration_failed(
                    format!(
                        "recording the cutover to {SECRETS_BUNDLE} failed: {why}. It was \
                         undone and nothing was deleted"
                    ),
                    format!("check whether another process is writing {SECRETS_BUNDLE}"),
                ),
                Err(e) => migration_failed(
                    format!(
                        "recording the cutover to {SECRETS_BUNDLE} failed: {why}, and it \
                         could not be undone ({e}). Nothing was deleted yet, but the next \
                         start may treat {SECRETS_BUNDLE} as current and delete the \
                         per-key secrets"
                    ),
                    format!(
                        "compare {SECRETS_BUNDLE} with the per-key secrets; if they differ, \
                         delete {SECRETS_BUNDLE} so the next start copies them again"
                    ),
                ),
            });
        }
        self.set_layout(Layout::Active);
        info!(
            backend = self.inner.backend(),
            secrets = bundle.legacy_keys.len(),
            "cut over to the single {SECRETS_BUNDLE} secret; deleting the per-key \
             secrets it replaces. A mediator older than 0.38.0 can no longer run \
             against this secret store"
        );
        self.finish_cleanup(&mut bundle).await;
        Ok(true)
    }

    /// Delete everything this store holds: the bundle and any per-key
    /// secrets (and indexed seeds) that still exist.
    pub async fn purge(&self) -> Result<()> {
        // Resolve before locking: a first-use migration takes the lock too.
        let layout = self.layout().await?;
        let _guard = self.write_lock.lock().await;
        if layout == Layout::Mirrored {
            for key in self.collect_legacy().await?.into_keys() {
                self.inner.delete(&key).await?;
            }
        }
        if let Some(bundle) = self.read_bundle().await? {
            for key in bundle.legacy_keys.iter().chain(&bundle.stray_keys) {
                self.inner.delete(key).await?;
            }
        }
        self.forget();
        self.inner.delete(SECRETS_BUNDLE).await
    }

    /// Read `key` from the backend, never from the read cache — for a
    /// caller checking that its write survived another process's.
    pub async fn get_fresh(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.layout().await?;
        match self.read_bundle().await? {
            Some(bundle) => bundle.entry(key),
            None => Ok(None),
        }
    }

    fn current_layout(&self) -> Option<Layout> {
        self.layout.lock().ok().and_then(|layout| *layout)
    }

    fn set_layout(&self, layout: Layout) {
        if let Ok(mut current) = self.layout.lock() {
            *current = Some(layout);
        }
    }

    async fn layout(&self) -> Result<Layout> {
        if let Some(layout) = self.current_layout() {
            return Ok(layout);
        }
        let _resolving = self.resolving.lock().await;
        if let Some(layout) = self.current_layout() {
            return Ok(layout);
        }
        // An error leaves the layout undecided, so the next call retries.
        let layout = self.resolve().await?;
        self.set_layout(layout);
        Ok(layout)
    }

    async fn resolve(&self) -> Result<Layout> {
        let existing = match self.get_bundle_bytes().await {
            Ok(existing) => existing,
            Err(e) => {
                // Readable per-key secrets mean the backend is up and this
                // is about the bundle itself — usually a role scoped to the
                // per-key names.
                if self.any_legacy_key_readable().await {
                    return Err(migration_failed(
                        format!(
                            "{SECRETS_BUNDLE} could not be read ({e}), although the per-key \
                             secrets can. Nothing was changed"
                        ),
                        format!(
                            "grant this mediator read, create and write access to \
                             {SECRETS_BUNDLE} (with your backend's prefix)"
                        ),
                    ));
                }
                return Err(e);
            }
        };
        let Some(bytes) = existing else {
            return self.migrate().await;
        };
        let mut bundle = Bundle::open(&bytes).map_err(|e| {
            migration_failed(
                format!("{SECRETS_BUNDLE} exists but can't be read ({e}). Nothing was changed"),
                format!(
                    "if this deployment's per-key secrets still exist (the migration was \
                     never confirmed), delete {SECRETS_BUNDLE} so the next start copies \
                     them again; otherwise restore {SECRETS_BUNDLE} from a backup"
                ),
            )
        })?;
        match bundle.state {
            State::Active => {
                if !bundle.legacy_keys.is_empty() || !bundle.stray_keys.is_empty() {
                    let _guard = self.write_lock.lock().await;
                    self.finish_cleanup(&mut bundle).await;
                }
                Ok(Layout::Active)
            }
            State::Staged => {
                info!(
                    "found an unfinished copy in {SECRETS_BUNDLE}; copying the per-key \
                     secrets again"
                );
                self.migrate().await
            }
            State::Mirrored => {
                let legacy = self.collect_legacy().await?;
                if legacy.is_empty() || bundle.matches(&legacy) {
                    return Ok(Layout::Mirrored);
                }
                info!(
                    "the per-key secrets changed since {SECRETS_BUNDLE} was copied from \
                     them; copying them again"
                );
                self.migrate().await
            }
        }
    }

    async fn any_legacy_key_readable(&self) -> bool {
        for key in LEGACY_KEYS {
            if let Ok(Some(_)) = self.inner.get(key).await {
                return true;
            }
        }
        false
    }

    /// Copy the per-key layout into a verified, mirrored bundle, or fail
    /// leaving the store as it was. See the module docs.
    async fn migrate(&self) -> Result<Layout> {
        let _guard = self.write_lock.lock().await;
        let legacy = self.collect_legacy().await?;
        if legacy.is_empty() {
            // Nothing to copy. A leftover staged/mirrored bundle with no
            // per-key secrets behind it can't be trusted or rebuilt.
            if let Some(bundle) = self.read_bundle().await?
                && bundle.state != State::Active
            {
                return Err(migration_failed(
                    format!(
                        "{SECRETS_BUNDLE} holds an unconfirmed copy, but the per-key \
                         secrets it was copied from are gone. Nothing was changed"
                    ),
                    format!(
                        "restore the per-key secrets, or delete {SECRETS_BUNDLE} to start \
                         as a fresh deployment"
                    ),
                ));
            }
            return Ok(Layout::Active);
        }

        // 1. Never copy something the mediator couldn't read anyway.
        for (key, value) in &legacy {
            if let Err(why) = readable_entry(value) {
                return Err(migration_failed(
                    format!(
                        "the per-key secret {key} is not a readable entry ({why}), so it \
                         was not copied into {SECRETS_BUNDLE}. Nothing was changed"
                    ),
                    format!("repair or remove the {key} secret"),
                ));
            }
        }

        // 2. Stage: written, read back, and still ignored by everyone.
        let mut bundle = Bundle {
            state: State::Staged,
            entries: BTreeMap::new(),
            legacy_keys: legacy.keys().cloned().collect(),
            stray_keys: self.stray_probe_sentinels().await,
        };
        for (key, value) in &legacy {
            bundle.insert(key, value);
        }
        self.forget();
        if let Err(e) = self.inner.put(SECRETS_BUNDLE, &bundle.seal()?).await {
            return Err(migration_failed(
                format!("{SECRETS_BUNDLE} could not be written ({e}). Nothing was changed"),
                format!(
                    "grant this mediator create and write access to {SECRETS_BUNDLE} \
                     (with your backend's prefix)"
                ),
            ));
        }
        if let Err(why) = self.verify(&bundle, &legacy).await {
            return Err(self.roll_back(&why).await);
        }

        // 3. Mirror: readable from now on, per-key secrets still written first.
        bundle.state = State::Mirrored;
        if let Err(why) = match self.inner.put(SECRETS_BUNDLE, &bundle.seal()?).await {
            Ok(()) => self.verify(&bundle, &legacy).await,
            Err(e) => Err(format!("it could not be marked verified ({e})")),
        } {
            return Err(self.roll_back(&why).await);
        }
        info!(
            backend = self.inner.backend(),
            secrets = legacy.len(),
            "copied the per-key mediator secrets into {SECRETS_BUNDLE} and verified \
             them. The per-key secrets are kept, and written alongside the bundle, \
             until a mediator has started on the new layout; until then an older \
             mediator still runs against them"
        );
        Ok(Layout::Mirrored)
    }

    /// Read the bundle back from the backend and require it to equal
    /// `bundle`, with every per-key value present byte for byte.
    async fn verify(
        &self,
        bundle: &Bundle,
        legacy: &BTreeMap<String, Vec<u8>>,
    ) -> std::result::Result<(), String> {
        let stored = match self.read_bundle().await {
            Ok(Some(stored)) => stored,
            Ok(None) => return Err(format!("{SECRETS_BUNDLE} was missing on read-back")),
            Err(e) => return Err(format!("{SECRETS_BUNDLE} could not be read back ({e})")),
        };
        if &stored != bundle || !stored.matches(legacy) {
            return Err(format!(
                "{SECRETS_BUNDLE} read back differently from what was written"
            ));
        }
        Ok(())
    }

    /// Undo a failed copy: delete the partial bundle, and say how that went.
    async fn roll_back(&self, why: &str) -> SecretStoreError {
        self.forget();
        match self.inner.delete(SECRETS_BUNDLE).await {
            Ok(()) => migration_failed(
                format!(
                    "copying the per-key secrets into {SECRETS_BUNDLE} failed: {why}. The \
                     partial copy was removed, so nothing was changed"
                ),
                format!("check whether another process is writing {SECRETS_BUNDLE}"),
            ),
            Err(e) => migration_failed(
                format!(
                    "copying the per-key secrets into {SECRETS_BUNDLE} failed: {why}, and \
                     the partial copy could not be removed ({e}). It is marked unfinished, \
                     so every mediator ignores it, and the per-key secrets are untouched"
                ),
                format!(
                    "check whether another process is writing {SECRETS_BUNDLE}; you may \
                     delete {SECRETS_BUNDLE} by hand"
                ),
            ),
        }
    }

    /// Every per-key entry present: the fixed keys, the seeds the index
    /// lists, and (where the backend can enumerate) seeds it doesn't.
    async fn collect_legacy(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut found: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for key in LEGACY_KEYS {
            if let Some(value) = self.inner.get(key).await? {
                found.insert((*key).to_string(), value);
            }
        }

        let mut seed_keys = Vec::new();
        if let Some(index) = found.get(BOOTSTRAP_SEED_INDEX)
            && let Ok(index) =
                Envelope::<BootstrapSeedIndex>::open(index, BOOTSTRAP_SEED_INDEX, KIND_SEED_INDEX)
        {
            seed_keys.extend(
                index
                    .entries
                    .into_iter()
                    .map(|e| format!("{BOOTSTRAP_EPHEMERAL_SEED_PREFIX}{}", e.bundle_id_hex)),
            );
        }
        if let Ok(keys) = self.inner.list_keys().await {
            seed_keys.extend(
                keys.into_iter()
                    .filter(|k| is_hex_suffixed(k, BOOTSTRAP_EPHEMERAL_SEED_PREFIX)),
            );
        }
        for key in seed_keys {
            if found.contains_key(&key) {
                continue;
            }
            if let Some(value) = self.inner.get(&key).await? {
                found.insert(key, value);
            }
        }
        Ok(found)
    }

    /// `mediator_probe_<uuid>` sentinels a probe failed to delete. Empty
    /// when the backend can't enumerate its own keys.
    async fn stray_probe_sentinels(&self) -> Vec<String> {
        match self.inner.list_keys().await {
            Ok(keys) => keys
                .into_iter()
                .filter(|k| is_hex_suffixed(k, PROBE_SENTINEL_PREFIX))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Delete the per-key and stray secrets an active bundle still lists,
    /// then record which are left. Failures are logged and retried on the
    /// next start; they never fail the caller, whose data is in the bundle.
    async fn finish_cleanup(&self, bundle: &mut Bundle) {
        let mut changed = false;
        for list in [&mut bundle.legacy_keys, &mut bundle.stray_keys] {
            let mut left = Vec::new();
            for key in std::mem::take(list) {
                match self.inner.delete(&key).await {
                    Ok(()) => changed = true,
                    Err(e) => {
                        warn!(
                            key = %key,
                            error = %e,
                            "could not delete a per-key secret {SECRETS_BUNDLE} replaces; \
                             will retry on the next start"
                        );
                        left.push(key);
                    }
                }
            }
            *list = left;
        }
        if !changed {
            return;
        }
        self.forget();
        let written = match bundle.seal() {
            Ok(bytes) => self.inner.put(SECRETS_BUNDLE, &bytes).await,
            Err(e) => Err(e),
        };
        if let Err(e) = written {
            warn!(
                error = %e,
                "could not record the per-key secret cleanup; the next start will \
                 retry deletes that already succeeded"
            );
        }
    }

    /// The stored bundle bytes. An empty value counts as no bundle, so
    /// infrastructure-as-code can pre-create the secret empty (backends
    /// store base64url, so a hand-written envelope would not parse).
    async fn get_bundle_bytes(&self) -> Result<Option<Vec<u8>>> {
        Ok(self
            .inner
            .get(SECRETS_BUNDLE)
            .await?
            .filter(|bytes| !bytes.is_empty()))
    }

    /// Read the bundle from the backend, bypassing (and refreshing) the
    /// read cache.
    async fn read_bundle(&self) -> Result<Option<Bundle>> {
        let bundle = match self.get_bundle_bytes().await? {
            Some(bytes) => Some(Bundle::open(&bytes)?),
            None => None,
        };
        self.remember(bundle.clone());
        Ok(bundle)
    }

    /// The bundle as of at most [`READ_CACHE_TTL`] ago.
    async fn cached_bundle(&self) -> Result<Option<Bundle>> {
        if let Ok(cached) = self.cached.lock()
            && let Some((at, bundle)) = cached.as_ref()
            && at.elapsed() < READ_CACHE_TTL
        {
            return Ok(bundle.clone());
        }
        self.read_bundle().await
    }

    fn remember(&self, bundle: Option<Bundle>) {
        if let Ok(mut cached) = self.cached.lock() {
            *cached = Some((Instant::now(), bundle));
        }
    }

    fn forget(&self) {
        if let Ok(mut cached) = self.cached.lock() {
            *cached = None;
        }
    }

    /// Read-modify-write the bundle under the write lock, always from a
    /// fresh read so another process's writes aren't overwritten with a
    /// cached copy. `edit` returns whether it changed anything; an
    /// unchanged bundle isn't rewritten.
    async fn update(&self, edit: impl FnOnce(&mut Bundle) -> bool + Send) -> Result<()> {
        let _guard = self.write_lock.lock().await;
        let mut bundle = self.read_bundle().await?.unwrap_or_default();
        if !edit(&mut bundle) {
            return Ok(());
        }
        match self.inner.put(SECRETS_BUNDLE, &bundle.seal()?).await {
            Ok(()) => {
                self.remember(Some(bundle));
                Ok(())
            }
            Err(e) => {
                self.forget();
                Err(e)
            }
        }
    }

    /// While mirrored, a change reached the per-key secret but not the
    /// bundle. The next start sees the mismatch and copies again, so the
    /// per-key value wins; say so rather than report a plain failure.
    fn mirror_failed(key: &str, e: SecretStoreError) -> SecretStoreError {
        SecretStoreError::Other(format!(
            "{key} was changed in its per-key secret but not in {SECRETS_BUNDLE} ({e}); \
             the next start copies the per-key secrets into {SECRETS_BUNDLE} again"
        ))
    }
}

/// `bytes` parse as an entry envelope of a version this build reads.
fn readable_entry(bytes: &[u8]) -> std::result::Result<(), String> {
    let envelope: Envelope<serde_json::Value> =
        serde_json::from_slice(bytes).map_err(|e| format!("not a JSON envelope: {e}"))?;
    if envelope.version != ENVELOPE_VERSION {
        return Err(format!("unsupported envelope version {}", envelope.version));
    }
    Ok(())
}

/// `key` is `prefix` followed by exactly 32 lowercase hex chars — the
/// shape of probe sentinels and bootstrap seed keys.
fn is_hex_suffixed(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix).is_some_and(|rest| {
        rest.len() == 32
            && rest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[async_trait]
impl SecretStore for BundledStore {
    fn backend(&self) -> &'static str {
        self.inner.backend()
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.layout().await?;
        match self.cached_bundle().await? {
            Some(bundle) => bundle.entry(key),
            None => Ok(None),
        }
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        match self.layout().await? {
            Layout::Active => self.update(|bundle| bundle.insert(key, value)).await,
            Layout::Mirrored => {
                // Per-key first: it stays the source of truth until cutover.
                self.inner.put(key, value).await?;
                self.update(|bundle| bundle.insert(key, value))
                    .await
                    .map_err(|e| Self::mirror_failed(key, e))
            }
        }
    }

    /// Removes the entry but never the bundle itself, even when it ends up
    /// empty: on AWS a force-deleted name can't be re-created for a short
    /// while, which would break a write right after a probe. Use
    /// [`BundledStore::purge`] to remove the bundle.
    async fn delete(&self, key: &str) -> Result<()> {
        match self.layout().await? {
            Layout::Active => {
                self.update(|bundle| bundle.entries.remove(key).is_some())
                    .await
            }
            Layout::Mirrored => {
                self.inner.delete(key).await?;
                self.update(|bundle| bundle.entries.remove(key).is_some())
                    .await
                    .map_err(|e| Self::mirror_failed(key, e))
            }
        }
    }

    async fn list_namespace(&self) -> Result<Vec<String>> {
        self.inner.list_namespace().await
    }

    async fn list_keys(&self) -> Result<Vec<String>> {
        self.layout().await?;
        Ok(self
            .cached_bundle()
            .await?
            .map(|bundle| bundle.entries.into_keys().collect())
            .unwrap_or_default())
    }

    /// One write instead of the default's two (sentinel in, sentinel out):
    /// rewrite the bundle exactly as read, then read it back. Proves the
    /// same read + write access without adding or removing anything.
    async fn probe(&self) -> Result<()> {
        self.layout().await?;
        let _guard = self.write_lock.lock().await;
        let expected = match self.get_bundle_bytes().await? {
            Some(bytes) => bytes,
            None => Bundle::default().seal()?,
        };
        self.inner.put(SECRETS_BUNDLE, &expected).await?;
        let got = self.inner.get(SECRETS_BUNDLE).await?;
        if got.as_deref() != Some(&expected[..]) {
            return Err(SecretStoreError::ProbeFailed {
                backend: self.inner.backend(),
                reason: format!("{SECRETS_BUNDLE} read back differently from what was written"),
            });
        }
        Ok(())
    }

    /// The backend's own read-only probe: it must not mutate anything, so
    /// it can't be the place a migration starts.
    async fn probe_readonly(&self) -> Result<()> {
        self.inner.probe_readonly().await
    }

    fn is_single_object(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::secrets::backends::MemoryStore;

    const SEED_ID: &str = "0123456789abcdef0123456789abcdef";

    fn memory() -> Arc<MemoryStore> {
        Arc::new(MemoryStore::new("memory"))
    }

    /// A per-key value as the mediator writes it: a sealed envelope.
    fn entry(tag: &str) -> Vec<u8> {
        Envelope::new("test", tag.to_string()).seal().unwrap()
    }

    fn seed_index_bytes(ids: &[&str]) -> Vec<u8> {
        let index = BootstrapSeedIndex {
            entries: ids
                .iter()
                .map(|id| crate::secrets::well_known::BootstrapSeedIndexEntry {
                    bundle_id_hex: (*id).to_string(),
                    created_at: 1,
                })
                .collect(),
        };
        Envelope::new(KIND_SEED_INDEX, index).seal().unwrap()
    }

    async fn physical_keys(store: &MemoryStore) -> Vec<String> {
        let mut keys = store.list_keys().await.unwrap();
        keys.sort();
        keys
    }

    async fn stored_bundle(store: &MemoryStore) -> Bundle {
        Bundle::open(&store.get(SECRETS_BUNDLE).await.unwrap().unwrap()).unwrap()
    }

    /// A deployment on the per-key layout, as an older mediator left it.
    async fn per_key_deployment() -> Arc<MemoryStore> {
        let inner = memory();
        inner.put(ADMIN_CREDENTIAL, &entry("admin")).await.unwrap();
        inner.put(JWT_SECRET, &entry("jwt")).await.unwrap();
        inner
    }

    #[tokio::test]
    async fn a_fresh_store_keeps_every_entry_in_one_secret() {
        let inner = memory();
        let store = BundledStore::new(inner.clone());
        store.put(ADMIN_CREDENTIAL, b"admin").await.unwrap();
        store.put(JWT_SECRET, b"jwt").await.unwrap();
        store.probe().await.unwrap();

        assert_eq!(physical_keys(&inner).await, vec![SECRETS_BUNDLE]);
        assert_eq!(stored_bundle(&inner).await.state, State::Active);
        assert_eq!(
            store.get(ADMIN_CREDENTIAL).await.unwrap().as_deref(),
            Some(&b"admin"[..])
        );
        store.delete(JWT_SECRET).await.unwrap();
        assert!(store.get(JWT_SECRET).await.unwrap().is_none());
        assert_eq!(store.list_keys().await.unwrap(), vec![ADMIN_CREDENTIAL]);
        assert!(!store.confirm_cutover().await.unwrap());
    }

    #[tokio::test]
    async fn migration_keeps_the_per_key_secrets_until_the_cutover() {
        let inner = per_key_deployment().await;
        let seed_key = format!("{BOOTSTRAP_EPHEMERAL_SEED_PREFIX}{SEED_ID}");
        let stray_probe = format!("{PROBE_SENTINEL_PREFIX}{}", "f".repeat(32));
        inner
            .put(BOOTSTRAP_SEED_INDEX, &seed_index_bytes(&[SEED_ID]))
            .await
            .unwrap();
        inner.put(&seed_key, &entry("seed")).await.unwrap();
        inner.put(&stray_probe, b"probe").await.unwrap();
        inner.put("some_other_app_key", b"x").await.unwrap();
        let before = physical_keys(&inner).await;

        let store = BundledStore::new(inner.clone());
        assert_eq!(
            store.get(&seed_key).await.unwrap(),
            Some(entry("seed")),
            "reads come from the verified copy"
        );
        let bundle = stored_bundle(&inner).await;
        assert_eq!(bundle.state, State::Mirrored);
        assert_eq!(bundle.stray_keys, vec![stray_probe.clone()]);
        // Every per-key secret is still there for an older mediator.
        let mut expected = before.clone();
        expected.push(SECRETS_BUNDLE.to_string());
        expected.sort();
        assert_eq!(physical_keys(&inner).await, expected);

        // The mediator has started on the bundle: cut over.
        assert!(store.confirm_cutover().await.unwrap());
        assert_eq!(
            physical_keys(&inner).await,
            vec![SECRETS_BUNDLE, "some_other_app_key"]
        );
        let bundle = stored_bundle(&inner).await;
        assert_eq!(bundle.state, State::Active);
        assert!(bundle.legacy_keys.is_empty() && bundle.stray_keys.is_empty());
        assert_eq!(store.get(JWT_SECRET).await.unwrap(), Some(entry("jwt")));
        assert!(!store.confirm_cutover().await.unwrap(), "only once");
    }

    #[tokio::test]
    async fn writes_before_the_cutover_reach_the_per_key_secrets_first() {
        let inner = per_key_deployment().await;
        let store = BundledStore::new(inner.clone());
        store.put(JWT_SECRET, &entry("jwt-2")).await.unwrap();
        store
            .put(VTA_LAST_KNOWN_BUNDLE, &entry("cache"))
            .await
            .unwrap();
        store.delete(ADMIN_CREDENTIAL).await.unwrap();

        // What an older mediator would read.
        assert_eq!(inner.get(JWT_SECRET).await.unwrap(), Some(entry("jwt-2")));
        assert_eq!(
            inner.get(VTA_LAST_KNOWN_BUNDLE).await.unwrap(),
            Some(entry("cache"))
        );
        assert!(inner.get(ADMIN_CREDENTIAL).await.unwrap().is_none());
        // And the bundle agrees, so the cutover goes ahead.
        assert!(store.confirm_cutover().await.unwrap());
        assert_eq!(store.get(JWT_SECRET).await.unwrap(), Some(entry("jwt-2")));
    }

    #[tokio::test]
    async fn per_key_changes_by_an_older_mediator_are_copied_again() {
        let inner = per_key_deployment().await;
        BundledStore::new(inner.clone())
            .get(JWT_SECRET)
            .await
            .unwrap();
        // An older mediator, still on the per-key layout, writes.
        inner.put(JWT_SECRET, &entry("rotated")).await.unwrap();

        let store = BundledStore::new(inner.clone());
        assert_eq!(store.get(JWT_SECRET).await.unwrap(), Some(entry("rotated")));
        assert!(store.confirm_cutover().await.unwrap());
    }

    #[tokio::test]
    async fn a_cutover_is_refused_if_the_per_key_secrets_changed_meanwhile() {
        let inner = per_key_deployment().await;
        let store = BundledStore::new(inner.clone());
        store.get(JWT_SECRET).await.unwrap();
        inner.put(JWT_SECRET, &entry("rotated")).await.unwrap();

        assert!(matches!(
            store.confirm_cutover().await,
            Err(SecretStoreError::MigrationFailed { .. })
        ));
        assert_eq!(stored_bundle(&inner).await.state, State::Mirrored);
        assert_eq!(inner.get(JWT_SECRET).await.unwrap(), Some(entry("rotated")));
        assert!(inner.get(ADMIN_CREDENTIAL).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn an_unreadable_per_key_secret_stops_the_migration_without_changes() {
        let inner = per_key_deployment().await;
        inner
            .put(OPERATING_SECRETS, b"not an envelope")
            .await
            .unwrap();
        let before = physical_keys(&inner).await;

        let store = BundledStore::new(inner.clone());
        let err = store.ensure_migrated().await.unwrap_err();
        assert!(
            matches!(&err, SecretStoreError::MigrationFailed { reason, action }
                if reason.contains(OPERATING_SECRETS) && action.contains(OPERATING_SECRETS)),
            "names the secret and the fix: {err}"
        );
        assert_eq!(physical_keys(&inner).await, before, "nothing written");
    }

    /// Backend that refuses one key's reads, writes or deletes, or alters
    /// what it stores.
    struct Faulty {
        inner: Arc<MemoryStore>,
        key: &'static str,
        refuse_get: bool,
        refuse_put: bool,
        refuse_delete: bool,
        corrupt_put: bool,
        /// Corrupt only a write marking the bundle `active` (the cutover).
        corrupt_cutover: bool,
    }

    impl Faulty {
        fn new(inner: Arc<MemoryStore>, key: &'static str) -> Self {
            Self {
                inner,
                key,
                refuse_get: false,
                refuse_put: false,
                refuse_delete: false,
                corrupt_put: false,
                corrupt_cutover: false,
            }
        }

        fn denied(&self) -> SecretStoreError {
            SecretStoreError::Unreachable {
                backend: "faulty",
                reason: format!("AccessDenied on {}", self.key),
            }
        }
    }

    #[async_trait]
    impl SecretStore for Faulty {
        fn backend(&self) -> &'static str {
            "faulty"
        }
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            if self.refuse_get && key == self.key {
                return Err(self.denied());
            }
            self.inner.get(key).await
        }
        async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
            if key == self.key {
                if self.refuse_put {
                    return Err(self.denied());
                }
                if self.corrupt_put
                    || (self.corrupt_cutover && Bundle::open(value).unwrap().state == State::Active)
                {
                    // Same envelope, one entry dropped.
                    let mut bundle = Bundle::open(value).unwrap();
                    bundle.entries.pop_first();
                    return self.inner.put(key, &bundle.seal().unwrap()).await;
                }
            }
            self.inner.put(key, value).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            if self.refuse_delete && key == self.key {
                return Err(self.denied());
            }
            self.inner.delete(key).await
        }
    }

    #[tokio::test]
    async fn a_copy_that_reads_back_wrong_is_removed_and_nothing_changes() {
        let inner = per_key_deployment().await;
        let before = physical_keys(&inner).await;
        let backend = Faulty {
            corrupt_put: true,
            ..Faulty::new(inner.clone(), SECRETS_BUNDLE)
        };
        let store = BundledStore::new(Arc::new(backend));

        assert!(matches!(
            store.get(JWT_SECRET).await,
            Err(SecretStoreError::MigrationFailed { .. })
        ));
        assert_eq!(physical_keys(&inner).await, before, "copy rolled back");
    }

    #[tokio::test]
    async fn a_cutover_that_reads_back_wrong_is_undone_and_deletes_nothing() {
        let inner = per_key_deployment().await;
        let before = physical_keys(&inner).await;
        let backend = Faulty {
            corrupt_cutover: true,
            ..Faulty::new(inner.clone(), SECRETS_BUNDLE)
        };
        let store = BundledStore::new(Arc::new(backend));
        store.get(JWT_SECRET).await.unwrap();

        assert!(store.confirm_cutover().await.is_err());
        assert_eq!(stored_bundle(&inner).await.state, State::Mirrored);
        let mut expected = before;
        expected.push(SECRETS_BUNDLE.to_string());
        expected.sort();
        assert_eq!(physical_keys(&inner).await, expected, "nothing deleted");

        // A healthy start afterwards cuts over normally.
        let store = BundledStore::new(inner.clone());
        assert!(store.confirm_cutover().await.unwrap());
        assert_eq!(physical_keys(&inner).await, vec![SECRETS_BUNDLE]);
    }

    #[tokio::test]
    async fn a_copy_that_cannot_be_removed_is_ignored_and_redone() {
        let inner = per_key_deployment().await;
        let backend = Faulty {
            corrupt_put: true,
            refuse_delete: true,
            ..Faulty::new(inner.clone(), SECRETS_BUNDLE)
        };
        assert!(
            BundledStore::new(Arc::new(backend))
                .ensure_migrated()
                .await
                .is_err()
        );
        // Left behind, but marked unfinished; the per-key secrets are intact.
        assert_eq!(stored_bundle(&inner).await.state, State::Staged);
        assert_eq!(inner.get(JWT_SECRET).await.unwrap(), Some(entry("jwt")));

        // The next start (healthy backend) copies again from the per-key secrets.
        let store = BundledStore::new(inner.clone());
        assert_eq!(store.get(JWT_SECRET).await.unwrap(), Some(entry("jwt")));
        assert_eq!(stored_bundle(&inner).await.state, State::Mirrored);
    }

    #[tokio::test]
    async fn an_unwritable_bundle_is_an_error_and_changes_nothing() {
        let inner = per_key_deployment().await;
        let before = physical_keys(&inner).await;
        let backend = Faulty {
            refuse_put: true,
            ..Faulty::new(inner.clone(), SECRETS_BUNDLE)
        };
        let store = BundledStore::new(Arc::new(backend));

        let err = store.ensure_migrated().await.unwrap_err();
        assert!(
            matches!(&err, SecretStoreError::MigrationFailed { action, .. }
                if action.contains(SECRETS_BUNDLE)),
            "says which secret needs access: {err}"
        );
        assert!(store.put(VTA_LAST_KNOWN_BUNDLE, b"cache").await.is_err());
        assert_eq!(physical_keys(&inner).await, before);
    }

    #[tokio::test]
    async fn a_fresh_store_that_cannot_create_the_bundle_fails_the_write() {
        let inner = memory();
        let backend = Faulty {
            refuse_put: true,
            ..Faulty::new(inner.clone(), SECRETS_BUNDLE)
        };
        let store = BundledStore::new(Arc::new(backend));
        assert!(store.put(ADMIN_CREDENTIAL, &entry("admin")).await.is_err());
        assert!(
            physical_keys(&inner).await.is_empty(),
            "no per-key fallback"
        );
    }

    #[tokio::test]
    async fn an_unreadable_bundle_is_an_error_when_per_key_secrets_are_readable() {
        let inner = per_key_deployment().await;
        let backend = Faulty {
            refuse_get: true,
            ..Faulty::new(inner.clone(), SECRETS_BUNDLE)
        };
        let store = BundledStore::new(Arc::new(backend));
        assert!(matches!(
            store.get(ADMIN_CREDENTIAL).await,
            Err(SecretStoreError::MigrationFailed { .. })
        ));
    }

    #[tokio::test]
    async fn an_unreachable_backend_is_an_error_and_is_retried() {
        let backend = Faulty {
            refuse_get: true,
            ..Faulty::new(memory(), SECRETS_BUNDLE)
        };
        let store = BundledStore::new(Arc::new(backend));
        // No per-key secret to fall back to: surface the error, decide nothing.
        assert!(store.get(JWT_SECRET).await.is_err());
        assert!(store.current_layout().is_none());
    }

    #[tokio::test]
    async fn a_failed_cleanup_delete_is_retried_on_the_next_start() {
        let inner = per_key_deployment().await;
        let backend = Faulty {
            refuse_delete: true,
            ..Faulty::new(inner.clone(), JWT_SECRET)
        };
        let store = BundledStore::new(Arc::new(backend));
        assert!(store.confirm_cutover().await.unwrap());
        assert_eq!(
            physical_keys(&inner).await,
            vec![JWT_SECRET, SECRETS_BUNDLE]
        );
        assert_eq!(stored_bundle(&inner).await.legacy_keys, vec![JWT_SECRET]);

        // Next start, delete allowed again.
        let store = BundledStore::new(inner.clone());
        assert_eq!(store.get(JWT_SECRET).await.unwrap(), Some(entry("jwt")));
        assert_eq!(physical_keys(&inner).await, vec![SECRETS_BUNDLE]);
    }

    #[tokio::test]
    async fn a_pre_created_empty_bundle_counts_as_absent() {
        // A fresh deployment whose IaC created the secret with no content.
        let inner = memory();
        inner.put(SECRETS_BUNDLE, b"").await.unwrap();
        let store = BundledStore::new(inner.clone());
        store.put(JWT_SECRET, b"jwt").await.unwrap();
        assert_eq!(
            store.get(JWT_SECRET).await.unwrap().as_deref(),
            Some(&b"jwt"[..])
        );

        // And a per-key deployment beside an empty one still migrates.
        let inner = per_key_deployment().await;
        inner.put(SECRETS_BUNDLE, b"").await.unwrap();
        let store = BundledStore::new(inner.clone());
        assert_eq!(store.get(JWT_SECRET).await.unwrap(), Some(entry("jwt")));
        assert!(store.confirm_cutover().await.unwrap());
    }

    #[tokio::test]
    async fn a_corrupt_bundle_is_an_error_not_overwritten() {
        let inner = per_key_deployment().await;
        inner.put(SECRETS_BUNDLE, b"not an envelope").await.unwrap();
        let store = BundledStore::new(inner.clone());
        assert!(matches!(
            store.get(ADMIN_CREDENTIAL).await,
            Err(SecretStoreError::MigrationFailed { .. })
        ));
        assert_eq!(
            inner.get(SECRETS_BUNDLE).await.unwrap().as_deref(),
            Some(&b"not an envelope"[..])
        );
    }

    #[tokio::test]
    async fn an_unconfirmed_copy_without_its_per_key_secrets_is_an_error() {
        let inner = per_key_deployment().await;
        BundledStore::new(inner.clone())
            .get(JWT_SECRET)
            .await
            .unwrap();
        let mut bundle = stored_bundle(&inner).await;
        bundle.state = State::Staged;
        inner
            .put(SECRETS_BUNDLE, &bundle.seal().unwrap())
            .await
            .unwrap();
        inner.delete(ADMIN_CREDENTIAL).await.unwrap();
        inner.delete(JWT_SECRET).await.unwrap();

        assert!(
            BundledStore::new(inner.clone())
                .get(JWT_SECRET)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn purge_removes_both_layouts() {
        let inner = per_key_deployment().await;
        let store = BundledStore::new(inner.clone());
        store.get(JWT_SECRET).await.unwrap();
        store.purge().await.unwrap();
        assert!(physical_keys(&inner).await.is_empty());
    }

    /// Counts backend calls, which is what cloud secret stores bill.
    struct Counting {
        inner: MemoryStore,
        gets: AtomicUsize,
        puts: AtomicUsize,
    }

    impl Counting {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: MemoryStore::new("memory"),
                gets: AtomicUsize::new(0),
                puts: AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> (usize, usize) {
            (
                self.gets.load(Ordering::SeqCst),
                self.puts.load(Ordering::SeqCst),
            )
        }
    }

    #[async_trait]
    impl SecretStore for Counting {
        fn backend(&self) -> &'static str {
            "counting"
        }
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.get(key).await
        }
        async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.inner.put(key, value).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key).await
        }
    }

    #[tokio::test]
    async fn writing_an_unchanged_entry_costs_no_write() {
        let backend = Counting::new();
        let store = BundledStore::new(backend.clone());
        store.put(JWT_SECRET, b"jwt").await.unwrap();
        let (_, puts) = backend.calls();
        store.put(JWT_SECRET, b"jwt").await.unwrap();
        store.delete(ADMIN_CREDENTIAL).await.unwrap();
        assert_eq!(backend.calls().1, puts, "no change, no write");
    }

    #[tokio::test]
    async fn reads_within_the_cache_window_cost_no_backend_call() {
        let backend = Counting::new();
        let store = BundledStore::new(backend.clone());
        store.put(JWT_SECRET, b"jwt").await.unwrap();
        let (gets, _) = backend.calls();
        for _ in 0..5 {
            assert!(store.get(JWT_SECRET).await.unwrap().is_some());
            assert!(store.get(ADMIN_CREDENTIAL).await.unwrap().is_none());
        }
        assert_eq!(backend.calls().0, gets);
        // A fresh read still goes to the backend.
        store.get_fresh(JWT_SECRET).await.unwrap();
        assert_eq!(backend.calls().0, gets + 1);
    }

    #[tokio::test]
    async fn probe_writes_once_and_changes_nothing() {
        let backend = Counting::new();
        let store = BundledStore::new(backend.clone());
        store.put(JWT_SECRET, b"jwt").await.unwrap();
        let before = backend.inner.get(SECRETS_BUNDLE).await.unwrap();
        let (_, puts) = backend.calls();
        store.probe().await.unwrap();
        assert_eq!(backend.calls().1, puts + 1);
        assert_eq!(backend.inner.get(SECRETS_BUNDLE).await.unwrap(), before);
    }

    #[test]
    fn hex_suffix_matches_only_the_generated_shape() {
        let probe = format!("{PROBE_SENTINEL_PREFIX}{}", "a".repeat(32));
        assert!(is_hex_suffixed(&probe, PROBE_SENTINEL_PREFIX));
        assert!(!is_hex_suffixed(
            "mediator_probe_readonly",
            PROBE_SENTINEL_PREFIX
        ));
        assert!(!is_hex_suffixed(
            "mediator_probe_keyring_sentinel",
            PROBE_SENTINEL_PREFIX
        ));
        assert!(!is_hex_suffixed(
            &format!("x{probe}"),
            PROBE_SENTINEL_PREFIX
        ));
    }
}
