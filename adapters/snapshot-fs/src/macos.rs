//! Descriptor-capability materialization of immutable semantic snapshots.

use rustix::fs::{self, AtFlags, Mode, OFlags, RenameFlags};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, fs::File, io::Write as _, os::unix::fs::MetadataExt as _};
use vellum_semantic_helper_protocol::{
    SemanticHelperExchangeRefV1, SemanticHelperSessionRefV1, SemanticHelperSnapshotDigestV1,
    SemanticHelperSnapshotManifestV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalSemanticSnapshotRefusalV1 {
    UnsafeRoot,
    ContentCountMismatch,
    ContentLengthMismatch,
    ContentDigestMismatch,
    Collision,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalSemanticSnapshotUsageV1 {
    pub attempts: u64,
    pub published: u64,
    pub refused: u64,
    pub logical_bytes_published: u64,
    pub counter_saturated: bool,
}

/// A caller-supplied private directory descriptor. The adapter never resolves
/// an ambient root path and never reads source workspace paths.
pub struct LocalSemanticSnapshotRootV1 {
    directory: File,
    usage: LocalSemanticSnapshotUsageV1,
}

impl std::fmt::Debug for LocalSemanticSnapshotRootV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LocalSemanticSnapshotRootV1(<descriptor>)")
    }
}

impl LocalSemanticSnapshotRootV1 {
    pub fn try_from_directory(directory: File) -> Result<Self, LocalSemanticSnapshotRefusalV1> {
        qualify_private_root(&directory)?;
        Ok(Self {
            directory,
            usage: LocalSemanticSnapshotUsageV1::default(),
        })
    }

    pub fn usage(&self) -> LocalSemanticSnapshotUsageV1 {
        self.usage
    }

    /// Materialize `contents` in the manifest's canonical entry order. Every
    /// length and digest is checked before the stage namespace is created.
    pub fn materialize(
        &mut self,
        session: SemanticHelperSessionRefV1,
        exchange: SemanticHelperExchangeRefV1,
        manifest: &SemanticHelperSnapshotManifestV1,
        contents: &[impl AsRef<[u8]>],
    ) -> Result<LocalSemanticSnapshotV1, LocalSemanticSnapshotRefusalV1> {
        increment(&mut self.usage.attempts, &mut self.usage.counter_saturated);
        let outcome = self.materialize_inner(session, exchange, manifest, contents);
        match &outcome {
            Ok(_) => {
                increment(&mut self.usage.published, &mut self.usage.counter_saturated);
                add(
                    &mut self.usage.logical_bytes_published,
                    manifest.total_bytes(),
                    &mut self.usage.counter_saturated,
                );
            }
            Err(_) => increment(&mut self.usage.refused, &mut self.usage.counter_saturated),
        }
        outcome
    }

    fn materialize_inner(
        &self,
        session: SemanticHelperSessionRefV1,
        exchange: SemanticHelperExchangeRefV1,
        manifest: &SemanticHelperSnapshotManifestV1,
        contents: &[impl AsRef<[u8]>],
    ) -> Result<LocalSemanticSnapshotV1, LocalSemanticSnapshotRefusalV1> {
        qualify_private_root(&self.directory)?;
        preflight(manifest, contents)?;
        // Acquire every capability needed by the returned lease before the
        // namespace publication boundary. A post-rename sealing failure rolls
        // the published name back before any lease can be returned.
        let lease_root = self
            .directory
            .try_clone()
            .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)?;

        let final_name = format!("snapshot-{}", encode_hex(session.as_bytes()));
        let stage_name = format!("stage-{}", encode_hex(exchange.as_bytes()));
        if exists(&self.directory, &final_name)? || exists(&self.directory, &stage_name)? {
            return Err(LocalSemanticSnapshotRefusalV1::Collision);
        }
        fs::mkdirat(&self.directory, &stage_name, Mode::from_raw_mode(0o700))
            .map_err(classify_create)?;
        let stage = match open_directory(&self.directory, &stage_name) {
            Ok(stage) => stage,
            Err(error) => {
                let _ = fs::unlinkat(&self.directory, &stage_name, AtFlags::REMOVEDIR);
                return Err(error);
            }
        };

        let mut files = Vec::with_capacity(manifest.entries().len());
        let mut directories = BTreeSet::new();
        let mut renamed = false;
        let staged = (|| {
            for (entry, content) in manifest.entries().iter().zip(contents) {
                let relative = entry.path().as_str();
                let parent = relative.rsplit_once('/').map(|(parent, _)| parent);
                if let Some(parent) = parent {
                    create_directory_chain(&stage, parent, &mut directories)?;
                }
                let parent_descriptor = open_relative_directory(&stage, parent)?;
                let name = relative
                    .rsplit('/')
                    .next()
                    .expect("validated path has a name");
                let descriptor = File::from(
                    fs::openat(
                        &parent_descriptor,
                        name,
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::from_raw_mode(0o600),
                    )
                    .map_err(classify_create)?,
                );
                // Ledger the exclusive creation before any subsequent write
                // or permission operation can fail. This affine snapshot is
                // not a durable store and makes no crash-persistence claim.
                files.push(relative.to_owned());
                let mut descriptor = descriptor;
                descriptor
                    .write_all(content.as_ref())
                    .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)?;
                fs::fchmod(&descriptor, Mode::from_raw_mode(0o400))
                    .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)?;
            }
            seal_directories(&stage, &directories)?;
            fs::renameat_with(
                &self.directory,
                &stage_name,
                &self.directory,
                &final_name,
                RenameFlags::NOREPLACE,
            )
            .map_err(classify_create)?;
            renamed = true;
            fs::fchmod(&stage, Mode::from_raw_mode(0o500))
                .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)?;
            Ok::<(), LocalSemanticSnapshotRefusalV1>(())
        })();

        if let Err(error) = staged {
            let cleanup_name = if renamed { &final_name } else { &stage_name };
            if cleanup_tree(&self.directory, cleanup_name, &stage, &files, &directories).is_err() {
                return Err(LocalSemanticSnapshotRefusalV1::Unavailable);
            }
            return Err(error);
        }
        Ok(LocalSemanticSnapshotV1 {
            root: lease_root,
            directory: stage,
            name: final_name,
            files,
            directories,
            digest: manifest.digest(),
            published: true,
        })
    }
}

/// Affine lifetime handle for one published immutable snapshot. Dropping it
/// performs bounded best-effort cleanup; callers needing evidence use
/// [`LocalSemanticSnapshotV1::destroy`].
pub struct LocalSemanticSnapshotV1 {
    root: File,
    directory: File,
    name: String,
    files: Vec<String>,
    directories: BTreeSet<String>,
    digest: SemanticHelperSnapshotDigestV1,
    published: bool,
}

impl std::fmt::Debug for LocalSemanticSnapshotV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LocalSemanticSnapshotV1(<opaque>)")
    }
}

impl LocalSemanticSnapshotV1 {
    pub fn try_clone_directory(&self) -> Result<File, LocalSemanticSnapshotRefusalV1> {
        self.directory
            .try_clone()
            .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)
    }

    pub const fn digest(&self) -> SemanticHelperSnapshotDigestV1 {
        self.digest
    }

    pub fn destroy(mut self) -> Result<(), LocalSemanticSnapshotRefusalV1> {
        let result = cleanup_tree(
            &self.root,
            &self.name,
            &self.directory,
            &self.files,
            &self.directories,
        );
        if result.is_ok() {
            self.published = false;
        }
        result
    }
}

impl Drop for LocalSemanticSnapshotV1 {
    fn drop(&mut self) {
        if self.published {
            let _ = cleanup_tree(
                &self.root,
                &self.name,
                &self.directory,
                &self.files,
                &self.directories,
            );
            self.published = false;
        }
    }
}

fn qualify_private_root(directory: &File) -> Result<(), LocalSemanticSnapshotRefusalV1> {
    let metadata = directory
        .metadata()
        .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
        || metadata.nlink() < 2
        || fs::fstatfs(directory)
            .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)?
            .f_flags
            & 0x0000_1000
            == 0
    {
        return Err(LocalSemanticSnapshotRefusalV1::UnsafeRoot);
    }
    Ok(())
}

fn preflight(
    manifest: &SemanticHelperSnapshotManifestV1,
    contents: &[impl AsRef<[u8]>],
) -> Result<(), LocalSemanticSnapshotRefusalV1> {
    if manifest.entries().len() != contents.len() {
        return Err(LocalSemanticSnapshotRefusalV1::ContentCountMismatch);
    }
    for (entry, content) in manifest.entries().iter().zip(contents) {
        let bytes = content.as_ref();
        if u64::try_from(bytes.len()).ok() != Some(entry.byte_len()) {
            return Err(LocalSemanticSnapshotRefusalV1::ContentLengthMismatch);
        }
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if digest != entry.digest().as_bytes() {
            return Err(LocalSemanticSnapshotRefusalV1::ContentDigestMismatch);
        }
    }
    Ok(())
}

fn create_directory_chain(
    stage: &File,
    path: &str,
    created: &mut BTreeSet<String>,
) -> Result<(), LocalSemanticSnapshotRefusalV1> {
    let mut descriptor = stage
        .try_clone()
        .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)?;
    let mut accumulated = String::new();
    for component in path.split('/') {
        if !accumulated.is_empty() {
            accumulated.push('/');
        }
        accumulated.push_str(component);
        if !created.contains(&accumulated) {
            fs::mkdirat(&descriptor, component, Mode::from_raw_mode(0o700))
                .map_err(classify_create)?;
            created.insert(accumulated.clone());
        }
        descriptor = open_directory(&descriptor, component)?;
    }
    Ok(())
}

fn open_relative_directory(
    stage: &File,
    path: Option<&str>,
) -> Result<File, LocalSemanticSnapshotRefusalV1> {
    let mut descriptor = stage
        .try_clone()
        .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)?;
    if let Some(path) = path {
        for component in path.split('/') {
            descriptor = open_directory(&descriptor, component)?;
        }
    }
    Ok(descriptor)
}

fn open_directory(parent: &File, name: &str) -> Result<File, LocalSemanticSnapshotRefusalV1> {
    fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)
}

fn seal_directories(
    stage: &File,
    directories: &BTreeSet<String>,
) -> Result<(), LocalSemanticSnapshotRefusalV1> {
    let mut ordered: Vec<_> = directories.iter().collect();
    ordered.sort_unstable_by_key(|path| std::cmp::Reverse(path.matches('/').count()));
    for path in ordered {
        let descriptor = open_relative_directory(stage, Some(path))?;
        fs::fchmod(&descriptor, Mode::from_raw_mode(0o500))
            .map_err(|_| LocalSemanticSnapshotRefusalV1::Unavailable)?;
    }
    Ok(())
}

fn cleanup_tree(
    root: &File,
    name: &str,
    directory: &File,
    files: &[String],
    directories: &BTreeSet<String>,
) -> Result<(), LocalSemanticSnapshotRefusalV1> {
    let mut failed = false;
    if fs::fchmod(directory, Mode::from_raw_mode(0o700)).is_err() {
        failed = true;
    }
    let mut ordered: Vec<_> = directories.iter().collect();
    ordered.sort_unstable_by_key(|path| path.matches('/').count());
    for path in &ordered {
        if let Ok(descriptor) = open_relative_directory(directory, Some(path)) {
            if fs::fchmod(&descriptor, Mode::from_raw_mode(0o700)).is_err() {
                failed = true;
            }
        } else {
            failed = true;
        }
    }
    for path in files.iter().rev() {
        let (parent, leaf) = path
            .rsplit_once('/')
            .map_or((None, path.as_str()), |(p, l)| (Some(p), l));
        match open_relative_directory(directory, parent) {
            Ok(parent) if fs::unlinkat(&parent, leaf, AtFlags::empty()).is_ok() => {}
            _ => failed = true,
        }
    }
    ordered.sort_unstable_by_key(|path| std::cmp::Reverse(path.matches('/').count()));
    for path in ordered {
        let (parent, leaf) = path
            .rsplit_once('/')
            .map_or((None, path.as_str()), |(p, l)| (Some(p), l));
        match open_relative_directory(directory, parent) {
            Ok(parent) if fs::unlinkat(&parent, leaf, AtFlags::REMOVEDIR).is_ok() => {}
            _ => failed = true,
        }
    }
    if fs::unlinkat(root, name, AtFlags::REMOVEDIR).is_err() {
        failed = true;
    }
    if failed {
        Err(LocalSemanticSnapshotRefusalV1::Unavailable)
    } else {
        Ok(())
    }
}

fn exists(parent: &File, name: &str) -> Result<bool, LocalSemanticSnapshotRefusalV1> {
    match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(_) => Err(LocalSemanticSnapshotRefusalV1::Unavailable),
    }
}

fn classify_create(error: rustix::io::Errno) -> LocalSemanticSnapshotRefusalV1 {
    if error == rustix::io::Errno::EXIST {
        LocalSemanticSnapshotRefusalV1::Collision
    } else {
        LocalSemanticSnapshotRefusalV1::Unavailable
    }
}

fn encode_hex<const N: usize>(bytes: [u8; N]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(N * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn increment(value: &mut u64, saturated: &mut bool) {
    let (next, overflow) = value.overflowing_add(1);
    if overflow {
        *value = u64::MAX;
        *saturated = true;
    } else {
        *value = next;
    }
}

fn add(value: &mut u64, amount: u64, saturated: &mut bool) {
    let (next, overflow) = value.overflowing_add(amount);
    if overflow {
        *value = u64::MAX;
        *saturated = true;
    } else {
        *value = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use vellum_semantic_helper_protocol::{
        SemanticHelperRelativePathV1, SemanticHelperSnapshotEntryV1,
    };

    struct Fixture(PathBuf);

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "vellum-semantic-snapshot-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn root(&self) -> LocalSemanticSnapshotRootV1 {
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags((OFlags::DIRECTORY | OFlags::NOFOLLOW).bits() as i32)
                .open(&self.0)
                .unwrap();
            LocalSemanticSnapshotRootV1::try_from_directory(file).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn manifest(files: &[(&str, &[u8])]) -> SemanticHelperSnapshotManifestV1 {
        SemanticHelperSnapshotManifestV1::try_from_entries(
            files
                .iter()
                .map(|(path, bytes)| {
                    SemanticHelperSnapshotEntryV1::new(
                        SemanticHelperRelativePathV1::new(path).unwrap(),
                        bytes.len() as u64,
                        Sha256::digest(bytes).into(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap()
    }

    fn refs() -> (SemanticHelperSessionRefV1, SemanticHelperExchangeRefV1) {
        (
            SemanticHelperSessionRefV1::new([1; 16]).unwrap(),
            SemanticHelperExchangeRefV1::new([2; 16]).unwrap(),
        )
    }

    #[test]
    fn publishes_exact_read_only_tree_and_destroy_removes_it() {
        let fixture = Fixture::new();
        let mut root = fixture.root();
        let files = [
            ("src/lib.rs", b"fn main() {}".as_slice()),
            ("README.md", b"hello".as_slice()),
        ];
        let manifest = manifest(&files);
        let contents = [files[1].1, files[0].1];
        let (session, exchange) = refs();
        let snapshot = root
            .materialize(session, exchange, &manifest, &contents)
            .unwrap();
        assert_eq!(snapshot.digest(), manifest.digest());
        let directory = snapshot.try_clone_directory().unwrap();
        assert_eq!(
            directory.metadata().unwrap().permissions().mode() & 0o777,
            0o500
        );
        assert_eq!(
            fs::read(
                fixture
                    .0
                    .join("snapshot-01010101010101010101010101010101/src/lib.rs")
            )
            .unwrap(),
            b"fn main() {}"
        );
        assert!(
            fs::write(
                fixture
                    .0
                    .join("snapshot-01010101010101010101010101010101/README.md"),
                b"changed"
            )
            .is_err()
        );
        snapshot.destroy().unwrap();
        assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());
        assert_eq!(root.usage().published, 1);
    }

    #[test]
    fn preflight_refuses_mismatched_content_without_partial_namespace() {
        let fixture = Fixture::new();
        let mut root = fixture.root();
        let manifest = manifest(&[("a", b"expected")]);
        let (session, exchange) = refs();
        assert!(matches!(
            root.materialize(session, exchange, &manifest, &[b"wrong"]),
            Err(LocalSemanticSnapshotRefusalV1::ContentLengthMismatch)
        ));
        assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());
        assert!(matches!(
            root.materialize(session, exchange, &manifest, &[b"changed!"]),
            Err(LocalSemanticSnapshotRefusalV1::ContentDigestMismatch)
        ));
        assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());
        assert_eq!(root.usage().refused, 2);
    }

    #[test]
    fn unsafe_root_and_namespace_collisions_fail_closed() {
        let fixture = Fixture::new();
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o755)).unwrap();
        let file = fs::File::open(&fixture.0).unwrap();
        assert!(matches!(
            LocalSemanticSnapshotRootV1::try_from_directory(file),
            Err(LocalSemanticSnapshotRefusalV1::UnsafeRoot)
        ));
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(
            "outside",
            fixture.0.join("stage-02020202020202020202020202020202"),
        )
        .unwrap();
        let mut root = fixture.root();
        let manifest = manifest(&[("a", b"a")]);
        let (session, exchange) = refs();
        assert!(matches!(
            root.materialize(session, exchange, &manifest, &[b"a"]),
            Err(LocalSemanticSnapshotRefusalV1::Collision)
        ));
    }
}
