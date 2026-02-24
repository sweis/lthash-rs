use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use lthash::LtHash16_1024;
use rayon::prelude::*;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Checksum size in bytes for LtHash16_1024, used throughout for buffer allocation.
const CHECKSUM_SIZE: usize = LtHash16_1024::checksum_size_bytes();

/// SIMD-optimized u16 element-wise wrapping addition for LtHash combination.
/// Uses `align_to` for safe alignment handling with auto-vectorization.
#[inline]
fn combine_checksums_simd(dest: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dest.len(), CHECKSUM_SIZE);
    debug_assert_eq!(src.len(), CHECKSUM_SIZE);

    // Use align_to for safe u64 reinterpretation (handles alignment correctly).
    // Vec<u8> from the global allocator is always at least pointer-aligned,
    // so prefix/suffix will be empty, but we assert to catch edge cases.
    let (d_prefix, dest_u64, d_suffix) = unsafe { dest.align_to_mut::<u64>() };
    let (s_prefix, src_u64, s_suffix) = unsafe { src.align_to::<u64>() };
    assert!(
        d_prefix.is_empty() && d_suffix.is_empty() && s_prefix.is_empty() && s_suffix.is_empty(),
        "Checksum buffers must be u64-aligned"
    );

    // Split-lane addition for u16 elements packed in u64.
    // This pattern is SIMD-friendly and auto-vectorizes well.
    const MASK_A: u64 = 0xffff_0000_ffff_0000_u64;
    const MASK_B: u64 = 0x0000_ffff_0000_ffff_u64;

    for (d, &s) in dest_u64.iter_mut().zip(src_u64.iter()) {
        let a = *d;
        let result_a = (a & MASK_A).wrapping_add(s & MASK_A) & MASK_A;
        let result_b = (a & MASK_B).wrapping_add(s & MASK_B) & MASK_B;
        *d = result_a | result_b;
    }
}

/// Reduction function for combining multiple checksums via rayon's try_reduce.
#[inline]
fn reduce_checksums(
    mut a: Vec<u8>,
    b: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    combine_checksums_simd(&mut a, &b);
    Ok(a)
}

/// File info with just the filename for use with openat().
struct FileEntry {
    name: CString,
    size: u64,
}

/// Directory context for openat() optimization.
/// Holds a directory fd and list of files to hash.
struct DirContext {
    dir_fd: RawFd,
    files: Vec<FileEntry>,
}

impl Drop for DirContext {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.dir_fd);
        }
    }
}

/// File info with full path for the flat-directory hashing path.
struct FileInfo {
    path: PathBuf,
    size: u64,
}

struct Args {
    directory: String,
    recursive: bool,
    include_hidden: bool,
    progress: bool,
}

/// Thread-safe progress tracking with ETA estimation.
/// Uses rate-limited printing to reduce overhead from frequent updates.
struct Progress {
    files_processed: AtomicUsize,
    dirs_processed: AtomicUsize,
    bytes_processed: AtomicU64,
    total_bytes: AtomicU64,
    total_files: AtomicUsize,
    last_print: AtomicU64,
    start_time: Instant,
    enabled: bool,
}

/// Minimum interval between progress prints (milliseconds)
const PROGRESS_PRINT_INTERVAL_MS: u64 = 100;

/// Minimum file size to apply I/O hints. For smaller files, syscall overhead exceeds benefit.
const IO_HINT_THRESHOLD: u64 = 262_144; // 256KB

/// Buffer sizes for adaptive I/O based on file size
const SMALL_BUFFER_SIZE: usize = 65_536; // 64KB for files < 1MB
const MEDIUM_BUFFER_SIZE: usize = 262_144; // 256KB for files 1-16MB
const LARGE_BUFFER_SIZE: usize = 1_048_576; // 1MB for files > 16MB

impl Progress {
    fn new(enabled: bool) -> Self {
        Self {
            files_processed: AtomicUsize::new(0),
            dirs_processed: AtomicUsize::new(0),
            bytes_processed: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            total_files: AtomicUsize::new(0),
            last_print: AtomicU64::new(0),
            start_time: Instant::now(),
            enabled,
        }
    }

    fn set_totals(&self, files: usize, bytes: u64) {
        self.total_files.store(files, Ordering::Relaxed);
        self.total_bytes.store(bytes, Ordering::Relaxed);
    }

    fn add_files(&self, count: usize, bytes: u64) {
        if self.enabled {
            self.files_processed.fetch_add(count, Ordering::Relaxed);
            self.bytes_processed.fetch_add(bytes, Ordering::Relaxed);
            self.maybe_print_progress();
        }
    }

    fn add_dir(&self) {
        if self.enabled {
            self.dirs_processed.fetch_add(1, Ordering::Relaxed);
            self.maybe_print_progress();
        }
    }

    /// Rate-limited progress printing to reduce contention and I/O overhead
    fn maybe_print_progress(&self) {
        let now_ms = self.start_time.elapsed().as_millis() as u64;
        let last = self.last_print.load(Ordering::Relaxed);

        if now_ms.saturating_sub(last) >= PROGRESS_PRINT_INTERVAL_MS
            && self
                .last_print
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.print_progress();
        }
    }

    fn print_progress(&self) {
        let files = self.files_processed.load(Ordering::Relaxed);
        let dirs = self.dirs_processed.load(Ordering::Relaxed);
        let bytes = self.bytes_processed.load(Ordering::Relaxed);
        let total_bytes = self.total_bytes.load(Ordering::Relaxed);
        let total_files = self.total_files.load(Ordering::Relaxed);

        let elapsed = self.start_time.elapsed().as_secs_f64();
        let mb = bytes as f64 / 1_000_000.0;

        let throughput = if elapsed > 0.01 {
            bytes as f64 / elapsed / 1_000_000.0
        } else {
            0.0
        };

        let eta_str = if total_bytes > 0 && throughput > 0.0 {
            let remaining_bytes = total_bytes.saturating_sub(bytes);
            let eta_secs = remaining_bytes as f64 / (throughput * 1_000_000.0);
            let pct = (bytes as f64 / total_bytes as f64 * 100.0).min(100.0);
            format!(" | {pct:.0}% | ETA: {}", format_duration(eta_secs))
        } else if total_files > 0 {
            let pct = (files as f64 / total_files as f64 * 100.0).min(100.0);
            format!(" | {pct:.0}%")
        } else {
            String::new()
        };

        let throughput_str = if throughput > 0.0 {
            format!(" @ {throughput:.0} MB/s")
        } else {
            String::new()
        };

        eprint!(
            "\r\x1b[K  Processing: {files} files, {dirs} dirs, {mb:.1} MB{throughput_str}{eta_str}"
        );
        let _ = std::io::stderr().flush();
    }

    fn finish(&self) {
        if self.enabled {
            self.print_progress();
            eprintln!();
        }
    }
}

struct Stats {
    files_found: usize,
    files_hashed: usize,
    dirs_hashed: usize,
    total_bytes: u64,
}

impl Stats {
    fn new() -> Self {
        Self {
            files_found: 0,
            files_hashed: 0,
            dirs_hashed: 0,
            total_bytes: 0,
        }
    }

    fn merge(&mut self, other: &Stats) {
        self.files_found += other.files_found;
        self.files_hashed += other.files_hashed;
        self.dirs_hashed += other.dirs_hashed;
        self.total_bytes += other.total_bytes;
    }
}

fn main() {
    let args = parse_args();

    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut directory = ".".to_string();
    let mut recursive = false;
    let mut include_hidden = false;
    let mut progress = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--recursive" => recursive = true,
            "-p" | "--progress" => progress = true,
            "--hidden" => include_hidden = true,
            arg if !arg.starts_with('-') => directory = arg.to_string(),
            other => {
                eprintln!("unknown option: {other}");
                eprintln!("usage: lthash_dir [-r] [-p] [--hidden] [directory]");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    Args {
        directory,
        recursive,
        include_hidden,
        progress,
    }
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    let progress = Arc::new(Progress::new(args.progress));

    if args.progress {
        eprint!("  Scanning...");
        let _ = std::io::stderr().flush();
        let (total_files, total_bytes) =
            scan_directory(&args.directory, args.include_hidden, args.recursive);
        progress.set_totals(total_files, total_bytes);
        eprint!("\r\x1b[K");
        let _ = std::io::stderr().flush();
    }

    let (hash, stats) = if args.recursive {
        hash_directory_recursive(&args.directory, args.include_hidden, &progress)?
    } else {
        hash_directory_flat(&args.directory, args.include_hidden, &progress)?
    };

    progress.finish();

    let total_time = start.elapsed();
    let encoded = URL_SAFE_NO_PAD.encode(hash.checksum());

    println!("{encoded}");
    eprintln!();
    eprintln!("Statistics:");
    eprintln!("  Directory:      {}", args.directory);
    eprintln!("  Recursive:      {}", args.recursive);
    eprintln!("  Files found:    {}", stats.files_found);
    eprintln!("  Files hashed:   {}", stats.files_hashed);
    if args.recursive {
        eprintln!("  Dirs hashed:    {}", stats.dirs_hashed);
    }
    eprintln!(
        "  Total bytes:    {} ({:.2} MB)",
        stats.total_bytes,
        stats.total_bytes as f64 / 1_000_000.0
    );
    eprintln!();
    eprintln!("Timing:");
    eprintln!("  Total:          {total_time:?}");

    if total_time.as_secs_f64() > 0.0 {
        let throughput = stats.total_bytes as f64 / total_time.as_secs_f64() / 1_000_000.0;
        eprintln!("  Throughput:     {throughput:.2} MB/s");
    }

    Ok(())
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn format_duration(secs: f64) -> String {
    if secs < 1.0 {
        "<1s".to_string()
    } else if secs < 60.0 {
        format!("{}s", secs as u64)
    } else if secs < 3600.0 {
        let mins = (secs / 60.0) as u64;
        let remainder = (secs % 60.0) as u64;
        format!("{mins}m {remainder}s")
    } else {
        let hours = (secs / 3600.0) as u64;
        let mins = ((secs % 3600.0) / 60.0) as u64;
        format!("{hours}h {mins}m")
    }
}

/// Quick scan to count files and total bytes for ETA estimation.
fn scan_directory(dir: &str, include_hidden: bool, recursive: bool) -> (usize, u64) {
    let root = Path::new(dir);

    if recursive {
        scan_directory_parallel(root, include_hidden)
    } else {
        scan_single_directory(root, include_hidden)
    }
}

fn scan_single_directory(path: &Path, include_hidden: bool) -> (usize, u64) {
    let mut files = 0usize;
    let mut bytes = 0u64;

    let Ok(entries) = fs::read_dir(path) else {
        return (0, 0);
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if !include_hidden && is_hidden(&path) {
            continue;
        }

        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };

        if metadata.is_file() {
            files += 1;
            bytes += metadata.len();
        }
    }

    (files, bytes)
}

/// Parallel recursive directory scanning for ETA estimation.
fn scan_directory_parallel(path: &Path, include_hidden: bool) -> (usize, u64) {
    let Ok(entries) = fs::read_dir(path) else {
        return (0, 0);
    };

    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut subdirs = Vec::new();

    for entry in entries.flatten() {
        let entry_path = entry.path();

        if !include_hidden && is_hidden(&entry_path) {
            continue;
        }

        let Ok(metadata) = fs::symlink_metadata(&entry_path) else {
            continue;
        };

        if metadata.is_file() {
            files += 1;
            bytes += metadata.len();
        } else if metadata.is_dir() {
            subdirs.push(entry_path);
        }
    }

    if !subdirs.is_empty() {
        let subdir_results: Vec<(usize, u64)> = subdirs
            .par_iter()
            .map(|subdir| scan_directory_parallel(subdir, include_hidden))
            .collect();

        for (f, b) in subdir_results {
            files += f;
            bytes += b;
        }
    }

    (files, bytes)
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map_or(false, |name| name.starts_with('.'))
}

fn hash_directory_flat(
    dir: &str,
    include_hidden: bool,
    progress: &Arc<Progress>,
) -> Result<(LtHash16_1024, Stats), Box<dyn std::error::Error + Send + Sync>> {
    let (file_infos, total_bytes) = collect_file_infos(dir, include_hidden)?;
    let files_found = file_infos.len();

    if file_infos.is_empty() {
        return Ok((LtHash16_1024::new()?, Stats::new()));
    }

    let hash = hash_files_parallel(file_infos)?;
    progress.add_files(files_found, total_bytes);

    Ok((
        hash,
        Stats {
            files_found,
            files_hashed: files_found,
            dirs_hashed: 0,
            total_bytes,
        },
    ))
}

fn hash_directory_recursive(
    dir: &str,
    include_hidden: bool,
    progress: &Arc<Progress>,
) -> Result<(LtHash16_1024, Stats), Box<dyn std::error::Error + Send + Sync>> {
    let root = Path::new(dir)
        .canonicalize()
        .map_err(|e| format!("cannot resolve '{dir}': {e}"))?;

    hash_dir_recursive_inner(&root, include_hidden, progress)
}

fn hash_dir_recursive_inner(
    dir: &Path,
    include_hidden: bool,
    progress: &Arc<Progress>,
) -> Result<(LtHash16_1024, Stats), Box<dyn std::error::Error + Send + Sync>> {
    let mut file_entries = Vec::new();
    let mut subdirs = Vec::new();
    let mut total_bytes = 0u64;

    // Open directory for openat() - avoids path resolution per file
    let dir_cstr =
        CString::new(dir.as_os_str().as_bytes()).map_err(|_| "invalid directory path")?;
    let dir_fd = unsafe { libc::open(dir_cstr.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if dir_fd < 0 {
        eprintln!(
            "warning: cannot open dir '{}': {}",
            dir.display(),
            std::io::Error::last_os_error()
        );
        return Ok((LtHash16_1024::new()?, Stats::new()));
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            unsafe {
                libc::close(dir_fd);
            }
            eprintln!("warning: cannot read '{}': {e}", dir.display());
            return Ok((LtHash16_1024::new()?, Stats::new()));
        }
    };

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };

        let path = entry.path();
        let file_name = entry.file_name();

        if !include_hidden && file_name.to_string_lossy().starts_with('.') {
            continue;
        }

        // symlink_metadata avoids following symlinks
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            eprintln!("warning: cannot stat '{}'", path.display());
            continue;
        };

        let file_type = metadata.file_type();

        if file_type.is_file() {
            let size = metadata.len();
            total_bytes += size;
            if let Ok(name) = CString::new(file_name.as_bytes()) {
                file_entries.push(FileEntry { name, size });
            }
        } else if file_type.is_dir() {
            subdirs.push(path);
        }
        // Symlinks and special files are skipped
    }

    // Sort for deterministic ordering
    file_entries.sort_by(|a, b| a.name.cmp(&b.name));
    subdirs.sort();

    let mut stats = Stats::new();
    stats.files_found = file_entries.len();
    stats.total_bytes = total_bytes;

    let ctx = DirContext {
        dir_fd,
        files: file_entries,
    };

    let mut dir_hash = if !ctx.files.is_empty() {
        stats.files_hashed = ctx.files.len();
        let checksum = hash_dir_files_openat(&ctx)?;
        progress.add_files(stats.files_hashed, total_bytes);
        LtHash16_1024::with_checksum(&checksum)?
    } else {
        LtHash16_1024::new()?
    };

    let subdir_results: Vec<_> = subdirs
        .par_iter()
        .map(|subdir| hash_dir_recursive_inner(subdir, include_hidden, progress))
        .collect();

    for result in subdir_results {
        let (subdir_hash, subdir_stats) = result?;
        stats.merge(&subdir_stats);
        stats.dirs_hashed += 1;
        dir_hash.try_add(&subdir_hash)?;
    }

    progress.add_dir();
    Ok((dir_hash, stats))
}

/// Collect file info for a flat directory (single stat per file).
fn collect_file_infos(
    dir: &str,
    include_hidden: bool,
) -> Result<(Vec<FileInfo>, u64), Box<dyn std::error::Error + Send + Sync>> {
    let mut file_infos = Vec::new();
    let mut total_bytes = 0u64;

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return Err(format!("cannot read directory '{dir}': {e}").into()),
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if !include_hidden && is_hidden(&path) {
            continue;
        }

        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };

        if metadata.file_type().is_file() {
            let size = metadata.len();
            total_bytes += size;
            file_infos.push(FileInfo { path, size });
        }
    }

    file_infos.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((file_infos, total_bytes))
}

/// Get optimal buffer size based on file size.
#[inline]
fn get_buffer_size(file_size: u64) -> usize {
    if file_size < 1_048_576 {
        SMALL_BUFFER_SIZE
    } else if file_size < 16_777_216 {
        MEDIUM_BUFFER_SIZE
    } else {
        LARGE_BUFFER_SIZE
    }
}

/// Safely convert file size to i64 for posix_fadvise, clamping to avoid wrapping.
#[cfg(target_os = "linux")]
#[inline]
fn file_size_as_i64(size: u64) -> i64 {
    i64::try_from(size).unwrap_or(i64::MAX)
}

/// Apply pre-read I/O hints (sequential readahead) for large files.
#[cfg(target_os = "linux")]
fn apply_io_hints_pre(fd: RawFd, size: u64) {
    if size >= IO_HINT_THRESHOLD {
        unsafe {
            libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }
    }
}

#[cfg(target_os = "macos")]
fn apply_io_hints_pre(fd: RawFd, size: u64) {
    if size >= IO_HINT_THRESHOLD {
        unsafe {
            libc::fcntl(fd, libc::F_RDAHEAD, 1);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn apply_io_hints_pre(_fd: RawFd, _size: u64) {}

/// Advise the kernel to free cached pages after reading (reduces cache pollution).
#[cfg(target_os = "linux")]
fn apply_io_hints_post(fd: RawFd, size: u64) {
    if size >= IO_HINT_THRESHOLD {
        unsafe {
            libc::posix_fadvise(fd, 0, file_size_as_i64(size), libc::POSIX_FADV_DONTNEED);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_io_hints_post(_fd: RawFd, _size: u64) {}

/// Core file hashing: read file contents through a blake3 hasher and produce XOF output.
/// Uses adaptive buffer sizing based on file size for optimal I/O throughput.
/// Heap-allocates all buffers to avoid stack overflow in rayon worker threads.
fn hash_file_contents(
    file: &mut File,
    file_size: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut hasher = blake3::Hasher::new();

    let buffer_size = get_buffer_size(file_size);
    let mut buffer = vec![0u8; buffer_size];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let mut output = vec![0u8; CHECKSUM_SIZE];
    hasher.finalize_xof().fill(&mut output);
    Ok(output)
}

/// Hash a file using openat() to avoid path resolution overhead.
fn hash_file_openat(
    dir_fd: RawFd,
    entry: &FileEntry,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let fd = unsafe { libc::openat(dir_fd, entry.name.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(format!("openat failed: {}", std::io::Error::last_os_error()).into());
    }

    // SAFETY: fd is a valid, newly opened file descriptor from openat().
    let mut file = unsafe { File::from_raw_fd(fd) };

    apply_io_hints_pre(file.as_raw_fd(), entry.size);
    let output = hash_file_contents(&mut file, entry.size)?;
    apply_io_hints_post(file.as_raw_fd(), entry.size);

    Ok(output)
}

/// Hash all files in a DirContext using openat().
fn hash_dir_files_openat(
    ctx: &DirContext,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if ctx.files.is_empty() {
        return Ok(vec![0u8; CHECKSUM_SIZE]);
    }

    ctx.files
        .par_iter()
        .map(|entry| hash_file_openat(ctx.dir_fd, entry))
        .try_reduce(|| vec![0u8; CHECKSUM_SIZE], reduce_checksums)
}

/// Hash a file by full path and return the BLAKE3 XOF output for LtHash.
fn hash_file_optimized(
    info: &FileInfo,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut file = File::open(&info.path)?;

    apply_io_hints_pre(file.as_raw_fd(), info.size);
    let output = hash_file_contents(&mut file, info.size)?;
    apply_io_hints_post(file.as_raw_fd(), info.size);

    Ok(output)
}

/// Hash files in parallel, combining checksums via tree reduction.
fn hash_files_parallel(
    file_infos: Vec<FileInfo>,
) -> Result<LtHash16_1024, Box<dyn std::error::Error + Send + Sync>> {
    if file_infos.is_empty() {
        return Ok(LtHash16_1024::new()?);
    }

    let combined = file_infos
        .par_iter()
        .map(hash_file_optimized)
        .try_reduce(|| vec![0u8; CHECKSUM_SIZE], reduce_checksums)?;

    LtHash16_1024::with_checksum(&combined)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}
