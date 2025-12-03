use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use lthash::LtHash16_1024;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

struct Args {
    directory: String,
    recursive: bool,
    include_hidden: bool,
}

struct Stats {
    files_found: usize,
    files_hashed: usize,
    files_skipped: usize,
    dirs_hashed: usize,
    total_bytes: u64,
}

fn main() {
    let args = parse_args();

    if let Err(e) = run(&args) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut directory = ".".to_string();
    let mut recursive = false;
    let mut include_hidden = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--recursive" => recursive = true,
            "--hidden" => include_hidden = true,
            arg if !arg.starts_with('-') => directory = arg.to_string(),
            other => {
                eprintln!("unknown option: {}", other);
                eprintln!("usage: lthash_dir [-r] [--hidden] [directory]");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    Args { directory, recursive, include_hidden }
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    let (hash, stats) = if args.recursive {
        hash_directory_recursive(&args.directory, args.include_hidden)?
    } else {
        hash_directory_flat(&args.directory, args.include_hidden)?
    };

    let total_time = start.elapsed();
    let encoded = URL_SAFE_NO_PAD.encode(hash.get_checksum());

    println!("{}", encoded);
    eprintln!();
    eprintln!("Statistics:");
    eprintln!("  Directory:      {}", args.directory);
    eprintln!("  Recursive:      {}", args.recursive);
    eprintln!("  Files found:    {}", stats.files_found);
    eprintln!("  Files hashed:   {}", stats.files_hashed);
    eprintln!("  Files skipped:  {}", stats.files_skipped);
    if args.recursive {
        eprintln!("  Dirs hashed:    {}", stats.dirs_hashed);
    }
    eprintln!("  Total bytes:    {} ({:.2} MB)", stats.total_bytes, stats.total_bytes as f64 / 1_000_000.0);
    eprintln!();
    eprintln!("Timing:");
    eprintln!("  Total:          {:?}", total_time);

    if total_time.as_secs_f64() > 0.0 {
        let throughput = stats.total_bytes as f64 / total_time.as_secs_f64() / 1_000_000.0;
        eprintln!("  Throughput:     {:.2} MB/s", throughput);
    }

    Ok(())
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.starts_with('.'))
        .unwrap_or(false)
}

fn hash_directory_flat(dir: &str, include_hidden: bool) -> Result<(LtHash16_1024, Stats), Box<dyn std::error::Error>> {
    let files = collect_files_flat(dir, include_hidden)?;
    let files_found = files.len();

    if files_found == 0 {
        return Ok((LtHash16_1024::new()?, Stats {
            files_found: 0,
            files_hashed: 0,
            files_skipped: 0,
            dirs_hashed: 0,
            total_bytes: 0,
        }));
    }

    let (readers, total_bytes, skipped) = open_files(&files);

    if readers.is_empty() {
        return Ok((LtHash16_1024::new()?, Stats {
            files_found,
            files_hashed: 0,
            files_skipped: skipped,
            dirs_hashed: 0,
            total_bytes: 0,
        }));
    }

    let hash = LtHash16_1024::from_readers_parallel(readers)?;

    Ok((hash, Stats {
        files_found,
        files_hashed: files_found - skipped,
        files_skipped: skipped,
        dirs_hashed: 0,
        total_bytes,
    }))
}

fn hash_directory_recursive(dir: &str, include_hidden: bool) -> Result<(LtHash16_1024, Stats), Box<dyn std::error::Error>> {
    let root = Path::new(dir).canonicalize()
        .map_err(|e| format!("cannot resolve '{}': {}", dir, e))?;

    let mut total_stats = Stats {
        files_found: 0,
        files_hashed: 0,
        files_skipped: 0,
        dirs_hashed: 0,
        total_bytes: 0,
    };

    let hash = hash_dir_recursive_inner(&root, &mut total_stats, include_hidden)?;
    Ok((hash, total_stats))
}

fn hash_dir_recursive_inner(
    dir: &Path,
    stats: &mut Stats,
    include_hidden: bool,
) -> Result<LtHash16_1024, Box<dyn std::error::Error>> {
    // Use walkdir to get immediate children only (max_depth=1)
    // follow_links(false) prevents symlink loops
    let mut files = Vec::new();
    let mut subdirs = Vec::new();

    for entry in WalkDir::new(dir).max_depth(1).follow_links(false) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                if let Some(path) = e.path() {
                    eprintln!("warning: cannot access '{}': {}", path.display(), e);
                }
                continue;
            }
        };

        // Skip the root directory itself
        if entry.depth() == 0 {
            continue;
        }

        let path = entry.path();

        // Skip hidden files/dirs unless include_hidden is set
        if !include_hidden && is_hidden(path) {
            continue;
        }

        let file_type = entry.file_type();

        if file_type.is_file() {
            files.push(path.to_path_buf());
        } else if file_type.is_dir() {
            subdirs.push(path.to_path_buf());
        }
        // Skip symlinks and other file types
    }

    // Sort for deterministic ordering
    files.sort();
    subdirs.sort();

    stats.files_found += files.len();

    // Hash all files in this directory
    let (readers, bytes, skipped) = open_files(&files);
    stats.files_skipped += skipped;
    stats.total_bytes += bytes;

    let mut dir_hash = if !readers.is_empty() {
        stats.files_hashed += readers.len();
        LtHash16_1024::from_readers_parallel(readers)?
    } else {
        LtHash16_1024::new()?
    };

    // Recursively hash subdirectories and add their checksums
    for subdir in subdirs {
        let subdir_hash = hash_dir_recursive_inner(&subdir, stats, include_hidden)?;
        // Add subdirectory's checksum as data to this directory's hash
        dir_hash.add_object(subdir_hash.get_checksum())?;
        stats.dirs_hashed += 1;
    }

    Ok(dir_hash)
}

fn collect_files_flat(dir: &str, include_hidden: bool) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return Err(format!("cannot read directory '{}': {}", dir, e).into()),
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();

        // Skip hidden files unless include_hidden is set
        if !include_hidden && is_hidden(&path) {
            continue;
        }

        let metadata = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.is_file() {
            files.push(path);
        }
    }

    files.sort();
    Ok(files)
}

fn open_files(files: &[PathBuf]) -> (Vec<BufReader<File>>, u64, usize) {
    let mut readers = Vec::with_capacity(files.len());
    let mut total_bytes = 0u64;
    let mut skipped = 0;

    for path in files {
        match File::open(path) {
            Ok(file) => {
                if let Ok(metadata) = file.metadata() {
                    total_bytes += metadata.len();
                }
                readers.push(BufReader::new(file));
            }
            Err(e) => {
                eprintln!("warning: skipping '{}': {}", path.display(), e);
                skipped += 1;
            }
        }
    }

    (readers, total_bytes, skipped)
}
