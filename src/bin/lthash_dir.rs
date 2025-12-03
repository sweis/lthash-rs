use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use lthash::LtHash16_1024;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = if args.len() > 1 { &args[1] } else { "." };

    if let Err(e) = run(dir) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run(dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    // Collect regular files, skipping unreadable entries
    let files = collect_files(dir)?;
    let file_count = files.len();
    let collect_time = start.elapsed();

    if file_count == 0 {
        println!("No readable files found in '{}'", dir);
        return Ok(());
    }

    // Open all files first to catch permission errors early
    let hash_start = Instant::now();
    let (readers, total_bytes, skipped) = open_files(&files);

    if readers.is_empty() {
        println!("No files could be opened");
        return Ok(());
    }

    // Hash files in parallel using streaming
    let hash = LtHash16_1024::from_readers_parallel(readers)?;
    let hash_time = hash_start.elapsed();

    let total_time = start.elapsed();
    let encoded = URL_SAFE_NO_PAD.encode(hash.get_checksum());

    // Output results
    println!("{}", encoded);
    eprintln!();
    eprintln!("Statistics:");
    eprintln!("  Directory:      {}", dir);
    eprintln!("  Files found:    {}", file_count);
    eprintln!("  Files hashed:   {}", file_count - skipped);
    eprintln!("  Files skipped:  {}", skipped);
    eprintln!("  Total bytes:    {} ({:.2} MB)", total_bytes, total_bytes as f64 / 1_000_000.0);
    eprintln!();
    eprintln!("Timing:");
    eprintln!("  File discovery: {:?}", collect_time);
    eprintln!("  Hashing:        {:?}", hash_time);
    eprintln!("  Total:          {:?}", total_time);

    if hash_time.as_secs_f64() > 0.0 {
        let throughput = total_bytes as f64 / hash_time.as_secs_f64() / 1_000_000.0;
        eprintln!("  Throughput:     {:.2} MB/s", throughput);
    }

    Ok(())
}

fn collect_files(dir: &str) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return Err(format!("cannot read directory '{}': {}", dir, e).into()),
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // Skip entries we can't read
        };

        let path = entry.path();

        // Check if it's a regular file (not directory, symlink, device, etc.)
        let metadata = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue, // Skip files we can't stat
        };

        if metadata.is_file() {
            files.push(path);
        }
    }

    // Sort for deterministic ordering
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
