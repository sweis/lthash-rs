//! LtHash Command Line Tool
//!
//! A Unix-friendly CLI for computing and combining LtHash checksums.
//! Uses streaming to handle large files without loading them into memory.
//! Supports parallel hashing when built with the `parallel` feature.
//!
//! # Usage
//!
//! ```bash
//! # Hash one or more files
//! lthash myfile.txt
//! lthash file1.txt file2.txt file3.txt
//!
//! # Hash stdin
//! cat myfile.txt | lthash -
//!
//! # Add files to an existing hash
//! lthash add <hash> file1.txt file2.txt ...
//!
//! # Remove files from an existing hash
//! lthash remove <hash> file1.txt file2.txt ...
//!
//! # Piping: chain operations
//! lthash file1.txt | lthash add - file2.txt file3.txt
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use lthash::LtHash16_1024;
use std::env;
use std::fs::File;
use std::io;
use std::process;

const USAGE: &str = r#"lthash - Homomorphic hash tool

USAGE:
    lthash [FILE...]              Hash one or more files (use '-' for stdin)
    lthash add HASH [FILE...]     Add files to existing hash
    lthash remove HASH [FILE...]  Remove files from existing hash

ARGUMENTS:
    FILE    File(s) to process (use '-' for stdin, only valid as sole argument)
    HASH    URL-safe base64 encoded hash (use '-' to read from stdin)

EXAMPLES:
    # Hash a single file
    lthash myfile.txt

    # Hash multiple files (combined homomorphically)
    lthash file1.txt file2.txt file3.txt

    # Hash stdin
    echo "hello" | lthash -

    # Combine hashes (piping)
    lthash file1.txt | lthash add - file2.txt file3.txt

    # Remove files' contribution
    lthash remove $COMBINED_HASH removed1.txt removed2.txt

FEATURES:
    Build with --features parallel for multi-threaded file hashing

OUTPUT:
    Prints URL-safe base64 encoded hash to stdout (no padding, safe for CLI args)
"#;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("{}", USAGE);
        process::exit(1);
    }

    match args[1].as_str() {
        "-h" | "--help" | "help" => {
            println!("{}", USAGE);
            Ok(())
        }
        "add" => {
            if args.len() < 3 {
                eprintln!("error: 'add' requires a hash argument");
                eprintln!("usage: lthash add HASH [FILE...]");
                process::exit(1);
            }
            let hash_arg = &args[2];
            let file_args: Vec<&str> = if args.len() > 3 {
                args[3..].iter().map(|s| s.as_str()).collect()
            } else {
                vec!["-"]
            };
            cmd_add(hash_arg, &file_args)
        }
        "remove" => {
            if args.len() < 3 {
                eprintln!("error: 'remove' requires a hash argument");
                eprintln!("usage: lthash remove HASH [FILE...]");
                process::exit(1);
            }
            let hash_arg = &args[2];
            let file_args: Vec<&str> = if args.len() > 3 {
                args[3..].iter().map(|s| s.as_str()).collect()
            } else {
                vec!["-"]
            };
            cmd_remove(hash_arg, &file_args)
        }
        _ => {
            // All remaining args are file paths
            let file_args: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();
            cmd_hash(&file_args)
        }
    }
}

/// Hash one or more files
fn cmd_hash(file_args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let hash = hash_files(file_args)?;
    let encoded = URL_SAFE_NO_PAD.encode(hash.checksum());
    println!("{}", encoded);
    Ok(())
}

/// Add files' hashes to an existing hash
fn cmd_add(hash_arg: &str, file_args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let existing_hash = read_hash(hash_arg)?;
    let mut hash = LtHash16_1024::with_checksum(&existing_hash)?;

    let file_hash = hash_files(file_args)?;
    hash.try_add(&file_hash)?;

    let encoded = URL_SAFE_NO_PAD.encode(hash.checksum());
    println!("{}", encoded);
    Ok(())
}

/// Remove files' hashes from an existing hash
fn cmd_remove(hash_arg: &str, file_args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let existing_hash = read_hash(hash_arg)?;
    let mut hash = LtHash16_1024::with_checksum(&existing_hash)?;

    let file_hash = hash_files(file_args)?;
    hash.try_sub(&file_hash)?;

    let encoded = URL_SAFE_NO_PAD.encode(hash.checksum());
    println!("{}", encoded);
    Ok(())
}

/// Hash multiple files, using parallel processing when available and beneficial
fn hash_files(file_args: &[&str]) -> Result<LtHash16_1024, Box<dyn std::error::Error>> {
    // Handle stdin case - must be processed sequentially
    if file_args.len() == 1 && file_args[0] == "-" {
        let mut hash = LtHash16_1024::new()?;
        let stdin = io::stdin();
        let reader = stdin.lock();
        hash.add_stream(reader)?;
        return Ok(hash);
    }

    // Check for stdin in multi-file context (not allowed)
    if file_args.contains(&"-") {
        return Err("stdin (-) can only be used as the sole file argument".into());
    }

    // Use parallel hashing if available and we have multiple files
    #[cfg(feature = "parallel")]
    {
        if file_args.len() > 1 {
            return hash_files_parallel(file_args);
        }
    }

    // Sequential fallback (single file or no parallel feature)
    hash_files_sequential(file_args)
}

/// Hash files sequentially using streaming
fn hash_files_sequential(file_args: &[&str]) -> Result<LtHash16_1024, Box<dyn std::error::Error>> {
    let mut hash = LtHash16_1024::new()?;

    for file_arg in file_args {
        let file =
            File::open(file_arg).map_err(|e| format!("cannot open '{}': {}", file_arg, e))?;
        hash.add_stream(file)?;
    }

    Ok(hash)
}

/// Hash files in parallel using rayon
#[cfg(feature = "parallel")]
fn hash_files_parallel(file_args: &[&str]) -> Result<LtHash16_1024, Box<dyn std::error::Error>> {
    // Open all files first to catch errors early
    let files: Result<Vec<_>, _> = file_args
        .iter()
        .map(|path| File::open(path).map_err(|e| format!("cannot open '{}': {}", path, e)))
        .collect();

    // Hash in parallel (blake3_xof uses 64KB internal buffer, no BufReader needed)
    LtHash16_1024::from_streams_parallel(files?).map_err(Into::into)
}

/// Read and decode a hash from argument or stdin
fn read_hash(hash_arg: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hash_str = if hash_arg == "-" {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    } else {
        hash_arg.to_string()
    };

    if hash_str.is_empty() {
        return Ok(vec![0u8; LtHash16_1024::checksum_size_bytes()]);
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(&hash_str)
        .map_err(|e| format!("invalid base64 hash: {}", e))?;

    let expected_size = LtHash16_1024::checksum_size_bytes();
    if decoded.len() != expected_size {
        return Err(format!(
            "invalid hash size: expected {} bytes, got {} bytes",
            expected_size,
            decoded.len()
        )
        .into());
    }

    Ok(decoded)
}
