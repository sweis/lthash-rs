//! LtHash Command Line Tool
//!
//! A Unix-friendly CLI for computing and combining LtHash checksums.
//! Uses streaming to handle large files without loading them into memory.
//!
//! # Usage
//!
//! ```bash
//! # Hash a file
//! lthash myfile.txt
//!
//! # Hash stdin
//! cat myfile.txt | lthash -
//!
//! # Add a file to an existing hash
//! lthash add <hash> myfile.txt
//!
//! # Subtract a file from an existing hash
//! lthash sub <hash> myfile.txt
//!
//! # Piping: chain operations
//! lthash file1.txt | lthash add - file2.txt | lthash add - file3.txt
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use lthash::LtHash16_1024;
use std::env;
use std::fs::File;
use std::io::{self, BufReader};
use std::process;

const USAGE: &str = r#"lthash - Homomorphic hash tool

USAGE:
    lthash [FILE]           Hash a file (or stdin with '-')
    lthash add HASH [FILE]  Add file to existing hash
    lthash sub HASH [FILE]  Subtract file from existing hash

ARGUMENTS:
    FILE    File to process (use '-' for stdin)
    HASH    URL-safe base64 encoded hash (use '-' to read from stdin)

EXAMPLES:
    # Hash a file
    lthash myfile.txt

    # Hash stdin
    echo "hello" | lthash -

    # Combine hashes (piping)
    lthash file1.txt | lthash add - file2.txt | lthash add - file3.txt

    # Remove a file's contribution
    lthash sub $COMBINED_HASH removed_file.txt

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
                eprintln!("usage: lthash add HASH [FILE]");
                process::exit(1);
            }
            let hash_arg = &args[2];
            let file_arg = args.get(3).map(|s| s.as_str()).unwrap_or("-");
            cmd_add(hash_arg, file_arg)
        }
        "sub" => {
            if args.len() < 3 {
                eprintln!("error: 'sub' requires a hash argument");
                eprintln!("usage: lthash sub HASH [FILE]");
                process::exit(1);
            }
            let hash_arg = &args[2];
            let file_arg = args.get(3).map(|s| s.as_str()).unwrap_or("-");
            cmd_sub(hash_arg, file_arg)
        }
        file_arg => cmd_hash(file_arg),
    }
}

/// Hash a single file using streaming (no full file load into memory)
fn cmd_hash(file_arg: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut hash = LtHash16_1024::new()?;
    hash_file_stream(&mut hash, file_arg, true)?;

    let encoded = URL_SAFE_NO_PAD.encode(hash.get_checksum());
    println!("{}", encoded);

    Ok(())
}

/// Add a file's hash to an existing hash using streaming
fn cmd_add(hash_arg: &str, file_arg: &str) -> Result<(), Box<dyn std::error::Error>> {
    let existing_hash = read_hash(hash_arg)?;

    let mut hash = LtHash16_1024::with_checksum(&existing_hash)?;
    hash_file_stream(&mut hash, file_arg, true)?;

    let encoded = URL_SAFE_NO_PAD.encode(hash.get_checksum());
    println!("{}", encoded);

    Ok(())
}

/// Subtract a file's hash from an existing hash using streaming
fn cmd_sub(hash_arg: &str, file_arg: &str) -> Result<(), Box<dyn std::error::Error>> {
    let existing_hash = read_hash(hash_arg)?;

    let mut hash = LtHash16_1024::with_checksum(&existing_hash)?;
    hash_file_stream(&mut hash, file_arg, false)?;

    let encoded = URL_SAFE_NO_PAD.encode(hash.get_checksum());
    println!("{}", encoded);

    Ok(())
}

/// Stream a file into the hash (add or remove based on `add` flag)
fn hash_file_stream(
    hash: &mut LtHash16_1024,
    file_arg: &str,
    add: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if file_arg == "-" {
        let stdin = io::stdin();
        let reader = stdin.lock();
        if add {
            hash.add_object_stream(reader)?;
        } else {
            hash.remove_object_stream(reader)?;
        }
    } else {
        let file =
            File::open(file_arg).map_err(|e| format!("cannot open '{}': {}", file_arg, e))?;
        let reader = BufReader::new(file);
        if add {
            hash.add_object_stream(reader)?;
        } else {
            hash.remove_object_stream(reader)?;
        }
    }

    Ok(())
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
