use lthash::{Blake2xb, LtHash16_1024, LtHashError};

fn main() -> Result<(), LtHashError> {
    println!("Testing Blake2xb implementation...");

    // Test Blake2xb
    let data = b"Hello, World!";
    let mut output = vec![0u8; 32];
    Blake2xb::hash(&mut output, data, &[], &[], &[])?;
    println!("Blake2xb hash: {}", hex::encode(&output));

    println!("Testing LtHash implementation...");

    // Test LtHash with method chaining
    let mut lthash = LtHash16_1024::new()?;

    // Add some data using chaining
    lthash.add(b"object1")?.add(b"object2")?.add(b"object3")?;

    println!(
        "Checksum after adding 3 items: {}",
        hex::encode(lthash.checksum())
    );

    // Remove one item, then add more using chaining
    lthash
        .remove(b"object2")?
        .add(b"object4")?
        .add(b"object5")?;

    println!(
        "Checksum after removing 1 item: {}",
        hex::encode(lthash.checksum())
    );

    // Test commutativity - add items in different order using chaining
    let mut lthash2 = LtHash16_1024::new()?;
    lthash2
        .add(b"object3")?
        .add(b"object1")?
        .add(b"object5")?
        .add(b"object4")?
        .add(b"object6")?
        .remove(b"object6")?;

    println!(
        "Second hash with same objects: {}",
        hex::encode(lthash2.checksum())
    );

    if lthash == lthash2 {
        println!("✓ Commutativity test passed!");
    } else {
        println!("✗ Commutativity test failed!");
    }

    Ok(())
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
