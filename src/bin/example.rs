use lthash::{Blake2xb, LtHash16_1024, LtHashError};

fn main() -> Result<(), LtHashError> {
    println!("Testing Blake2xb implementation...");

    // Test Blake2xb
    let data = b"Hello, World!";
    let mut output = vec![0u8; 32];
    Blake2xb::hash(&mut output, data, &[], &[], &[])?;
    println!("Blake2xb hash: {}", hex::encode(&output));

    println!("Testing LtHash implementation...");

    // Test LtHash
    let mut lthash = LtHash16_1024::new()?;

    // Add some objects
    lthash.add_object(b"object1")?;
    lthash.add_object(b"object2")?;
    lthash.add_object(b"object3")?;

    println!(
        "Checksum after adding 3 objects: {}",
        hex::encode(lthash.get_checksum())
    );

    // Remove one object
    lthash.remove_object(b"object2")?;

    lthash.add_object(b"object4")?;
    lthash.add_object(b"object5")?;

    println!(
        "Checksum after removing 1 object: {}",
        hex::encode(lthash.get_checksum())
    );

    // Test commutativity - add objects in different order
    let mut lthash2 = LtHash16_1024::new()?;
    lthash2.add_object(b"object3")?;
    lthash2.add_object(b"object1")?;
    lthash2.add_object(b"object5")?;
    lthash2.add_object(b"object4")?;
    lthash2.add_object(b"object6")?;
    lthash2.remove_object(b"object6")?;

    println!(
        "Second hash with same objects: {}",
        hex::encode(lthash2.get_checksum())
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
