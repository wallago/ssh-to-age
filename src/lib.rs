use anyhow::{Result, anyhow};
use base64::prelude::*;

pub fn from_ssh_pub_key(ssh_pub_key: &str) -> Result<String> {
    let ssh_pub_key_bytes = decode_ssh_pub_key(ssh_pub_key)?;
    let age = convert_ssh_pub_key_to_age_recipient(&ssh_pub_key_bytes)?;
    Ok(age)
}

// ssh-ed25519 <base64-encoded-bytes> [comment]
fn decode_ssh_pub_key(ssh_pub_key: &str) -> Result<[u8; 32]> {
    let mut parts = ssh_pub_key.split_whitespace();

    if parts.next() != Some("ssh-ed25519") {
        return Err(anyhow!("Expected ssh-ed25519 key"));
    }

    let base64_str = parts
        .next()
        .ok_or_else(|| anyhow!("Missing base64 part in SSH public key"))?;
    let decoded = BASE64_STANDARD.decode(base64_str)?;
    let cursor = std::io::Cursor::new(decoded);

    let key_type_len = u32::from_be_bytes(
        cursor.get_ref()[0..4]
            .try_into()
            .map_err(|e| anyhow!("Failed to convert slice to array: {e}"))?,
    ) as usize;
    let key_type = &cursor.get_ref()[4..4 + key_type_len];
    if key_type != b"ssh-ed25519" {
        return Err(anyhow!("Expected key type ssh-ed25519"));
    }

    let pubkey_offset = 4 + key_type_len;
    let pubkey_len = u32::from_be_bytes(
        cursor.get_ref()[pubkey_offset..pubkey_offset + 4]
            .try_into()
            .map_err(|e| anyhow!("Failed to convert slice to array: {e}"))?,
    ) as usize;
    if pubkey_len != 32 {
        return Err(anyhow!("Expected 32-byte Ed25519 pubkey"));
    }

    let key_start = pubkey_offset + 4;
    let key_bytes = &cursor.get_ref()[key_start..key_start + 32];

    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);
    Ok(key)
}

fn convert_ssh_pub_key_to_age_recipient(ssh_pub_key_bytes: &[u8; 32]) -> Result<String> {
    let mut age_bytes = vec![0x01];
    age_bytes.extend_from_slice(ssh_pub_key_bytes);
    let hrp = bech32::Hrp::parse("age")?;
    Ok(bech32::encode::<bech32::Bech32m>(
        hrp,
        &age_bytes.as_slice(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_key_to_age_key() {
        let result = from_ssh_pub_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICzGeuU9ZoBrWz2KPISui/XypsQOvogQqcHGIVig9mvn root@octopus",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "age1qykvv7h984ngq66m8k9rep9w306l9fkyp6lgsy9fc8rzzk9q7e47w9ycwg6".to_string()
        );

        let result = from_ssh_pub_key(
            "AAAAC3NzaC1lZDI1NTE5AAAAICzGeuU9ZoBrWz2KPISui/XypsQOvogQqcHGIVig9mvn root@octopus",
        );
        assert!(result.is_err());

        let result = from_ssh_pub_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICzGeuU9ZoBrWz2KPISui/XypsQOvogQqcHGIVig9mvn",
        );
        assert!(result.is_ok());

        let result = from_ssh_pub_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICzGeuU9ZoBrWz2KPISui/XypsQOvogQqcHGIVig9mv root@octopus",
        );
        assert!(result.is_err());
    }
}
