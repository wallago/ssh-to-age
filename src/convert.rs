use anyhow::{Context, Result, anyhow};
use bech32::{Bech32m, Hrp};
use curve25519_dalek::{MontgomeryPoint, edwards::CompressedEdwardsY, traits::IsIdentity};
use sha2::{Digest, Sha512};
use ssh_key::{PrivateKey, PublicKey};

/// Converts an Ed25519 private key to a Curve25519 private key (scalar).
fn ed25519_private_key_to_curve25519(ed_sk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(ed_sk); // the seed
    let hash = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);

    // Clamp bits according to Curve25519 spec
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;

    out
}

/// Converts an Ed25519 public key to a Curve25519 public key (Montgomery point).
fn ed25519_public_key_to_curve25519(ed_pk: &[u8; 32]) -> Result<[u8; 32]> {
    if ed_pk.len() != 32 {
        anyhow::bail!("Invalid Ed25519 public key length");
    }

    let compressed = CompressedEdwardsY(*ed_pk);
    let edwards_point = compressed
        .decompress()
        .context("Failed to decompress Ed25519 public key")?;

    if edwards_point.is_identity() {
        anyhow::bail!("Ed25519 public key is the identity point");
    }

    let montgomery_point: MontgomeryPoint = edwards_point.to_montgomery();

    Ok(montgomery_point.to_bytes())
}

fn encode_public_key(pk: &[u8; 32]) -> Result<String> {
    let curve_pk = ed25519_public_key_to_curve25519(pk)?;
    let hrp = Hrp::parse("age")?;
    Ok(bech32::encode::<Bech32m>(hrp, &curve_pk)?)
}

fn encode_private_key(sk: &[u8; 32]) -> Result<String> {
    let curve_sk = ed25519_private_key_to_curve25519(sk);
    let hrp = Hrp::parse("AGE-SECRET-KEY-")?;
    Ok(bech32::encode::<Bech32m>(hrp, &curve_sk)?.to_uppercase())
}

pub fn ssh_private_key_to_age(openssh_sk: &[u8]) -> Result<(String, String)> {
    let ssh_sk = PrivateKey::from_openssh(openssh_sk)?;
    let ed_keypair = ssh_sk
        .key_data()
        .ed25519()
        .ok_or(anyhow!("Invalid Ed25519 private key format"))?;
    let curve_pk = encode_public_key(&ed_keypair.public.0)?;
    let curve_sk = encode_private_key(&ed_keypair.private.to_bytes())?;
    Ok((curve_sk, curve_pk))
}

pub fn ssh_public_key_to_age(openssh_pk: &str) -> Result<String> {
    let ssh_pk = PublicKey::from_openssh(openssh_pk)?;
    let ed_pk = ssh_pk
        .key_data()
        .ed25519()
        .ok_or(anyhow!("Invalid Ed25519 public key format"))?
        .0;
    encode_public_key(&ed_pk)
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::traits::Identity;

    use super::*;

    #[test]
    fn test_private_key_clamping() {
        let seed = [0xFFu8; 32]; // all bits set, worst case
        let clamped = ed25519_private_key_to_curve25519(&seed);

        // Clamp rules for Curve25519:
        assert_eq!(clamped[0] & 7, 0); // lowest 3 bits zero
        assert_eq!(clamped[31] & 0x80, 0); // highest bit zero
        assert_eq!(clamped[31] & 0x40, 0x40); // second highest bit set
    }

    #[test]
    fn test_ed25519_public_key_to_curve25519() {
        let ed25519_pubkey: [u8; 32] = [
            0x8d, 0x3d, 0xe8, 0x64, 0x6a, 0x75, 0x2e, 0x8f, 0x99, 0x0c, 0x13, 0x84, 0xd2, 0xa5,
            0x91, 0x77, 0x74, 0x45, 0x4b, 0x63, 0x98, 0xe3, 0x2c, 0x2e, 0x1c, 0x8f, 0xa5, 0xc3,
            0xf3, 0x3f, 0x93, 0x4e,
        ];
        let result = ed25519_public_key_to_curve25519(&ed25519_pubkey);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_ed25519_public_key_identity_fails() {
        // This is the compressed point for the identity element (all zeroes is invalid compressed format but identity is valid and known)
        let identity_pk = CompressedEdwardsY::identity().to_bytes();
        let result = ed25519_public_key_to_curve25519(&identity_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_public_key() {
        let ed25519_pubkey: [u8; 32] = [
            0x8d, 0x3d, 0xe8, 0x64, 0x6a, 0x75, 0x2e, 0x8f, 0x99, 0x0c, 0x13, 0x84, 0xd2, 0xa5,
            0x91, 0x77, 0x74, 0x45, 0x4b, 0x63, 0x98, 0xe3, 0x2c, 0x2e, 0x1c, 0x8f, 0xa5, 0xc3,
            0xf3, 0x3f, 0x93, 0x4e,
        ];
        let encoded = encode_public_key(&ed25519_pubkey);
        assert!(encoded.is_ok());
        assert!(encoded.unwrap().starts_with("age1"));
    }

    #[test]
    fn test_encode_private_key() {
        let seed = [0x00u8; 32];
        let encoded = encode_private_key(&seed);
        assert!(encoded.is_ok());
        assert!(encoded.unwrap().starts_with("AGE-SECRET-KEY-"));
    }
}
