pub mod convert;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_pk_to_age() {
        let result = convert::ssh_public_key_to_age(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICFrs5OngYGD5FHUaYqr3gAk7NApAuFCL3cVaHLSWRXL",
        );
        assert!(result.is_ok());
        let recipient = result.unwrap();
        assert_eq!(
            recipient,
            "age1wy42r2p2c67ckywgq8xj7ejf6eykqfu623wktxeh729rtagu4fkqrsqsg6"
        );
    }

    #[test]
    fn test_ssh_sk_to_age() {
        let result = convert::ssh_private_key_to_age(
            b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAha7OTp4GBg+RR1GmKq94AJOzQKQLhQi93FWhy0lkVywAAAJDFKuT1xSrk
9QAAAAtzc2gtZWQyNTUxOQAAACAha7OTp4GBg+RR1GmKq94AJOzQKQLhQi93FWhy0lkVyw
AAAECfpgF0oYy6xXA5JRzgTNwNYLcUIGlZhkOEDV7XRuIYWyFrs5OngYGD5FHUaYqr3gAk
7NApAuFCL3cVaHLSWRXLAAAADHJvb3RAb2N0b3B1cwE=
-----END OPENSSH PRIVATE KEY-----",
        );
        assert!(result.is_ok());
        let age = result.unwrap();
        assert_eq!(
            age.recipient,
            "age1wy42r2p2c67ckywgq8xj7ejf6eykqfu623wktxeh729rtagu4fkqrsqsg6"
        );
        assert_eq!(
            age.secret,
            "AGE-SECRET-KEY-1GQ46Z46GKWWDXR6KF96CYS9DWHWJWCV4KCCE4HA0C7ZZUY74JFPSAC42H6"
        );
    }

    #[test]
    fn test_ssh_private_key_to_age_invalid_key() {
        let invalid_key = b"not a valid private key";
        let result = convert::ssh_private_key_to_age(invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_ssh_public_key_to_age_invalid_key() {
        let invalid_key = "not a valid private key";
        let result = convert::ssh_public_key_to_age(invalid_key);
        assert!(result.is_err());
    }
}
