//! age-encrypted profile decryption behind the App's `decryptConfig`.
//!
//! The App detects the ASCII armor header itself and hands us the file plus an
//! X25519 secret key; both binary and armored age files are accepted here.

use std::fs;
use std::str::FromStr;

use age::x25519::Identity;

/// Decrypt an age file with an X25519 secret key (`AGE-SECRET-KEY-1...`) and
/// return the plaintext.
pub fn decrypt_file(path: &str, secret_key: &str) -> Result<String, String> {
    let raw = fs::read(path).map_err(|e| format!("read {}: {e}", path))?;
    let identity = Identity::from_str(secret_key.trim())
        .map_err(|e| format!("invalid age secret key: {e}"))?;
    let plain =
        age::decrypt(&identity, &raw).map_err(|e| format!("age decryption failed: {e}"))?;
    String::from_utf8(plain).map_err(|_| "decrypted profile is not valid UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    #[test]
    fn armored_profile_round_trips() {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let text = "proxies:\n  - name: test\n    type: ss\n    server: 127.0.0.1\n";
        let armored =
            age::encrypt_and_armor(&recipient, text.as_bytes()).expect("encrypt for test");
        assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

        let dir = std::env::temp_dir().join(format!("skyward-age-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profile.age");
        std::fs::write(&path, armored).unwrap();

        let key = identity.to_string().expose_secret().to_string();
        let out = decrypt_file(path.to_str().unwrap(), &key).expect("decrypt");
        assert_eq!(out, text);

        std::fs::remove_dir_all(&dir).ok();
    }
}
