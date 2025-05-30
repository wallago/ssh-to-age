# 🔁 ssh-to-age

Convert SSH Ed25519 keys to age keys. This is useful for usage in [sops-nix](https://github.com/Mic92/sops-nix) and [sops](https://github.com/getsops/sops).\

This crate fills a gap in the Rust ecosystem: there is currently no Rust-native library to convert Ed25519 SSH keys into [age](https://github.com/FiloSottile/age) compatible X25519 keys.\
Crate like [rage](https://github.com/str4d/rage), doesn't convert my ssh key as exepected.\
With this, you can reuse your existing SSH keypair for encryption — no need to manage a separate key just for age.

## 🧠 Why?

Age supports encrypting to X25519 public keys. Since SSH Ed25519 keys are widely supported and already in use, this library converts them into age-compatible X25519 keys:

- ✅ Ed25519 keys are compact, secure, and already in use for SSH.
- ✅ Age uses X25519, a related elliptic curve, for encryption.
- 🔄 This library converts Ed25519 to X25519 using proper cryptographic primitives.

Age can derive an encryption key from that public key, avoiding the need to manage yet another keypair.

## 🔐 What is Ed25519?

Ed25519 is a signature scheme based on the Edwards form of Curve25519. It is used for signing and is known for its speed and security.

## 📦 What is age?

age is a modern, simple, and secure file encryption tool — a user-friendly alternative to GPG.

## 📃 What does this library do?

- ✅ Parses OpenSSH Ed25519 private and public keys
- 🔁 Converts them to age-compatible X25519 keys
- 🧾 Returns them in the correct Bech32m format (age1..., AGE-SECRET-KEY-...)
- 🛠️ Easily integrable in Rust projects

## 🚀 Example Use Case

For use in `sops-nix`, where age recipients are typically stored in your Nix config:

```nix
sops.age.keyFile = "/path/to/your/AGE-SECRET-KEY-...";
```

Instead of generating a new age key, just convert your existing SSH key.

## 🤝 Acknowledgements

This rust lib is inspired by the excellent work done by [Mic92](https://github.com/Mic92/dotfiles) and his repositorie [ssh-to-age](https://github.com/Mic92/ssh-to-age).

---

Let me know if you have any suggestion.
