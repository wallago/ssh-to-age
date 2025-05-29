# ssh-to-age

Convert SSH Ed25519 keys to Age keys. This is useful for usage in [sops-nix](https://github.com/Mic92/sops-nix) and [sops](https://github.com/getsops/sops).\
No rust lib provided a function to convert SSH Ed25519 key to Age.

Age can derive an encryption key from that public key, avoiding the need to manage yet another keypair.\
Ed25519 keys are strong, compact, and widely supported. Age converts the SSH key into an internal format (X25519) suitable for secure encryption.

## 🔑 What is Ed25519

Ed25519 is an elliptic curve signing algorithm using EdDSA and Curve25519.

## 🔑 What is Age

Age a simple, modern, and secure file encryption tool (alternative to GPG).\

## 📃 Purpose of this lib

Take an SSH key and transform it to an Age key.

## 🤝 Acknowledgements

This rust lib is inspired by the excellent work done by [Mic92](https://github.com/Mic92/dotfiles) and his repositorie [ssh-to-age](https://github.com/Mic92/ssh-to-age).
