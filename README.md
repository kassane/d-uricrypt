# URICrypt

[![Static Badge](https://img.shields.io/badge/v2.111.0%20(stable)-f8240e?logo=d&logoColor=f8240e&label=runtime)](https://dlang.org/download.html)
![Latest release](https://img.shields.io/github/v/release/kassane/d-uricrypt?include_prereleases&label=latest)
[![Artifacts](https://github.com/kassane/d-uricrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/kassane/d-uricrypt/actions/workflows/ci.yml)

A D library for encrypting URIs while preserving their hierarchical structure and common prefixes.

## Features

- Prefix-Preserving Encryption: URIs with shared paths maintain identical encrypted prefixes, enabling efficient caching and storage
- Plaintext Scheme: URI schemes (like `https://`) remain unencrypted for protocol identification
- Path-Only Support: Can encrypt paths without schemes (e.g., `/path/to/file`)
- Deterministic Encryption: Same inputs always produce the same encrypted output
- URL-Safe Output: Generates clean URLs without padding characters using base64 URL-safe encoding
- Authenticated Encryption: Each component includes a 16-byte SIV for tamper detection

## Instalation

```bash
dub add uricrypt
```

## Known Implementations

| Name                                                                                                            | Language   |
| --------------------------------------------------------------------------------------------------------------- | ---------- |
| [rust-uricrypt](https://github.com/jedisct1/rust-uricrypt)                                                      | Rust       |
| [uricrypt.js](https://www.npmjs.com/package/uricrypt)                                                             | JavaScript |
| [zig-uricrypt](https://github.com/jedisct1/zig-uricrypt)                                                          | Zig        |

## Acknowledgements

- [jedisct1](https://github.com/jedisct1/) - for the original implementation