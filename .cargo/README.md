# chksum-hash-sha2-384

[![GitHub](https://img.shields.io/badge/github-chksum--rs%2Fhash--sha2--384-24292e?style=flat-square&logo=github "GitHub")](https://github.com/chksum-rs/hash-sha2-384)
[![Build](https://img.shields.io/github/actions/workflow/status/chksum-rs/hash-sha2-384/rust.yml?branch=master&style=flat-square&logo=github "Build")](https://github.com/chksum-rs/hash-sha2-384/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/chksum-hash-sha2-384?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-hash-sha2-384/)
[![MSRV](https://img.shields.io/badge/MSRV-1.63.0-informational?style=flat-square "MSRV")](https://github.com/chksum-rs/hash-sha2-384/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-hash-sha2-384/0.0.0/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-hash-sha2-384/0.0.0)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/chksum-rs/hash-sha2-384?style=flat-square "LICENSE")](https://github.com/chksum-rs/hash-sha2-384/blob/master/LICENSE)

An implementation of SHA-2 384 hash algorithm for batch and stream computation.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-hash-sha2-384 = "0.0.0"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-hash-sha2-384
```

## Usage

Use the `hash` function for batch digest calculation.

```rust
use chksum_hash_sha2_384 as sha2_384;

let digest = sha2_384::hash(b"example data");
assert_eq!(
    digest.to_hex_lowercase(),
    "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
);
```

Use the `default` function to create a hash instance for stream digest calculation.

```rust
use chksum_hash_sha2_384 as sha2_384;

let digest = sha2_384::default()
    .update("example")
    .update(b"data")
    .update([0, 1, 2, 3])
    .digest();
assert_eq!(
    digest.to_hex_lowercase(),
    "ef0484e7424aa96c8f3d4910ac081d129b089435e4275b0cec9327a09959359e18c3ca55355fbc32968d20c85c379d86"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-hash-sha2-384/).

## License

This crate is licensed under the MIT License.
