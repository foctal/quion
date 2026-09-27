# Contributing

Bug reports should include the quion revision, Rust version, operating system,
enabled features, and a small reproducer when possible. For interoperability
issues, include the peer implementation and version. Remove private keys, TLS
secrets, credentials, and application data from logs before sharing them.

## Development

Use Rust 1.88 or later. Before submitting a change, run:

```sh
cargo fmt --check --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

For changes that affect compiler compatibility, also run:

```sh
cargo +1.88.0 check --workspace --all-targets --all-features
```

[Testing](docs/testing.md) describes feature checks, fuzzing, and soak tests.
[Interoperability](docs/interop.md) and [benchmarking](docs/performance.md)
cover tests that need additional tools or longer runs.

## Submitting changes

Describe the behavior being changed and how you tested it. Add a regression
test for bug fixes, and update documentation when changing public behavior.
For protocol changes, include the relevant specification section and any
known interoperability limits.

Keep documentation, comments, public APIs, and commit messages in English.
The API is still experimental; discuss substantial API changes before starting
implementation.
