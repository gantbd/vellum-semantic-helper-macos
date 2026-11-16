# Contributing

Keep macOS provider isolation mechanisms outside Vellum's cross-platform
engine. Adapters may depend only on the sibling helper protocol boundary; they
must not widen authority or imply signing, notarization, activation, or
production confinement that has not been implemented and qualified.

Use the exact sibling Vellum revision recorded in `release/source.json`, then
run:

```sh
make check
```

The workspace is unpublished. Do not add crates.io publication metadata or a
release claim without an explicit release-policy change.
