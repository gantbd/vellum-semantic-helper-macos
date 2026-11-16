# Vellum semantic helper for macOS

This unpublished peer owns macOS-only semantic-provider isolation mechanisms.
It is deliberately outside the cross-platform Vellum engine repository.

Implemented adapters:

- descriptor-anchored immutable snapshot materialization;
- a one-attempt signed-service NSXPC client with bounded canonical frames.

The snapshot adapter produces an affine read-only lease for provider input. It
is not a durable store and makes no crash-persistence or recovery claim.

The signed App Sandbox service, provider runner, bundle construction, signing,
notarization and whole-tree resource enforcement are not yet implemented. The
current code therefore cannot qualify a production semantic provider and is
not part of Vellum's daemon/MCP release closure.

No package is authorized for crates.io publication.
