# Style and Review Scope

Peios Standards and Conventions (PSC), maintained under Panorama's `docs`,
owns the common and language rules. This repository follows its Go, Rust,
Python, shell, C, and Starlark profiles where those languages occur.

Apply the house style to maintained source and tooling. Preserve exact kernel
and PPK writer snapshots under `vendor`; their origin records define their
update process. Generated UAPI declarations are checked by regeneration.
Historical records under `docs/archive` retain their original text.

Function length and nesting are review prompts, not hard limits. Keep protocol
layouts, ownership transitions, and validation visible when splitting functions.
A formatting check does not establish public API safety or runtime correctness.
