# Profiles

Profiles are TOML files that select modules and set their params. The
built-in `minimal` and `web` are embedded from
`crates/vps-ready/src/config/profiles/`; `--profile <name|path>` selects one,
and a file may `extends` a built-in one.
