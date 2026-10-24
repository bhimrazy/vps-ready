//! Profiles: TOML files that select the modules to run and set their
//! params. `minimal` and `web` are embedded; a user file may extend one.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::modules::{Module, ModuleError};

/// The built-in profiles by name. They list only registered modules: each
/// module's PR adds its section.
const BUILT_IN: [(&str, &str); 2] = [
    ("minimal", include_str!("profiles/minimal.toml")),
    ("web", include_str!("profiles/web.toml")),
];

/// The only `schema` value.
const SCHEMA: u32 = 1;

/// Why a profile did not load.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// The text is not a profile, e.g. an unknown key. Boxed: the parse
    /// error is large.
    #[error("invalid profile: {0}")]
    Parse(#[source] Box<toml::de::Error>),
    /// `schema` is not 1.
    #[error("unsupported schema {0}; this version reads schema 1")]
    Schema(u32),
    /// `extends` names no built-in profile.
    #[error("cannot extend `{0}`; the built-in profiles are minimal and web")]
    UnknownBase(String),
    /// A section names no registered module.
    #[error("unknown module `{module}`; modules are {known}")]
    UnknownModule {
        /// As written.
        module: String,
        /// The registry, comma separated.
        known: String,
    },
    /// `enabled` is not a boolean.
    #[error("module `{0}`: `enabled` must be true or false")]
    Enabled(String),
    /// A section's params are invalid for its module.
    #[error("module `{module}`: {source}")]
    Params {
        /// The module.
        module: String,
        /// What is wrong.
        source: ModuleError,
    },
}

/// A profile file as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    schema: u32,
    extends: Option<String>,
    #[serde(default)]
    modules: BTreeMap<String, toml::Table>,
}

/// The modules a profile enables, with their params.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    modules: BTreeMap<String, toml::Table>,
}

impl Profile {
    /// The built-in profile `name`, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// [`ProfileError`] if it is invalid for `registry`; a test checks that
    /// none is.
    pub fn built_in(name: &str, registry: &[&dyn Module]) -> Result<Option<Self>, ProfileError> {
        let Some((_, text)) = BUILT_IN.iter().find(|(n, _)| *n == name) else {
            return Ok(None);
        };
        Self::parse(text, registry).map(Some)
    }

    /// Parses `text`, a profile that may `extends` a built-in one, and
    /// checks the params of every section against `registry`, also those of
    /// a module that is disabled or does not apply on this host.
    ///
    /// # Errors
    ///
    /// [`ProfileError`].
    pub fn parse(text: &str, registry: &[&dyn Module]) -> Result<Self, ProfileError> {
        Self::parse_with(text, registry, &BUILT_IN)
    }

    fn parse_with(
        text: &str,
        registry: &[&dyn Module],
        built_in: &[(&str, &str)],
    ) -> Result<Self, ProfileError> {
        let raw: Raw = toml::from_str(text).map_err(|e| ProfileError::Parse(Box::new(e)))?;
        if raw.schema != SCHEMA {
            return Err(ProfileError::Schema(raw.schema));
        }
        let mut merged = BTreeMap::new();
        if let Some(name) = &raw.extends {
            let (_, base) = built_in
                .iter()
                .find(|(n, _)| n == name)
                .ok_or_else(|| ProfileError::UnknownBase(name.clone()))?;
            let base: Raw = toml::from_str(base).map_err(|e| ProfileError::Parse(Box::new(e)))?;
            merged = base.modules;
        }
        // One level deep: a key of the module's table replaces the base's.
        for (id, table) in raw.modules {
            merged
                .entry(id)
                .or_insert_with(toml::Table::new)
                .extend(table);
        }

        let mut modules = BTreeMap::new();
        for (id, mut table) in merged {
            let Some(module) = registry.iter().find(|m| m.id() == id) else {
                let known: Vec<_> = registry.iter().map(|m| m.id()).collect();
                return Err(ProfileError::UnknownModule {
                    module: id,
                    known: known.join(", "),
                });
            };
            let enabled = match table.remove("enabled") {
                None => true,
                Some(toml::Value::Boolean(b)) => b,
                Some(_) => return Err(ProfileError::Enabled(id)),
            };
            module
                .check_params(&table)
                .map_err(|source| ProfileError::Params {
                    module: id.clone(),
                    source,
                })?;
            if enabled {
                modules.insert(id, table);
            }
        }
        Ok(Self { modules })
    }

    /// The params of module `id`, or `None` if the profile does not enable it.
    #[must_use]
    pub fn params(&self, id: &str) -> Option<&toml::Table> {
        self.modules.get(id)
    }
}

#[cfg(test)]
mod tests;
