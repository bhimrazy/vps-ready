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
        let mut merged = match &raw.extends {
            Some(name) => base_modules(name, built_in)?.1,
            None => BTreeMap::new(),
        };
        // One level deep: a key of the module's table replaces the base's.
        for (id, table) in raw.modules {
            merged
                .entry(id)
                .or_insert_with(toml::Table::new)
                .extend(table);
        }
        Self::resolve(merged, registry)
    }

    /// Checks the merged sections against `registry` and keeps the enabled
    /// ones.
    fn resolve(
        merged: BTreeMap<String, toml::Table>,
        registry: &[&dyn Module],
    ) -> Result<Self, ProfileError> {
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

/// The name and sections of the built-in profile `name` in `built_in`.
fn base_modules<'a>(
    name: &str,
    built_in: &[(&'a str, &str)],
) -> Result<(&'a str, BTreeMap<String, toml::Table>), ProfileError> {
    let (name, text) = built_in
        .iter()
        .find(|(n, _)| *n == name)
        .ok_or_else(|| ProfileError::UnknownBase(name.to_owned()))?;
    let raw: Raw = toml::from_str(text).map_err(|e| ProfileError::Parse(Box::new(e)))?;
    Ok((name, raw.modules))
}

/// A built-in profile with changes: builds the [`Profile`] and writes the
/// profile file that gives the same one.
#[derive(Debug, Clone)]
pub struct ProfileBuilder {
    base: &'static str,
    /// The base's sections.
    base_modules: BTreeMap<String, toml::Table>,
    /// The sections with the changes, merged as `extends` merges them.
    modules: BTreeMap<String, toml::Table>,
}

impl ProfileBuilder {
    /// Starts from the built-in profile `base`.
    ///
    /// # Errors
    ///
    /// [`ProfileError::UnknownBase`] if there is no built-in `base`.
    pub fn new(base: &str) -> Result<Self, ProfileError> {
        let (base, base_modules) = base_modules(base, &BUILT_IN)?;
        Ok(Self {
            base,
            modules: base_modules.clone(),
            base_modules,
        })
    }

    /// Sets keys of module `id`'s params, one level deep as `extends` does,
    /// and enables it if the base lacks it or it was taken out.
    pub fn set_params(&mut self, id: &str, params: toml::Table) -> &mut Self {
        let table = self.modules.entry(id.to_owned()).or_default();
        // Only `remove` sets `enabled`: no built-in does, so `to_toml` never
        // needs to write `enabled = true`.
        table.remove("enabled");
        table.extend(params);
        self
    }

    /// Takes module `id` out, dropping params set for it.
    pub fn remove(&mut self, id: &str) -> &mut Self {
        match self.base_modules.get(id) {
            Some(base) => {
                let mut table = base.clone();
                table.insert("enabled".to_owned(), toml::Value::Boolean(false));
                self.modules.insert(id.to_owned(), table);
            }
            None => {
                self.modules.remove(id);
            }
        }
        self
    }

    /// The profile, as [`Profile::parse`] gives it for [`Self::to_toml`].
    ///
    /// # Errors
    ///
    /// [`ProfileError`] if a module or its params are invalid for `registry`.
    pub fn build(&self, registry: &[&dyn Module]) -> Result<Profile, ProfileError> {
        Profile::resolve(self.modules.clone(), registry)
    }

    /// The profile file: `schema`, `extends` and the keys that differ from
    /// the base, with `enabled = false` for a module taken out.
    #[must_use]
    pub fn to_toml(&self) -> String {
        let mut modules = toml::Table::new();
        for (id, table) in &self.modules {
            let base = self.base_modules.get(id);
            if base == Some(table) {
                continue;
            }
            let changed: toml::Table = table
                .iter()
                .filter(|&(k, v)| base.and_then(|b| b.get(k)) != Some(v))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            modules.insert(id.clone(), toml::Value::Table(changed));
        }
        let mut text = format!(
            "schema = {SCHEMA}\nextends = {}\n",
            toml::Value::String(self.base.to_owned())
        );
        if !modules.is_empty() {
            let mut doc = toml::Table::new();
            doc.insert("modules".to_owned(), toml::Value::Table(modules));
            text.push('\n');
            text.push_str(&doc.to_string());
        }
        text
    }
}

#[cfg(test)]
mod tests;
