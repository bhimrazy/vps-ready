//! Profiles: TOML files that select the modules to run and set their
//! params. `minimal`, `web` and `private` are embedded; a user file may
//! extend one.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::modules::{Module, ModuleError};

/// The built-in profiles by name. They list only registered modules: each
/// module's PR adds its section.
const BUILT_IN: [(&str, &str); 3] = [
    ("minimal", include_str!("profiles/minimal.toml")),
    ("web", include_str!("profiles/web.toml")),
    ("private", include_str!("profiles/private.toml")),
];

/// The VPN modules, each with the interface it brings up, which
/// firewall.inbound's `ssh_via = "vpn"` resolves to.
pub(crate) const VPNS: [(&str, &str); 2] =
    [("net.tailscale", "tailscale0"), ("net.wireguard", "wg0")];

/// `ssh_via = "vpn"`: the interface of the profile's one VPN module.
const VPN: &str = "vpn";

/// What [`Profile::resolve`] turns `ssh_via = "vpn"` into, before the
/// interface: firewall.inbound then keeps SSH public until a session comes
/// through that interface (step 1 of 2 of the private profile).
pub(crate) const STAGED_VIA: &str = "vpn:";

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
    #[error("cannot extend `{0}`; the built-in profiles are minimal, web and private")]
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
    /// firewall.inbound's `ssh_via = "vpn"` without exactly one VPN module.
    #[error("{0}")]
    Vpn(String),
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
            if id == "firewall.inbound" {
                reserved_via(&table)?;
            }
            if enabled {
                modules.insert(id, table);
            }
        }
        resolve_vpn(&mut modules, registry)?;
        Ok(Self { modules })
    }

    /// The params of module `id`, or `None` if the profile does not enable it.
    #[must_use]
    pub fn params(&self, id: &str) -> Option<&toml::Table> {
        self.modules.get(id)
    }
}

/// Refuses a written `ssh_via` in [`STAGED_VIA`]'s form, which only
/// [`resolve_vpn`] may produce.
fn reserved_via(firewall: &toml::Table) -> Result<(), ProfileError> {
    let via = firewall.get("ssh_via").and_then(toml::Value::as_str);
    match via {
        Some(v) if v.starts_with(STAGED_VIA) => Err(ProfileError::Params {
            module: "firewall.inbound".to_owned(),
            source: ModuleError::Refused(format!(
                "`ssh_via = {v:?}`: `{STAGED_VIA}` is reserved; write `ssh_via = \"{VPN}\"` for \
                 the profile's VPN, or the interface's name"
            )),
        }),
        _ => Ok(()),
    }
}

/// Turns firewall.inbound's `ssh_via = "vpn"` into [`STAGED_VIA`] and the
/// interface of the one enabled VPN module in `modules`.
fn resolve_vpn(
    modules: &mut BTreeMap<String, toml::Table>,
    registry: &[&dyn Module],
) -> Result<(), ProfileError> {
    let via = modules
        .get("firewall.inbound")
        .and_then(|t| t.get("ssh_via"))
        .and_then(toml::Value::as_str);
    if via != Some(VPN) {
        return Ok(());
    }
    let vpns: Vec<_> = VPNS
        .iter()
        .filter(|(id, _)| modules.contains_key(*id))
        .collect();
    let interface = match vpns[..] {
        [(_, interface)] => interface,
        [] => {
            let add: Vec<_> = VPNS
                .iter()
                .filter(|(id, _)| registry.iter().any(|m| m.id() == *id))
                .map(|(id, _)| format!("`[modules.\"{id}\"]`"))
                .collect();
            return Err(ProfileError::Vpn(format!(
                "`ssh_via = \"vpn\"` (the private profile) needs a VPN module: add {}",
                add.join(" or ")
            )));
        }
        _ => {
            let ids: Vec<_> = vpns.iter().map(|(id, _)| *id).collect();
            return Err(ProfileError::Vpn(format!(
                "`ssh_via = \"vpn\"` (the private profile) takes one VPN module, and this \
                 enables {}: leave one out with `enabled = false`",
                ids.join(" and ")
            )));
        }
    };
    if let Some(firewall) = modules.get_mut("firewall.inbound") {
        firewall.insert(
            "ssh_via".to_owned(),
            toml::Value::String(format!("{STAGED_VIA}{interface}")),
        );
    }
    Ok(())
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

    /// The name of the built-in profile it starts from.
    #[must_use]
    pub fn base(&self) -> &'static str {
        self.base
    }

    /// Whether it still gives the base, so [`Self::to_toml`] would hold
    /// only `schema` and `extends`.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.modules == self.base_modules
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
