//! Versioned public contracts for the lattice-security service.
//!
//! Contract types remain the source of truth for committed JSON schemas. The
//! phase 2 modules provide the public HTTP service, SQLite state, scheduler,
//! and the internal estimator client.

pub mod api;
pub mod canonical;
pub mod database;
pub mod domain;
pub mod error;
pub mod formats;
pub mod scheduler;
pub mod service;
pub mod sweep;
pub mod ui;
pub mod upstream;
pub mod validation;

pub use canonical::{AttackCacheIdentity, EstimatorContext, canonical_json, stable_hash};
pub use domain::*;
pub use formats::*;
pub use validation::{Validate, ValidationError};

/// Canonicalization rules used for cache and request identities.
pub const CANONICALIZATION_VERSION: u32 = 1;
/// Current parameter-set and security-report major format version.
pub const FILE_FORMAT_VERSION: u32 = 1;
