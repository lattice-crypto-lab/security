//! Lattice security domain, application use-cases, and transports.
//!
//! `core` is the stable data/rules surface. Runtime modules remain internal so
//! SQLite jobs and Sage process orchestration do not leak into clients.

pub mod api;
mod applicability;
pub mod application;
mod canonical;
pub mod cli;
pub mod core;
mod database;
mod domain;
mod error;
mod formats;
mod scheduler;
pub mod service;
mod upstream;
mod validation;
mod web;

pub use applicability::*;
pub use canonical::{AttackCacheIdentity, EstimatorContext, canonical_json, stable_hash};
pub use domain::*;
pub use error::ServiceError;
pub use formats::*;
pub use upstream::Metadata;
pub use validation::{Validate, ValidationError};

/// Canonicalization rules used for cache and request identities.
pub const CANONICALIZATION_VERSION: u32 = 1;
/// Current parameter-set and security-report major format version.
pub const FILE_FORMAT_VERSION: u32 = 1;
