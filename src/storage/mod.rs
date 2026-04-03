//! Storage layer: configuration and data persistence.

pub mod config;
pub mod db;

pub use config::Config;
pub use db::{Message, MessageStore, ReadOnlyMessageStore};
