//! FCEP-2 MLS group encryption core for FiSH-11
//!
//! This crate implements the cryptographic core of FCEP-2, delegating all
//! group cryptographic operations to OpenMLS (RFC 9420). It does not contain
//! any IRC transport, mIRC DLL hooks, or Win32 code.

pub mod envelope;
pub mod error;
pub mod fragment;
pub mod group;
pub mod identity;
pub mod keypackage;
pub mod persistence;
pub mod provider;
pub mod storage;
