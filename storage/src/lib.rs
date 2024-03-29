/**
 * Structures for representing authenticated associations with foreign DNAs.
 *
 * @package Holo-REA
 */
use hdk::prelude::*;
pub use holo_hash::{DnaHash};
use hc_zome_dna_auth_resolver_core::AvailableCapability;

pub const CAP_STORAGE_ENTRY_DEF_ID: &str = "dna_authed_method_mapping";

// :TODO: remove this, replace with reference to appropriate namespacing of zome config
#[derive(Clone, Serialize, Deserialize, SerializedBytes, PartialEq, Debug)]
pub struct DnaConfigSlice {
    pub remote_auth: AvailableCapabilities,
}

/// Configuration structure for mapped open permissions, specified in DNA properties
///
#[derive(Clone, Serialize, Deserialize, SerializedBytes, PartialEq, Debug)]
pub struct AvailableCapabilities {
    pub permissions: Vec<AvailableCapability>,
}

/// Helper to determine CapClaim tag for given requesting DNA hash & permission ID
///
pub fn get_tag_for_auth<S>(dna: &DnaHash, permission_id: &S) -> String
    where S: AsRef<str>,
{
    let mut s = permission_id.as_ref().to_string();
    s.push(':');
    s.push_str(&String::from_utf8_lossy(dna.as_ref()).to_string());
    s
}

/// Helper to handle retrieving linked element entry from an element
///
/// :TODO: import this from a well-vetted shared lib
///
pub fn try_entry_from_element<'a>(element: Option<&'a Record>) -> ExternResult<&'a Entry> {
    element
        .and_then(|el| el.entry().as_option())
        .ok_or(wasm_error!(WasmErrorInner::Guest("non-existent element".to_string())))
}
