/**
 * DNA Auth Resolver data integrity zome
 *
 * Defines the data validations for any holochain entry types
 *
 * @package @holochain-open-dev/dna-auth-resolver
 * @since   2022-07-21
 */
use hdi::prelude::*;

/// Mapping of externally-facing permission IDs to zome/method call parameters.
///
/// Used in DNA properties of receiving DNA, stored as an Entry for lookup in
/// the requesting DNA.
///
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
pub struct AvailableCapability {
    pub extern_id: String,
    pub allowed_method: GrantedFunction,
}

#[hdk_entry_defs]
#[unit_enum(EntryTypesUnit)]
pub enum EntryTypes {
    #[entry_def(required_validations = 5, visibility = "private")]
    AvailableCapability(AvailableCapability),
}

#[hdk_link_types]
pub enum LinkTypes {
    AvailableCapability,
}
