/**
 * DNA Auth Resolver core library
 *
 * These shouldn't be touched, as much as possible, as they are so used in the integrity zomes.
 * They are separate from the integrity zome so they can be safely imported into coordinator zomes
 * without triggering conflicting holochain callbacks to be defined
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
