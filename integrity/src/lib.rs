/**
 * DNA Auth Resolver data integrity zome
 *
 * Defines the data validations for any holochain entry types
 *
 * @package @holochain-open-dev/dna-auth-resolver
 * @since   2022-07-21
 */
use hc_zome_dna_auth_resolver_core::{EntryTypes, EntryTypesUnit, LinkTypes};
use hdi::prelude::*;

#[hdk_extern]
pub fn entry_defs(_: ()) -> ExternResult<EntryDefsCallbackResult> {
    let defs: Vec<EntryDef> = EntryTypes::ENTRY_DEFS
        .iter()
        .map(|a| EntryDef::from(a.clone()))
        .collect();
    Ok(EntryDefsCallbackResult::from(defs))
}

#[no_mangle]
pub fn __num_entry_types() -> u8 {
    EntryTypesUnit::len()
}

// TODO: this is temporary until importing multiple link types is resolved

// Add the extern function that says how many links this zome has.
#[no_mangle]
pub fn __num_link_types() -> u8 {
    LinkTypes::len()
}
