/**
 * DNA Auth Resolver zome
 *
 * Provides an API for foreign DNAs to register themselves with (this) local DNA.
 *
 * @see hc_zome_dna_auth_resolver_lib
 *
 * @package @holochain-open-dev/dna-auth-resolver
 * @since   2021-03-18
 */
use hdk::prelude::*;

use hc_zome_dna_auth_resolver_rpc::*;
use hc_zome_dna_auth_resolver_storage::*;

/**
 * Accept a request from some remote DNA to register an authenticated connection with the local DNA.
 *
 * Reads the zome properties to determine the (statically known) list of available external "permissions"
 * for this DNA, and the internal zome & method names to which they correspond. These are passed into a
 * newly created capability grant in the local DNA and stored to allow the authentication.
 */
#[hdk_extern]
fn register_dna(DnaRegistration { remote_dna, permission_id, secret }: DnaRegistration) -> ExternResult<ZomeCallCapGrant> {
    let tag = get_tag_for_auth(&remote_dna, &permission_id);

    // lookup assigned capability ID
    let cap_fn_mapping: DnaConfigSlice = dna_info()?.properties.try_into()?;
    let cap_fn = cap_fn_mapping.remote_auth.permissions.iter().find(|cap| { cap.extern_id == permission_id });

    if None == cap_fn { return Err(WasmError::CallError(format!("no permission with ID {:?}", permission_id))); }

    // create capability grant for the remote requestor, based on the `secret` they provided and the currently executing (local) agent
    let mut assignees = BTreeSet::new();
    assignees.insert(agent_info()?.agent_latest_pubkey);

    let mut allowed_methods = BTreeSet::new();
    allowed_methods.insert(cap_fn.unwrap().allowed_method.to_owned());

    let cap_header = create_cap_grant(CapGrantEntry::new(
        tag,
        CapAccess::Assigned { secret, assignees },
        allowed_methods,
    ))?;

    // read capability grant back out to return it to the caller
    let result = get(cap_header, GetOptions { strategy: GetStrategy::Latest })?;
    let entry = try_entry_from_element(result.as_ref())?;

    match entry.as_cap_grant() {
        Some(CapGrant::RemoteAgent(grant)) => Ok(grant),
        Some(_) => Err(WasmError::Guest("Wrong capability type assigned in create_cap_grant()! This should never happen.".to_string())),
        None => Err(WasmError::Guest("Consistency error storing capability grant! This should never happen.".to_string())),
    }
}
