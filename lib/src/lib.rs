/**
 * Library for use in application zomes which need to register themselves with
 * remote zomes for indexing.
 *
 * @package @holochain-open-dev/dna-auth-resolver
 * @since   2021-03-18
 */
use hdk::prelude::*;
use holo_hash::{ActionHash, DnaHash};

pub use hc_zome_dna_auth_resolver_core::*;
pub use hc_zome_dna_auth_resolver_rpc::*;
pub use hc_zome_dna_auth_resolver_storage::*;

#[hdk_dependent_entry_types]
enum EntryZomes {
    IntegrityEntry(EntryTypes),
}
#[hdk_dependent_link_types]
enum LinkZomes {
    IntegrityLink(LinkTypes),
}

// :TODO: make this dynamic so that DNA configurations don't have reserved zome names anymore
pub const AUTH_ZOME_NAME: &str = "remote_auth";
pub const AUTH_ZOME_METHOD: &str = "register_dna";

/// Authentication data held by the local (calling) DNA about a connection to some remote (receiving) DNA,
/// enabling it to lookup all necessary parameters to `call` to the correct remote zome.
///
#[derive(Debug)]
pub struct DNAConnectionAuth {
    pub method: GrantedFunction,
    pub claim: CapClaim,
}

/// fetches auth for some remote DNA if we are already authed, attempts one otherwise
///
pub fn ensure_authed<S>(
    to_dna: &DnaHash,
    remote_permission_id: &S,
) -> ExternResult<DNAConnectionAuth>
where
    S: AsRef<str>,
{
    let mut cell_auth = get_auth_data(to_dna, remote_permission_id);
    match &cell_auth {
        Ok(_) => {}
        // transparently request indicated permission if not granted
        Err(_) => {
            let _ = make_auth_request(to_dna, remote_permission_id)?;

            // re-check for permissions after request, bail if failed
            cell_auth = get_auth_data(to_dna, remote_permission_id);
            match cell_auth {
                Ok(_) => {}
                Err(e) => {
                    return Err(wasm_error!(WasmErrorInner::Guest(format!(
                        "Error in auth handshake from DNA {:?} to DNA {:?}: {:?}",
                        dna_info()?.hash,
                        to_dna.to_owned(),
                        e.to_string()
                    ))));
                }
            }
        }
    }

    let auth_data = cell_auth.unwrap();

    Ok(auth_data)
}

/// trigger an initial authentication request to some remote DNA that is hosting the dna-auth-resolver zome API
///
pub fn make_auth_request<S>(to_dna: &DnaHash, remote_permission_id: &S) -> ExternResult<()>
where
    S: AsRef<str>,
{
    let permission_id = remote_permission_id.as_ref().to_string();
    let secret = generate_cap_secret()?;
    let local_agent_key = agent_info()?.agent_latest_pubkey;
    let to_cell = CellId::new(to_dna.clone(), local_agent_key.clone());

    // make request to the auth zome to ask for remote capability to be granted
    let resp = call(
        CallTargetCell::OtherCell(to_cell),
        ZomeName::from(AUTH_ZOME_NAME),
        FunctionName::from(AUTH_ZOME_METHOD),
        None,
        DnaRegistration {
            remote_dna: dna_info()?.hash,
            permission_id: permission_id.clone(),
            secret,
        },
    )?;

    let mut grant_data: Option<ZomeCallCapGrant> = None;
    let mut local_cap_action: Option<ActionHash> = None;

    // handle response from auth zome and store provided capability access tokens
    (match resp {
        ZomeCallResponse::Ok(data) => {
            let remote_grant: ZomeCallCapGrant = data
                .decode()
                .map_err(|e| wasm_error!(WasmErrorInner::Serialize(e)))?;
            grant_data = Some(remote_grant.to_owned());
            let remote_cap = remote_grant.access;

            match remote_cap {
                CapAccess::Assigned { secret, assignees } => {
                    local_cap_action = Some(create_cap_claim(CapClaim::new(
                        get_tag_for_auth(to_dna, &permission_id),
                        assignees.iter().cloned().next().unwrap(), // take grantor as the author of the remote CapGrantEntry
                        secret,
                    ))?);
                }
                CapAccess::Transferable { secret } => {
                    local_cap_action = Some(create_cap_claim(CapClaim::new(
                        get_tag_for_auth(to_dna, &permission_id),
                        local_agent_key, // :TODO: ensure this is correct metadata for Transferable grants
                        secret,
                    ))?);
                }
                CapAccess::Unrestricted => {} // :TODO: figure out if anything needs storing for these
            }

            Ok(())
        }
        ZomeCallResponse::Unauthorized(cell, zome, fname, agent) => {
            Err(wasm_error!(WasmErrorInner::Guest(format!(
                "Auth request unauthorized: {:?} {:?} {:?} for agent {:?}",
                cell, zome, fname, agent
            ))))
        }
        ZomeCallResponse::NetworkError(msg) => Err(wasm_error!(WasmErrorInner::Guest(format!(
            "Network error in auth request: {:?}",
            msg
        )))),
        ZomeCallResponse::CountersigningSession(msg) => Err(wasm_error!(WasmErrorInner::Guest(
            format!("Countersigning session failed: {:?}", msg)
        ))),
    })?;

    if None == local_cap_action {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Internal error updating local CapClaim register".into()
        )));
    }

    // retrieve EntryHash for CapClaim just stored
    let result = get(
        local_cap_action.unwrap(),
        GetOptions {
            strategy: GetStrategy::Latest,
        },
    )?;
    let cap_claim_hash = get_entry_hash_for_element(result.as_ref())?;

    // store & link to allowed method list for calling back based on permission
    let method = grant_data.unwrap().functions.iter().cloned().next();

    if None == method {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Remote auth registration endpoint authorized no methods".into()
        )));
    }

    let entry = EntryZomes::IntegrityEntry(EntryTypes::AvailableCapability(AvailableCapability {
        extern_id: permission_id.clone(),
        allowed_method: method.unwrap().clone(),
    }));
    let method_action = create_entry(entry)?;

    let method_element = get(
        method_action,
        GetOptions {
            strategy: GetStrategy::Latest,
        },
    )?;
    create_link(
        cap_claim_hash,
        get_entry_hash_for_element(method_element.as_ref())?,
        LinkTypes::AvailableCapability,
        LinkTag::from(()),
    )?;

    Ok(())
}

/// Read capability claim obtained from a previous `make_auth_request()`, in order to make an authenticated cross-DNA call.
///
pub fn get_auth_data<S>(
    to_registered_dna: &DnaHash,
    remote_permission_id: &S,
) -> ExternResult<DNAConnectionAuth>
where
    S: AsRef<str>,
{
    let tag = get_tag_for_auth(to_registered_dna, remote_permission_id);
    let no_auth_err = Err(wasm_error!(WasmErrorInner::Guest(format!(
        "No auth data for {:?} in DNA {:?}",
        remote_permission_id.as_ref(),
        to_registered_dna.as_ref()
    ))));

    // lookup the matching CapClaim by filtering against authed DNA+permission tag
    let claims = query(
        ChainQueryFilter::new()
            .entry_type(EntryType::CapClaim)
            .include_entries(true),
    )?;
    let claim = claims
        .iter()
        .map(|c| {
            let h = get_entry_hash_for_element(Some(c));
            let r = try_entry_from_element(Some(c));
            match r {
                Err(_) => None,
                Ok(e) => Some((h, e.as_cap_claim())),
            }
        })
        .filter(|c| {
            if !c.is_some() {
                return false;
            }
            let r = c.as_ref().unwrap();
            r.1.is_some() && r.1.unwrap().tag() == tag
        })
        .next();

    match claim {
        // using CapClaim data, locate authenticated method data
        Some(Some((Ok(claim_hash), Some(claim)))) => {
            let links_result = get_links(
                claim_hash,
                LinkTypes::AvailableCapability,
                Some(LinkTag::from(())),
            )?;
            let method_entry_hash = links_result.iter().map(|l| l.target.clone()).next();

            if None == method_entry_hash {
                return no_auth_err;
            }

            let method_element = get(
                method_entry_hash.unwrap(),
                GetOptions {
                    strategy: GetStrategy::Latest,
                },
            )?;
            let method_entry = try_entry_from_element(method_element.as_ref())?;
            let method: AvailableCapability = try_decode_app_entry(method_entry.to_owned())?;

            // return CapClaim and GrantedFunction to the caller so they can `call()` the appropriate endpoint
            Ok(DNAConnectionAuth {
                claim: claim.to_owned(),
                method: method.allowed_method,
            })
        }
        _ => no_auth_err,
    }
}

// helper to read related EntryHash for a Create or Update action Element
fn get_entry_hash_for_element(element: Option<&Record>) -> ExternResult<EntryHash> {
    element
        .and_then(|el| match el.action() {
            Action::Create(Create { entry_hash, .. }) => Some(entry_hash.to_owned()),
            Action::Update(Update { entry_hash, .. }) => Some(entry_hash.to_owned()),
            _ => None,
        })
        .ok_or(wasm_error!(WasmErrorInner::Guest(
            "non-existent element".to_string()
        )))
}

/// Helper for handling decoding of entry data to requested entry struct type
///
/// :TODO: check the performance of this function, into_sb() is copying data
/// :TODO: import this from a well-vetted shared lib
///
fn try_decode_app_entry<T>(entry: Entry) -> ExternResult<T>
where
    SerializedBytes: TryInto<T, Error = SerializedBytesError>,
{
    match entry {
        Entry::App(content) => {
            let decoded: T = content
                .into_sb()
                .try_into()
                .map_err(|e| wasm_error!(WasmErrorInner::Serialize(e)))?;
            Ok(decoded)
        }
        _ => Err(wasm_error!(WasmErrorInner::Guest(
            "wrong entry datatype".into()
        ))),
    }
}
