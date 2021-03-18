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

use hc_zome_dna_auth_resolver_storage::*;

#[derive(Debug, Serialize, Deserialize)]
struct DnaRegistration {
    remote_dna: DnaHash,
    auth: AuthedDnaConnection,
}

#[hdk_extern]
fn register_dna(DnaRegistration { remote_dna, auth }: DnaRegistration) -> ExternResult<bool> {
    // init all elements
    let _header_hash = create_entry(auth.clone())?;
    let entry_hash = hash_entry(auth)?;
    let dna_path = get_path_for_dna(&remote_dna);
    dna_path.ensure()?;
    let dna_hash = dna_path.hash()?;
    let link_tag = LinkTag::from(());

    // delete any existing links to ensure only 1 set of credentials is saved (this means this method can be used to update)
    let existing_links = pull_links_data(&dna_hash, &link_tag, get_link_target_header)?;
    let _deleted: Vec<ExternResult<HeaderHash>> = existing_links.iter()
        .cloned()
        .map(delete_link)
        .collect();

    // create link for lookup
    create_link(dna_hash, entry_hash, link_tag)?;
    Ok(true)
}

fn pull_links_data<T, F>(
    base_address: &EntryHash,
    link_tag: &LinkTag,
    link_map: F,
) -> ExternResult<Vec<T>>
    where F: Fn(&Link) -> T,
{
    let links_result = get_links((*base_address).clone(), Some(link_tag.clone()))?;

    Ok(links_result
        .into_inner()
        .iter()
        .map(link_map)
        .collect()
    )
}

fn get_link_target_header(l: &Link) -> HeaderHash {
    l.create_link_hash.clone()
}
