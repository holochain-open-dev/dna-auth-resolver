/**
 * Library for use in application zomes which need to register themselves with
 * remote zomes for indexing.
 *
 * @package @holochain-open-dev/dna-auth-resolver
 * @since   2021-03-18
 */
use hdk::prelude::*;
use holo_hash::{DnaHash};
use hc_zome_dna_auth_resolver_storage::*;

pub fn get_auth_data(remote_dna: &DnaHash) -> ExternResult<AuthedDnaConnection> {
    let dna_path = get_path_for_dna(remote_dna);

    let result = get(dna_path.hash()?, GetOptions::default())?;

    let entry = try_entry_from_element(result.as_ref())?;
    try_decode_entry(entry.to_owned())
}

/// Helper to handle retrieving linked element entry from an element
///
/// :TODO: import this from a well-vetted shared lib
///
fn try_entry_from_element<'a>(element: Option<&'a Element>) -> ExternResult<&'a Entry> {
    element
        .and_then(|el| el.entry().as_option())
        .ok_or(WasmError::Guest("non-existent element".to_string()))
}

/// Helper for handling decoding of entry data to requested entry struct type
///
/// :TODO: import this from a well-vetted shared lib
/// :TODO: check the performance of this function, into_sb() is copying data
///
fn try_decode_entry<T>(entry: Entry) -> ExternResult<T>
    where SerializedBytes: TryInto<T, Error = SerializedBytesError>,
{
    match entry {
        Entry::App(content) => {
            let decoded: T = content.into_sb().try_into()?;
            Ok(decoded)
        },
        _ => Err(WasmError::Guest("non-app entry".to_string())),
    }
}
