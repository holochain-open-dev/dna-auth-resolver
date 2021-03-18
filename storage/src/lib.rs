/**
 * Structures for representing authenticated associations with foreign DNAs.
 *
 * Pretty simple sourcechain layout:
 * The zome uses a `Path` for each `DnaHash` to lookup an associated
 * `AuthedDnaConnection` that stores the credentials used to call into it.
 *
 * @package Holo-REA
 */
use hdk::prelude::*;
pub use holo_hash::{DnaHash};

#[hdk_entry(id="dna_auth")]
#[derive(Clone)]
pub struct AuthedDnaConnection {
    pub agent_pubkey: AgentPubKey,
    pub cap_secret: Option<CapSecret>,
}

pub fn get_path_for_dna(dna: &DnaHash) -> Path {
    Path::from(vec![dna.as_ref().to_vec().into()])
}
