use holo_hash::{DnaHash};
use holochain_zome_types::capability::CapSecret;
use holochain_serialized_bytes::prelude::*;

/// Payload to send to remote DNAs that the local DNA wants to authenticate with.
/// Made unauthenticated, to allow subsequent requests to be authed against a CapClaim.
///
#[derive(Debug, Serialize, Deserialize, SerializedBytes)]
pub struct DnaRegistration {
    pub remote_dna: DnaHash,
    pub permission_id: String,
    pub secret: CapSecret,
}
