# DNA Auth Resolver

> A simple configuration-based module for inter-network RPC in Holochain hApps.

<!-- MarkdownTOC -->

- [About](#about)
- [Usage](#usage)
	- [In the *origin* zome](#in-the-origin-zome)
	- [In the *destination* DNA](#in-the-destination-dna)
	- [Troubleshooting](#troubleshooting)
- [Building / developing](#building--developing)
- [Built with this module](#built-with-this-module)
- [License](#license)

<!-- /MarkdownTOC -->



## About

*(TLDR; this module replaces what was formerly known as "bridging" in Holochain-Redux.)*

You have a Holochain application composed of multiple coordinated application 'cells'. These cells want to talk to each other but need some way of assigning capabilities to each other in order to do so. This helper module and related zome provides this functionality.

It works by providing a layer for mapping pre-known request identifiers onto the actual zome & method names deployed into a DNA. An open-access endpoint living at the pre-known `remote_auth` zome name in the destination DNA is used to request and assign separate capability tokens which can be retrieved and used at runtime to authenticate method calls between apps.



## Usage

### In the *origin* zome

> (the one where a record has been modified which will trigger an update in some *destination* zome in a remote DNA)

1. Include the `hc_zome_dna_auth_resolver_storage` crate in the zome module to ensure that its capability storage `EntryDef` is available:  
   ```toml
   [dependencies]
   hc_zome_dna_auth_resolver_storage = {git = "https://github.com/holochain-open-dev/dna-auth-resolver", tag = "X.X.X" package = "hc_zome_dna_auth_resolver_storage"}
   ```
   ```rust
   use hc_zome_dna_auth_resolver_storage::*;
   ```
2. Wherever your cross-DNA logic is triggered, import the `_lib` crate and use the helper methods to communicate with the remote zome: 
	```toml
	[dependencies]
	hc_zome_dna_auth_resolver_lib = {git = "https://github.com/holochain-open-dev/dna-auth-resolver", tag = "X.X.X" package = "hc_zome_dna_auth_resolver_lib"}
	```
	```rust
	use hc_zome_dna_auth_resolver_lib::{DNAConnectionAuth, ensure_authed};

	// define external permission ID to map to in destination zome config
	pub const remote_permission_id: &str = "EXTERNAL_PERMISSION_IDENTIFIER";

	// pull destination DNA hash from somewhere
	let to_dna: DnaHash = //...

	// transparently request & retrieve auth data for remote DNA/zome
	let auth_data = ensure_authed(to_dna, remote_permission_id)?;

	// use auth data to make request
	let DNAConnectionAuth { claim, method } = auth_data;
	let resp = hdk::call(
		Some(CellId::new(to_dna, claim.grantor().to_owned())), 
		method.0, method.1, 
		Some(claim.secret().to_owned()), 
		payload,
	);
	```

### In the *destination* DNA

> (the one containing the zome being "driven" by the *origin* DNA/zome)

1. Build and include a compiled-to-WASM version of the `hc_zome_dna_auth_resolver` crate, with the name `remote_auth`. **The zome name is important.**  
	1. One possible way of doing this is to re-export the crate from this module in your own derived crate:  
		```toml
		[package]
		name = "hc_zome_my_app_auth_resolver"
		version = "0.1.0"
		edition = "2018"
		private = true

		[dependencies]
		hc_zome_dna_auth_resolver = {git = "https://github.com/holochain-open-dev/dna-auth-resolver", tag = "X.X.X", package = "hc_zome_dna_auth_resolver"}

		[lib]
		path = "src/lib.rs"
		crate-type = ["cdylib", "rlib"]
		```
		```rust
		extern crate hc_zome_dna_auth_resolver;
		```
	2. Include the built zome artifacts in your DNA bundle, along with the destination zomes.
	   ```yaml
	   zomes:
		 # ...
		 - name: remote_auth
		   bundled: "../../target/wasm32-unknown-unknown/release/hc_zome_my_app_auth_resolver.wasm"
	   ```
2. Add this configuration block to the DNA properties:  
   ```yaml
   properties:
	 # ...
	 remote_auth:
	   permissions:
		 - extern_id: EXTERNAL_PERMISSION_IDENTIFIER
		   allowed_method: [TARGET_ZOME_NAME, TARGET_FUNC_NAME]
   ```


### Troubleshooting

**Errors relating to missing `EntryDef` for `"dna_authed_method_mapping"`:**

This can happen for zomes which define the `entry_defs` extern themselves rather than using convenience macros; in which case any entry types defined with `#[hdk_entry]` are overridden by the returned array.

In such cases, you can add this `EntryDef` to your `EntryDefsCallbackResult`:

```rust
EntryDef {
	id: CAP_STORAGE_ENTRY_DEF_ID.into(),
	visibility: EntryVisibility::Private,
	crdt_type: CrdtType,
	required_validations: 1.into(),
	required_validation_type: RequiredValidationType::default(),
},
```



## Building / developing

Written in [Rust](https://www.rust-lang.org/). Uses regular Cargo manifests & package commands, best included as dependencies in your other packages.

To reference these crates directly from Github, you can use (eg.)

	hc_zome_dna_auth_resolver_lib = {git = "https://github.com/holochain-open-dev/dna-auth-resolver", tag = "X.X.X" package = "hc_zome_dna_auth_resolver_lib"}



## Built with this module

[`hdk_records`](https://github.com/holo-rea/holo-rea/tree/feature/sprout/lib/hdk_records) is a high-level record and index management library for highly modular Holochain apps.



## License

Apache-2.0
