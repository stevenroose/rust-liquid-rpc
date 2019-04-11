// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Rust Client for Bitcoin Core API
//!
//! This is a client library for the Bitcoin Core JSON-RPC API.
//!

#![crate_name = "liquid_rpc_json"]
#![crate_type = "rlib"]

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate bitcoincore_rpc;
extern crate elements;
extern crate hex;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;

pub mod amount;
pub use amount::Amount;

use std::collections::HashMap;
use std::result;

use bitcoin::consensus::encode;
use bitcoin::{PublicKey, Script};
use bitcoin_hashes::hex::FromHex;
use bitcoin_hashes::{sha256, sha256d};
use bitcoincore_rpc::json::serde_hex;
use bitcoincore_rpc::Result;
use serde::de::Error;
use serde::{Deserialize, Serialize};

/// The hexadecimal representation of the Bitcoin pegged asset.
pub const BITCOIN_ASSET_HEX: &'static str =
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

/// The [AssetId] of the Bitcoin pegged asset.
pub fn bitcoin_asset() -> AssetId {
    AssetId::from_hex(BITCOIN_ASSET_HEX).unwrap()
}

/// deserialize_hex_array_opt deserializes a vector of hex-encoded byte arrays.
fn deserialize_hex_array_opt<'de, D>(
    deserializer: D,
) -> result::Result<Option<Vec<Vec<u8>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    //TODO(stevenroose) Revisit when issue is fixed:
    // https://github.com/serde-rs/serde/issues/723

    let v: Vec<String> = Vec::deserialize(deserializer)?;
    let mut res = Vec::new();
    for h in v.into_iter() {
        res.push(hex::decode(h).map_err(D::Error::custom)?);
    }
    Ok(Some(res))
}

// TODO(stevenroose) asset IDs are actually midstates..
/// Shorthand for an asset ID.
pub type AssetId = sha256::Hash;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResult {
    pub hash: sha256d::Hash,
    pub confirmations: usize,
    pub height: usize,
    pub version: u32,
    #[serde(default, with = "serde_hex::opt")]
    pub version_hex: Option<Vec<u8>>,
    pub merkleroot: sha256d::Hash,
    pub time: usize,
    pub mediantime: Option<usize>,
    pub n_tx: usize,
    pub previousblockhash: Option<sha256d::Hash>,
    pub nextblockhash: Option<sha256d::Hash>,
    #[serde(rename = "signblock_witness_asm")]
    pub signblock_witness_asm: Option<String>,
    #[serde(rename = "signblock_withess_hex", default, with = "serde_hex::opt")]
    pub signblock_withess_hex: Option<Vec<u8>>,
}

/// Models the result of "getblockchaininfo"
#[derive(Clone, Debug, Deserialize)]
pub struct GetBlockchainInfoResult {
    /// Current network name as defined in BIP70 (main, test, regtest)
    pub chain: String,
    /// The current number of blocks processed in the server
    pub blocks: u64,
    /// The current number of headers we have validated
    pub headers: u64,
    /// The hash of the currently best block
    pub bestblockhash: sha256d::Hash,
    /// Median time for the current best block
    pub mediantime: u64,
    /// Estimate of verification progress [0..1]
    pub verificationprogress: f64,
    /// Estimate of whether this node is in Initial Block Download mode
    pub initialblockdownload: bool,
    /// The estimated size of the block and undo files on disk
    pub size_on_disk: u64,
    /// If the blocks are subject to pruning
    pub pruned: bool,
    /// Lowest-height complete block stored (only present if pruning is enabled)
    pub pruneheight: Option<u64>,
    /// Whether automatic pruning is enabled (only present if pruning is enabled)
    pub automatic_pruning: Option<bool>,
    /// The target size used by pruning (only present if automatic pruning is enabled)
    pub prune_target_size: Option<u64>,
    /// Status of softforks in progress
    pub softforks: Vec<bitcoincore_rpc::json::Softfork>,
    /// Status of BIP9 softforks in progress
    pub bip9_softforks: serde_json::Value,
    /// Any network and blockchain warnings.
    pub warnings: String,
    /// The block signing challenge in asm format.
    pub signblock_asm: Option<String>,
    /// The block signing challenge in hex format.
    #[serde(default, with = "serde_hex::opt")]
    pub signblock_hex: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransationResultVinIssuance {
    #[serde(with = "serde_hex")]
    pub asset_blinding_nonce: Vec<u8>,
    #[serde(with = "serde_hex")]
    pub asset_entropy: Vec<u8>,
    pub isreissuance: bool,
    pub token: Option<AssetId>,
    pub asset: AssetId,
    #[serde(rename = "assetamount", default, with = "amount::serde::as_btc::opt")]
    pub asset_amount: Option<Amount>,
    #[serde(rename = "assetamountcommitment", default, with = "serde_hex::opt")]
    pub asset_amount_commitment: Option<Vec<u8>>,
    #[serde(rename = "tokenamount", default, with = "amount::serde::as_btc::opt")]
    pub token_amount: Option<Amount>,
    #[serde(rename = "tokenamountcommitment", default, with = "serde_hex::opt")]
    pub token_amount_commitment: Option<Vec<u8>>,
}

impl GetRawTransationResultVinIssuance {
    /// Get the asset issuance in elements type.
    pub fn asset_issuance(&self) -> Result<elements::AssetIssuance> {
        Ok(elements::AssetIssuance {
            asset_blinding_nonce: {
                if self.asset_blinding_nonce.len() != 32 {
                    return Err(encode::Error::ParseFailed("invalid asset blinding nonce").into());
                }
                let mut a = [0; 32];
                a.copy_from_slice(&self.asset_blinding_nonce);
                a
            },
            asset_entropy: {
                if self.asset_entropy.len() != 32 {
                    return Err(encode::Error::ParseFailed("invalid asset entropy").into());
                }
                let mut a = [0; 32];
                a.copy_from_slice(&self.asset_entropy);
                a
            },
            amount: if let Some(amount) = self.asset_amount {
                elements::confidential::Value::Explicit(amount.as_sat() as u64)
            } else if let Some(ref commitment) = self.asset_amount_commitment {
                encode::deserialize(&commitment)?
            } else {
                return Err(encode::Error::ParseFailed("missing issuance amount info").into());
            },
            inflation_keys: if let Some(amount) = self.token_amount {
                elements::confidential::Value::Explicit(amount.as_sat() as u64)
            } else if let Some(ref commitment) = self.token_amount_commitment {
                encode::deserialize(&commitment)?
            } else {
                return Err(encode::Error::ParseFailed("missing issuance token info").into());
            },
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVin {
    pub txid: sha256d::Hash,
    pub vout: u32,
    pub script_sig: bitcoincore_rpc::json::GetRawTransactionResultVinScriptSig,
    pub sequence: u32,
    #[serde(default, deserialize_with = "deserialize_hex_array_opt")]
    pub txinwitness: Option<Vec<Vec<u8>>>,
    #[serde(default, rename = "pegin_witness", deserialize_with = "deserialize_hex_array_opt")]
    pub pegin_witness: Option<Vec<Vec<u8>>>,
    pub issuance: Option<GetRawTransationResultVinIssuance>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetRawTransactionResultVoutScriptPubKey {
    pub asm: String,
    #[serde(with = "serde_hex")]
    pub hex: Vec<u8>,
    #[serde(rename = "reqSigs")]
    pub req_sigs: Option<usize>,
    #[serde(rename = "type")]
    pub type_: Option<String>, //TODO(stevenroose) consider enum
    pub addresses: Option<Vec<String>>,

    #[serde(default, with = "serde_hex::opt")]
    pub pegout_chain: Option<Vec<u8>>,
    pub pegout_asm: Option<String>,
    #[serde(default, with = "serde_hex::opt")]
    pub pegout_hex: Option<Vec<u8>>,
    #[serde(rename = "pegout_reqSigs")]
    pub pegout_req_sigs: Option<usize>,
    pub pegout_type: Option<String>, //TODO(stevenroose) consider enum
    pub pegout_addresses: Option<Vec<String>>,
}

impl GetRawTransactionResultVoutScriptPubKey {
    pub fn script(&self) -> Script {
        self.hex.clone().into()
    }

    pub fn is_pegout(&self) -> bool {
        self.pegout_chain.is_some()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVout {
    #[serde(default, with = "amount::serde::as_btc::opt")]
    pub value: Option<Amount>,
    #[serde(rename = "ct-minimum", default, with = "amount::serde::as_btc::opt")]
    pub value_minimum: Option<Amount>,
    #[serde(rename = "ct-maximum", default, with = "amount::serde::as_btc::opt")]
    pub value_maximum: Option<Amount>,
    #[serde(rename = "ct-exponent")]
    pub ct_exponent: Option<i64>,
    #[serde(rename = "ct-bits")]
    pub ct_bits: Option<i64>,
    #[serde(rename = "valuecommitment", default, with = "serde_hex::opt")]
    pub value_commitment: Option<Vec<u8>>,
    pub asset: Option<AssetId>,
    #[serde(rename = "assetcommitment", default, with = "serde_hex::opt")]
    pub asset_commitment: Option<Vec<u8>>,
    #[serde(rename = "commitmentnonce", with = "serde_hex")]
    pub commitment_nonce: Vec<u8>,
    #[serde(rename = "commitmentnonce_fully_valid")]
    pub commitment_nonce_fully_valie: bool,
    pub n: u32,
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResult {
    #[serde(rename = "in_active_chain")]
    pub in_active_chain: Option<bool>,
    #[serde(with = "serde_hex")]
    pub hex: Vec<u8>,
    pub txid: sha256d::Hash,
    /// The hash of the tx, including witnesses.
    pub wtxid: sha256d::Hash,
    /// The hash of just the tx witnesses as used in the witness merkle root.
    pub withash: sha256d::Hash,
    pub hash: sha256d::Hash,
    pub size: usize,
    pub vsize: usize,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<GetRawTransactionResultVin>,
    pub vout: Vec<GetRawTransactionResultVout>,
    pub blockhash: sha256d::Hash,
    pub confirmations: usize,
    pub time: usize,
    pub blocktime: usize,
}

impl GetRawTransactionResult {
    pub fn transaction(&self) -> Result<elements::Transaction> {
        Ok(encode::deserialize(&self.hex)?)
    }
}

#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_address: Option<HashMap<AssetId, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_position: Option<u32>,
    #[serde(rename = "change_type", skip_serializing_if = "Option::is_none")]
    pub change_type: Option<bitcoincore_rpc::json::AddressType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_watching: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_unspents: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_rate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtract_fee_from_outputs: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaceable: Option<bool>,
    #[serde(rename = "conf_target", skip_serializing_if = "Option::is_none")]
    pub conf_target: Option<u32>,
    #[serde(rename = "estimate_mode", skip_serializing_if = "Option::is_none")]
    pub estimate_mode: Option<bitcoincore_rpc::json::EstimateMode>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionResult {
    pub hex: Vec<u8>,
    pub fee: u64,
    #[serde(rename = "changepos")]
    pub change_position: u32,
}

impl FundRawTransactionResult {
    pub fn transaction(&self) -> Result<elements::Transaction> {
        Ok(encode::deserialize(&self.hex)?)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentQueryOptions {
    #[serde(default, with = "amount::serde::as_btc::opt")]
    pub minimum_amount: Option<Amount>,
    #[serde(default, with = "amount::serde::as_btc::opt")]
    pub maximum_amount: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_count: Option<usize>,
    #[serde(default, with = "amount::serde::as_btc::opt")]
    pub maximum_sum_amount: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentResultEntry {
    pub txid: sha256d::Hash,
    pub vout: u32,
    pub address: Option<String>,
    pub label: Option<String>,
    pub redeem_script: Option<Script>,
    pub witness_script: Option<Script>,
    pub script_pub_key: Script,
    #[serde(with = "amount::serde::as_btc")]
    pub amount: Amount,
    pub confirmations: usize,
    pub spendable: bool,
    pub solvable: bool,
    #[serde(rename = "desc")]
    pub descriptor: Option<String>,
    pub safe: bool,
    pub asset: AssetId,
    #[serde(rename = "assetcommitment", default, with = "serde_hex::opt")]
    pub asset_commitment: Option<Vec<u8>>,
    #[serde(rename = "amountcommitment", default, with = "serde_hex::opt")]
    pub amount_commitment: Option<Vec<u8>>,
    #[serde(rename = "amountblinder", with = "serde_hex")]
    pub amount_blinding_factor: Vec<u8>,
    #[serde(rename = "assetblinder", with = "serde_hex")]
    pub asset_blinding_factor: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListTransactionsResultEntryCategory {
    Send,
    Receive,
    Orphan,
    Immature,
    Generate,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ListTransactionsResultEntry {
    #[serde(default, rename = "involvesWatchonly")]
    pub involves_watch_only: bool,
    pub category: ListTransactionsResultEntryCategory,
    pub address: Option<String>,
    #[serde(with = "amount::serde::as_btc")]
    pub amount: Amount,
    pub asset: AssetId,
    #[serde(rename = "amountblinder", with = "serde_hex")]
    pub amount_blinding_factor: Vec<u8>,
    #[serde(rename = "assetblinder", with = "serde_hex")]
    pub asset_blinding_factor: Vec<u8>,
    pub label: Option<String>,
    pub vout: u32,
    #[serde(default, with = "amount::serde::as_btc::opt")]
    pub fee: Option<Amount>,
    pub abandoned: Option<bool>,
    //
    pub confirmations: u32,
    #[serde(default)]
    pub generated: bool,
    #[serde(rename = "blockhash")]
    pub block_hash: Option<sha256d::Hash>,
    #[serde(rename = "blockindex")]
    pub block_index: Option<u32>,
    #[serde(rename = "blocktime")]
    pub block_time: Option<u64>,
    #[serde(default)]
    pub trusted: bool,
    pub txid: sha256d::Hash,
    #[serde(rename = "walletconflicts")]
    pub wallet_conflicts: Vec<sha256d::Hash>,
    pub time: u64,
    #[serde(rename = "timereceived")]
    pub time_received: u64,
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: bitcoincore_rpc::json::Bip125Replaceable,
    /// Extra fields that are not well-defined.
    #[serde(flatten)]
    pub extra_info: HashMap<String, String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ValidateAddressResult {
    #[serde(rename = "isvalid")]
    pub is_valid: bool,
    #[serde(rename = "isvalid_parent")]
    pub is_valid_parent: bool,

    // Only provided when is_valid is true.
    pub address: Option<String>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Option<Script>,
    #[serde(rename = "isscript")]
    pub is_script: Option<bool>,
    #[serde(rename = "iswitness")]
    pub is_witness: Option<bool>,
    pub witness_version: Option<u8>,
    #[serde(default, with = "serde_hex::opt")]
    pub witness_program: Option<Vec<u8>>,
    pub confidential_key: Option<String>,
    pub unconfidential: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetAddressInfoResult {
    pub address: String,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Script,
    pub ismine: bool,
    pub iswatchonly: bool,
    pub isscript: bool,
    pub iswitness: bool,
    pub witness_version: Option<u32>,
    #[serde(default, with = "serde_hex::opt")]
    pub witness_program: Option<Vec<u8>>,
    /// The script type.
    pub script: String,
    pub pubkey: Option<PublicKey>,
    pub iscompressed: Option<bool>,
    pub label: Option<String>,
    pub labels: Vec<String>,
    pub timestamp: Option<u64>,
    pub hdkeypath: Option<String>, //TODO(stevenroose) bip32
    #[serde(default, with = "serde_hex::opt")]
    pub hdseedid: Option<Vec<u8>>, //TODO(stevenroose) bip32
    #[serde(default, with = "serde_hex::opt")]
    pub hdmasterkeyid: Option<Vec<u8>>, //TODO(stevenroose) bip32
    // elements
    pub confidential: String,
    pub unconfidential: String,
    pub confidential_key: Option<PublicKey>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetTxOutResult {
    #[serde(rename = "bestblock")]
    pub best_block: sha256d::Hash,
    pub confirmations: u32,
    pub coinbase: bool,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
    #[serde(default, with = "amount::serde::as_btc::opt")]
    pub value: Option<Amount>,
    #[serde(rename = "valuecommitment", default, with = "serde_hex::opt")]
    pub value_commitment: Option<Vec<u8>>,
    pub asset: Option<AssetId>,
    #[serde(rename = "assetcommitment", default, with = "serde_hex::opt")]
    pub asset_commitment: Option<Vec<u8>>,
    #[serde(rename = "commitmentnonce", with = "serde_hex")]
    pub commitment_nonce: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetSidechainInfoResult {
    #[serde(rename = "fedpegscript")]
    pub fedpeg_script: Script,
    pub pegged_asset: AssetId,
    #[serde(rename = "min_peg_diff", with = "serde_hex")]
    pub min_peg_difficulty: Vec<u8>,
    pub parent_blockhash: sha256d::Hash,
    pub parent_chain_has_pow: bool,
    pub enforce_pak: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetPeginAddressResult {
    pub mainchain_address: String,
    pub claim_script: Script,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct CreateRawPeginResult {
    #[serde(with = "serde_hex")]
    pub hex: Vec<u8>,
    pub mature: bool,
}

impl CreateRawPeginResult {
    pub fn transaction(&self) -> Result<elements::Transaction> {
        Ok(encode::deserialize(&self.hex)?)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct InitPegoutWalletResult {
    #[serde(rename = "pegentry")]
    pub pak_entry: String,
    pub liquid_pak: PublicKey,
    pub liquid_pak_address: String,
    pub address_lookahead: Vec<bitcoin::Address>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct SendToMainChainResult {
    pub bitcoin_address: bitcoin::Address,
    pub txid: sha256d::Hash,
    pub bitcoin_descriptor: String, // currently no serde for ExtendedPubKey
    pub bip32_counter: String,      // update serde for ChildNumber to use string
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetWalletPakInfoResult {
    pub bip32_counter: String,
    pub bitcoin_descriptor: String,
    pub liquid_pak: PublicKey,
    pub liquid_pak_address: String,
    pub address_lookahead: Vec<bitcoin::Address>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetPakInfoResultPakList {
    pub online: Option<Vec<PublicKey>>,
    pub offline: Option<Vec<PublicKey>>,
    pub refect: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetPakInfoResult {
    pub config_paklist: GetPakInfoResultPakList,
    pub block_paklist: GetPakInfoResultPakList,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct TweakFedpegScriptResult {
    pub script: Script,
    pub address: bitcoin::Address,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct ListIssuancesResult {
    pub txid: sha256d::Hash,
    #[serde(with = "serde_hex")]
    pub entropy: Vec<u8>,
    pub asset: AssetId,
    #[serde(rename = "assetlabel")]
    pub asset_label: Option<String>,
    pub vin: u32,
    #[serde(rename = "assetamount", with = "amount::serde::as_btc")]
    pub asset_amount: Amount,
    #[serde(rename = "assetblinds", with = "serde_hex")]
    pub asset_blinding_factor: Vec<u8>,
    #[serde(rename = "isreissuance")]
    pub is_reissuance: bool,

    // no reissuance issuance
    pub token: Option<AssetId>,
    #[serde(rename = "tokenamount", default, with = "amount::serde::as_btc::opt")]
    pub token_amount: Option<Amount>,
    #[serde(rename = "tokenblinds", default, with = "serde_hex::opt")]
    pub token_blinding_factor: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct IssueAssetResult {
    pub txid: sha256d::Hash,
    pub vin: u32,
    #[serde(with = "serde_hex")]
    pub entropy: Vec<u8>,
    pub asset: AssetId,
    pub token: AssetId,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct ReissueAssetResult {
    pub txid: sha256d::Hash,
    pub vin: u32,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RawIssuanceDetails {
    #[serde(rename = "assetamount", with = "amount::serde::as_btc")]
    pub asset_amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_address: Option<String>,
    #[serde(rename = "assetamount", with = "amount::serde::as_btc")]
    pub token_amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blind: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_hash: Option<sha256::Hash>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct RawReissuanceDetails {
    pub input_index: u32,
    #[serde(rename = "assetamount", with = "amount::serde::as_btc")]
    pub asset_amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_address: Option<String>,
    #[serde(rename = "asset_blinder", with = "serde_hex")]
    pub blinding_factor: Vec<u8>,
    #[serde(with = "serde_hex")]
    pub entropy: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct RawReissueAssetResult {
    #[serde(with = "serde_hex")]
    pub hex: Vec<u8>,
}

impl RawReissueAssetResult {
    pub fn transaction(&self) -> Result<elements::Transaction> {
        Ok(encode::deserialize(&self.hex)?)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct UnblindRawTransactionResult {
    #[serde(with = "serde_hex")]
    pub hex: Vec<u8>,
}

impl UnblindRawTransactionResult {
    pub fn transaction(&self) -> Result<elements::Transaction> {
        Ok(encode::deserialize(&self.hex)?)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SignedBlockSignature {
    pub pubkey: PublicKey,
    pub sig: Script,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct CombineBlockSigsResult {
    #[serde(with = "serde_hex")]
    pub hex: Vec<u8>,
    pub complete: bool,
}

impl CombineBlockSigsResult {
    pub fn block(&self) -> Result<elements::Block> {
        Ok(encode::deserialize(&self.hex)?)
    }
}
