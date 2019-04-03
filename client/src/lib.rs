// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Rust Client for Liquid API
//!
//! This is a client library for the Liquid JSON-RPC API.
//!

#![crate_name = "liquid_rpc"]
#![crate_type = "rlib"]

extern crate bitcoin;
extern crate bitcoin_amount;
extern crate bitcoin_hashes;
extern crate bitcoincore_rpc;
extern crate elements;
extern crate hex;
extern crate jsonrpc;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;

pub extern crate liquid_rpc_json;
pub use liquid_rpc_json as json;

use std::collections::HashMap;

use bitcoin::consensus::encode;
use bitcoin::util::bip32;
use bitcoin::{PublicKey, Script};
use bitcoin_amount::Amount;
use bitcoin_hashes::sha256d;
use bitcoincore_rpc::Result;
use secp256k1::SecretKey;

use json::AssetId;

/// Serialize an amount returned by the RPC.
fn ser_amount(amount: &Amount) -> serde_json::Value {
    //TODO(stevenroose) THIS IS WRONG, NEED OTHER AMOUNT TYPE OR EXACT CONVERSION
    (amount.clone().into_inner() as f64).into()
}

// tmp bitcoincore_rpc utils

/// Shorthand for converting a variable into a serde_json::Value.
fn into_json<T>(val: T) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

/// Shorthand for converting bytes into a serde_json::Value.
fn into_json_hex<T: AsRef<[u8]>>(val: T) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(hex::encode(val))?)
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
fn opt_into_json<T>(opt: Option<T>) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(into_json(val)?),
        None => Ok(serde_json::Value::Null),
    }
}

/// Shorthand for converting bytes into a serde_json::Value.
fn opt_into_json_hex<T: AsRef<[u8]>>(opt: Option<T>) -> Result<serde_json::Value> {
    match opt {
        Some(b) => Ok(serde_json::to_value(hex::encode(b))?),
        None => Ok(serde_json::Value::Null),
    }
}

/// Shorthand for `serde_json::Value::Null`.
fn null() -> serde_json::Value {
    serde_json::Value::Null
}

/// Shorthand for an empty serde_json::Value array.
fn empty() -> serde_json::Value {
    serde_json::Value::Array(vec![])
}

/// Handle default values in the argument list
///
/// Substitute `Value::Null`s with corresponding values from `defaults` table,
/// except when they are trailing, in which case just skip them altogether
/// in returned list.
///
/// Note, that `defaults` corresponds to the last elements of `args`.
///
/// ```norust
/// arg1 arg2 arg3 arg4
///           def1 def2
/// ```
///
/// Elements of `args` without corresponding `defaults` value, won't
/// be substituted, because they are required.
fn handle_defaults<'a, 'b>(
    args: &'a mut [serde_json::Value],
    defaults: &'b [serde_json::Value],
) -> &'a [serde_json::Value] {
    assert!(args.len() >= defaults.len());

    // Pass over the optional arguments in backwards order, filling in defaults after the first
    // non-null optional argument has been observed.
    let mut first_non_null_optional_idx = None;
    for i in 0..defaults.len() {
        let args_i = args.len() - 1 - i;
        let defaults_i = defaults.len() - 1 - i;
        if args[args_i] == serde_json::Value::Null {
            if first_non_null_optional_idx.is_some() {
                if defaults[defaults_i] == serde_json::Value::Null {
                    panic!("Missing `default` for argument idx {}", args_i);
                }
                args[args_i] = defaults[defaults_i].clone();
            }
        } else if first_non_null_optional_idx.is_none() {
            first_non_null_optional_idx = Some(args_i);
        }
    }

    let required_num = args.len() - defaults.len();

    if let Some(i) = first_non_null_optional_idx {
        &args[..i + 1]
    } else {
        &args[..required_num]
    }
}

/// Trait implementing the Liquid RPC commands.
pub trait LiquidRpc: Sized {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T>;

    fn get_block_header_raw(&self, hash: &sha256d::Hash) -> Result<elements::BlockHeader> {
        let hex: String = self.call("getblockheader", &[into_json(hash)?, false.into()])?;
        let bytes = hex::decode(hex)?;
        Ok(encode::deserialize(&bytes)?)
    }

    fn get_block_header_verbose(&self, hash: &sha256d::Hash) -> Result<json::GetBlockHeaderResult> {
        self.call("getblockheader", &[into_json(hash)?, true.into()])
    }

    /// Returns a data structure containing various state info regarding
    /// blockchain processing.
    fn get_blockchain_info(&self) -> Result<json::GetBlockchainInfoResult> {
        self.call("getblockchaininfo", &[])
    }

    fn get_raw_transaction(
        &self,
        txid: &sha256d::Hash,
        block_hash: Option<&sha256d::Hash>,
    ) -> Result<elements::Transaction> {
        let mut args = [
            into_json(txid)?,
            into_json(false)?,
            opt_into_json(block_hash)?,
        ];
        let hex: String = self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))?;
        let bytes = hex::decode(hex)?;
        Ok(encode::deserialize(&bytes)?)
    }

    fn get_raw_transaction_verbose(
        &self,
        txid: &sha256d::Hash,
        block_hash: Option<&sha256d::Hash>,
    ) -> Result<json::GetRawTransactionResult> {
        let mut args = [
            into_json(txid)?,
            into_json(true)?,
            opt_into_json(block_hash)?,
        ];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))
    }

    fn send_to_address(
        &self,
        address: &str,
        amount: f64,
        comment: Option<&str>,
        comment_to: Option<&str>,
        substract_fee: Option<bool>,
        replaceable: Option<bool>,
        confirmation_target: Option<u32>,
        estimate_mode: Option<bitcoincore_rpc::json::EstimateMode>,
        asset_label: Option<&str>,
        ignore_blind_fail: Option<bool>,
    ) -> Result<sha256d::Hash> {
        let mut args = [
            address.into(),
            into_json(amount)?,
            opt_into_json(comment)?,
            opt_into_json(comment_to)?,
            opt_into_json(substract_fee)?,
            opt_into_json(replaceable)?,
            opt_into_json(confirmation_target)?,
            opt_into_json(estimate_mode)?,
            opt_into_json(asset_label)?,
            opt_into_json(ignore_blind_fail)?,
        ];
        self.call(
            "sendtoaddress",
            handle_defaults(&mut args, &vec![null(); 8]),
        )
    }

    fn create_raw_transaction_hex(
        &self,
        utxos: &[bitcoincore_rpc::json::CreateRawTransactionInput],
        outs: &HashMap<String, f64>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
        assets: Option<&HashMap<String, AssetId>>,
    ) -> Result<String> {
        let mut args = [
            into_json(utxos)?,
            into_json(outs)?,
            opt_into_json(locktime)?,
            opt_into_json(replaceable)?,
            opt_into_json(assets)?,
        ];
        let defaults = [into_json(0i64)?, null(), null()];
        self.call(
            "createrawtransaction",
            handle_defaults(&mut args, &defaults),
        )
    }

    fn create_raw_transaction(
        &self,
        utxos: &[bitcoincore_rpc::json::CreateRawTransactionInput],
        outs: &HashMap<String, f64>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
        assets: Option<&HashMap<String, AssetId>>,
    ) -> Result<elements::Transaction> {
        let hex: String =
            self.create_raw_transaction_hex(utxos, outs, locktime, replaceable, assets)?;
        let bytes = hex::decode(hex)?;
        Ok(encode::deserialize(&bytes)?)
    }

    fn list_unspent(
        &self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
        addresses: Option<&[&str]>,
        include_unsafe: Option<bool>,
        query_options: Option<json::ListUnspentQueryOptions>,
    ) -> Result<Vec<json::ListUnspentResultEntry>> {
        let mut args = [
            opt_into_json(minconf)?,
            opt_into_json(maxconf)?,
            opt_into_json(addresses)?,
            opt_into_json(include_unsafe)?,
            opt_into_json(query_options)?,
        ];
        let defaults = [
            into_json(0)?,
            into_json(9999999)?,
            null(),
            into_json(true)?,
            null(),
        ];
        self.call("listunspent", handle_defaults(&mut args, &defaults))
    }

    fn get_address_info(&self, address: &str) -> Result<json::GetAddressInfoResult> {
        self.call("getaddressinfo", &[address.into()])
    }

    fn get_txout(
        &self,
        outpoint: elements::OutPoint,
        include_mempool: Option<bool>,
    ) -> Result<json::GetTxOutResult> {
        let mut args = [
            into_json(outpoint.txid)?,
            into_json(outpoint.vout)?,
            opt_into_json(include_mempool)?,
        ];
        self.call("gettxout", handle_defaults(&mut args, &[null()]))
    }

    // TODO(stevenroose)
    // sendmany
    // fundrawtransaction? hard.. not in upstream because hard

    fn get_sidechain_info(&self) -> Result<json::GetSidechainInfoResult> {
        self.call("getsidechaininfo", &[])
    }

    fn get_pegin_address(&self) -> Result<json::GetPeginAddressResult> {
        self.call("getpeginaddress", &[])
    }

    fn create_raw_pegin<B: AsRef<[u8]>>(
        &self,
        raw_bitcoin_tx: B,
        txout_proof: B,
        claim_script: Option<&Script>,
    ) -> Result<json::CreateRawPeginResult> {
        let mut args = [
            into_json_hex(raw_bitcoin_tx)?,
            into_json_hex(txout_proof)?,
            opt_into_json_hex(claim_script.map(|s| s.as_bytes()))?,
        ];
        self.call("createrawpegin", handle_defaults(&mut args, &[null()]))
    }

    fn claim_pegin<B: AsRef<[u8]>>(
        &self,
        raw_bitcoin_tx: B,
        txout_proof: B,
        claim_script: Option<&Script>,
    ) -> Result<sha256d::Hash> {
        let mut args = [
            into_json_hex(raw_bitcoin_tx)?,
            into_json_hex(txout_proof)?,
            opt_into_json_hex(claim_script.map(|s| s.as_bytes()))?,
        ];
        self.call("claimpegin", handle_defaults(&mut args, &[null()]))
    }

    fn init_pegout_wallet(
        &self,
        bitcoin_descriptor: bip32::ExtendedPubKey,
        bip32_counter: Option<bip32::ChildNumber>,
        liquid_pak: Option<&str>,
    ) -> Result<json::InitPegoutWalletResult> {
        let mut args = [
            "".into(), // compatibility dummy
            bitcoin_descriptor.to_string().into(),
            opt_into_json(bip32_counter)?,
            opt_into_json(liquid_pak)?,
        ];
        self.call(
            "initpegoutwallet",
            handle_defaults(&mut args, &[0.into(), null()]),
        )
    }

    fn send_to_main_chain(
        &self,
        amount: Amount,
        subtract_fee_from_amount: Option<bool>,
    ) -> Result<json::SendToMainChainResult> {
        let mut args = [
            "".into(), // compatibility dummy
            into_json(ser_amount(&amount))?,
            opt_into_json(subtract_fee_from_amount)?,
        ];
        self.call("sendtomainchain", handle_defaults(&mut args, &[null()]))
    }

    fn get_wallet_pak_info(&self) -> Result<json::GetWalletPakInfoResult> {
        self.call("getwalletpakinfo", &[])
    }

    fn get_pak_info(&self) -> Result<json::GetPakInfoResult> {
        self.call("getpakinfo", &[])
    }

    fn tweak_fedpeg_script(&self, claim_script: &Script) -> Result<json::TweakFedpegScriptResult> {
        self.call(
            "tweakfedpegscript",
            &[into_json_hex(claim_script.as_bytes())?],
        )
    }

    fn list_issuances(&self, asset: Option<AssetId>) -> Result<Vec<json::ListIssuancesResult>> {
        let mut args = [opt_into_json(asset)?];
        self.call("listissuances", handle_defaults(&mut args, &[null()]))
    }

    fn issue_asset(
        &self,
        asset_amount: Amount,
        token_amount: Amount,
        blind: Option<bool>,
    ) -> Result<json::IssueAssetResult> {
        let mut args = [
            into_json(ser_amount(&asset_amount))?,
            into_json(ser_amount(&token_amount))?,
            opt_into_json(blind)?,
        ];
        self.call("issueasset", handle_defaults(&mut args, &[null()]))
    }

    fn reissue_asset(
        &self,
        asset: AssetId,
        asset_amount: Amount,
    ) -> Result<json::ReissueAssetResult> {
        self.call(
            "reissueasset",
            &[into_json(asset)?, into_json(ser_amount(&asset_amount))?],
        )
    }

    fn raw_issue_asset<B: AsRef<[u8]>>(
        &self,
        raw_tx: B,
        issuances: &[json::RawIssuanceDetails],
    ) -> Result<json::IssueAssetResult> {
        self.call(
            "rawissueasset",
            &[into_json_hex(raw_tx)?, into_json(issuances)?],
        )
    }

    fn raw_reissue_asset<B: AsRef<[u8]>>(
        &self,
        raw_tx: B,
        issuances: &[json::RawReissuanceDetails],
    ) -> Result<json::RawReissueAssetResult> {
        self.call(
            "rawreissueasset",
            &[into_json_hex(raw_tx)?, into_json(issuances)?],
        )
    }

    fn dump_asset_labels(&self) -> Result<HashMap<String, AssetId>> {
        self.call("dumpassetlabels", &[])
    }

    fn destroy_amount(
        &self,
        asset: AssetId,
        amount: Amount,
        comment: Option<&str>,
    ) -> Result<sha256d::Hash> {
        let mut args = [
            into_json(asset)?,
            into_json(ser_amount(&amount))?,
            opt_into_json(comment)?,
        ];
        self.call("destropamount", handle_defaults(&mut args, &[null()]))
    }

    fn blind_raw_transaction<B: AsRef<[u8]>>(
        &self,
        raw_tx: B,
        ignore_blind_fail: Option<bool>,
        asset_commitments: Option<&[B]>,
        blind_issuances: Option<bool>,
    ) -> Result<elements::Transaction> {
        let commitments = asset_commitments
            .map(|v| {
                let ret: Result<Vec<serde_json::Value>> = v.iter().map(into_json_hex).collect();
                ret
            })
            .transpose()?;
        let mut args = [
            into_json_hex(raw_tx)?,
            opt_into_json(ignore_blind_fail)?,
            opt_into_json(commitments)?,
            opt_into_json(blind_issuances)?,
        ];
        let hex: String = self.call(
            "blindrawtransaction",
            handle_defaults(&mut args, &[true.into(), empty(), null()]),
        )?;
        let bytes = hex::decode(hex)?;
        Ok(encode::deserialize(&bytes)?)
    }

    fn unblind_raw_transaction<B: AsRef<[u8]>>(
        &self,
        raw_tx: B,
    ) -> Result<json::UnblindRawTransactionResult> {
        self.call("unblindrawtransaction", &[into_json_hex(raw_tx)?])
    }

    fn raw_blind_raw_transaction<B: AsRef<[u8]>>(
        &self,
        raw_tx: B,
        input_amount_blinding_factors: &[B],
        input_amounts: &[Amount],
        input_assets: &[AssetId],
        input_asset_blinding_factors: &[B],
        ignore_blind_fail: Option<bool>,
    ) -> Result<elements::Transaction> {
        let amount_bfs: Result<Vec<serde_json::Value>> = input_amount_blinding_factors
            .into_iter()
            .map(into_json_hex)
            .collect();
        let amounts: Vec<serde_json::Value> = input_amounts.into_iter().map(ser_amount).collect();
        let assets: Result<Vec<serde_json::Value>> =
            input_assets.into_iter().map(into_json).collect();
        let asset_bfs: Result<Vec<serde_json::Value>> = input_asset_blinding_factors
            .into_iter()
            .map(into_json_hex)
            .collect();
        let mut args = [
            into_json_hex(raw_tx)?,
            into_json(amount_bfs?)?,
            into_json(amounts)?,
            into_json(assets?)?,
            into_json(asset_bfs?)?,
            opt_into_json(ignore_blind_fail)?,
        ];
        let hex: String = self.call(
            "rawblindrawtransaction",
            handle_defaults(&mut args, &[null()]),
        )?;
        let bytes = hex::decode(hex)?;
        Ok(encode::deserialize(&bytes)?)
    }

    fn create_blinded_address(&self, address: &str, blinding_pubkey: PublicKey) -> Result<String> {
        let mut args = [
            into_json_hex(address)?,
            //TODO(stevenroose) use PublicKey's serde for rust-bitcoin > 0.18.0
            blinding_pubkey.to_string().into(),
        ];
        self.call("createblindedaddress", handle_defaults(&mut args, &[]))
    }

    fn dump_blinding_key(&self, address: &str) -> Result<SecretKey> {
        let hex: String = self.call("dumpblindingkey", &[into_json_hex(address)?])?;
        let bytes = hex::decode(hex)?;
        Ok(SecretKey::from_slice(&bytes).map_err(encode::Error::Secp256k1)?)
    }

    fn import_blinding_key(&self, address: &str, blinding_key: SecretKey) -> Result<()> {
        let args = [into_json_hex(address)?, blinding_key.to_string().into()];
        self.call("importblindingkey", &args)
    }

    fn dump_master_blinding_key(&self) -> Result<SecretKey> {
        let hex: String = self.call("dumpmasterblindingkey", &[])?;
        let bytes = hex::decode(hex)?;
        Ok(SecretKey::from_slice(&bytes).map_err(encode::Error::Secp256k1)?)
    }

    fn import_master_blinding_key(&self, master_blinding_key: SecretKey) -> Result<()> {
        self.call(
            "importmasterblindingkey",
            &[master_blinding_key.to_string().into()],
        )
    }

    fn dump_issuance_blinding_key(&self, txid: sha256d::Hash, vin: u32) -> Result<SecretKey> {
        let hex: String = self.call("dumpissuanceblindingkey", &[into_json(txid)?, vin.into()])?;
        let bytes = hex::decode(hex)?;
        Ok(SecretKey::from_slice(&bytes).map_err(encode::Error::Secp256k1)?)
    }

    fn import_issuance_blinding_key(
        &self,
        txid: sha256d::Hash,
        vin: u32,
        blinding_key: SecretKey,
    ) -> Result<()> {
        let args = [
            into_json(txid)?,
            vin.into(),
            blinding_key.to_string().into(),
        ];
        self.call("importissuanceblindingkey", &args)
    }

    fn get_new_block(&self, min_tx_age_secs: Option<usize>) -> Result<elements::Block> {
        let mut args = [opt_into_json(min_tx_age_secs)?];
        let hex: String = self.call("getnewblockhex", handle_defaults(&mut args, &[null()]))?;
        let bytes = hex::decode(hex)?;
        Ok(encode::deserialize(&bytes)?)
    }

    fn sign_block(&self, block: elements::Block) -> Result<Vec<json::SignedBlockSignature>> {
        self.call("signblock", &[into_json_hex(encode::serialize(&block))?])
    }

    fn combine_block_signatures(
        &self,
        block: elements::Block,
        signatures: &[&json::SignedBlockSignature],
    ) -> Result<json::CombineBlockSigsResult> {
        let args = [
            into_json_hex(encode::serialize(&block))?,
            into_json(signatures)?,
        ];
        self.call("combineblocksigs", &args)
    }

    fn test_proposed_block(
        &self,
        block: elements::Block,
        accept_non_standard: Option<bool>,
    ) -> Result<()> {
        let mut args = [
            into_json_hex(encode::serialize(&block))?,
            opt_into_json(accept_non_standard)?,
        ];
        self.call("testproposedblock", handle_defaults(&mut args, &[null()]))
    }

    fn submit_block(&self, block: elements::Block) -> Result<String> {
        self.call("submitblock", &[into_json_hex(encode::serialize(&block))?])
    }

    //TODO(stevenroose)
    // Compact Blocks commands
    // getcompactsketch
    // consumecompactsketch
    // finalizecompactblock
}

/// A Liquid RPC client.
///
/// This type implements both the [bitcoincore_rpc::RpcApi] trait as the
/// [liquid_rpc::LiquidRpc] trait.  Methods that are shared between Liquid and
/// Bitcoin Core can be used from the former and changed or new methods are
/// provided by the latter.
pub struct LiquidClient(bitcoincore_rpc::Client);

impl LiquidClient {
    /// Creates a client to a liquidd JSON-RPC server.
    pub fn new(url: String, user: Option<String>, pass: Option<String>) -> Self {
        debug_assert!(pass.is_none() || user.is_some());

        LiquidClient(bitcoincore_rpc::Client::new(url, user, pass))
    }

    /// Create a new LiquidClient.
    pub fn from_jsonrpc(client: jsonrpc::client::Client) -> Self {
        LiquidClient(bitcoincore_rpc::Client::from_jsonrpc(client))
    }
}

impl bitcoincore_rpc::RpcApi for LiquidClient {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        bitcoincore_rpc::RpcApi::call(&self.0, cmd, args)
    }
}

impl LiquidRpc for LiquidClient {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        bitcoincore_rpc::RpcApi::call(self, cmd, args)
    }
}
