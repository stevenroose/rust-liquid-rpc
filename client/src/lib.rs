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
extern crate bitcoin_hashes;
extern crate bitcoincore_rpc;
extern crate elements;
extern crate hex;
extern crate jsonrpc;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;

pub extern crate liquid_rpc_json;
pub use json::{bitcoin_asset, Amount, AssetId, BITCOIN_ASSET_HEX};
pub use liquid_rpc_json as json;

pub use bitcoincore_rpc::json as btcjson;
pub use bitcoincore_rpc::{Error, Result};

use std::collections::HashMap;
use std::fs::File;
use std::{io, result};

use bitcoin::consensus::encode;
use bitcoin::util::bip32;
use bitcoin::{PrivateKey, PublicKey, Script};
use bitcoin_hashes::sha256d;
use secp256k1::SecretKey;

/// Serialize an amount returned by the RPC.
fn ser_amount(amount: &Amount) -> serde_json::Value {
    amount.as_float_denom(json::amount::Denomination::Bitcoin).into()
}

fn deser_amount(val: serde_json::Value) -> Amount {
    Amount::from_float_denom(val.as_f64().unwrap(), json::amount::Denomination::Bitcoin)
}

fn convert_balances(balances: HashMap<String, serde_json::Value>) -> HashMap<String, Amount> {
    let mut ret = HashMap::new();
    for (k, v) in balances.into_iter() {
        ret.insert(k, deser_amount(v));
    }
    ret
}

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

/// Shorthand for an empty serde_json object.
fn empty_obj() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
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

/// Convert a possible-null result into an Option.
fn opt_result<T: for<'a> serde::de::Deserialize<'a>>(
    result: serde_json::Value,
) -> Result<Option<T>> {
    if result == serde_json::Value::Null {
        Ok(None)
    } else {
        Ok(serde_json::from_value(result)?)
    }
}

/// Used to pass raw txs into the API.
pub trait RawTx: Sized {
    fn raw_hex(self) -> String;
}

impl<'a> RawTx for &'a elements::Transaction {
    fn raw_hex(self) -> String {
        hex::encode(bitcoin::consensus::encode::serialize(self))
    }
}

impl<'a> RawTx for &'a [u8] {
    fn raw_hex(self) -> String {
        hex::encode(self)
    }
}

impl<'a> RawTx for &'a Vec<u8> {
    fn raw_hex(self) -> String {
        hex::encode(self)
    }
}

impl<'a> RawTx for &'a str {
    fn raw_hex(self) -> String {
        self.to_owned()
    }
}

impl RawTx for String {
    fn raw_hex(self) -> String {
        self
    }
}

/// The different authentication methods for the client.
pub enum Auth<'a> {
    //TODO(stevenroose) remove this and re-export bitcoincore_rpc::Auth
    // once it's merged there: https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/39
    None,
    UserPass(String, String),
    CookieFile(&'a str),
}

impl<'a> Auth<'a> {
    /// Convert into the arguments that jsonrpc::Client needs.
    fn get_user_pass(self) -> result::Result<(Option<String>, Option<String>), io::Error> {
        use std::io::Read;
        match self {
            Auth::None => Ok((None, None)),
            Auth::UserPass(u, p) => Ok((Some(u), Some(p))),
            Auth::CookieFile(path) => {
                let mut file = File::open(path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let mut split = contents.splitn(2, ":");
                Ok((Some(split.next().unwrap().into()), Some(split.next().unwrap_or("").into())))
            }
        }
    }
}

/// Trait implementing the Liquid RPC commands.
pub trait LiquidRpcApi: Sized {
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
        let mut args = [into_json(txid)?, into_json(false)?, opt_into_json(block_hash)?];
        let hex: String = self.call("getrawtransaction", handle_defaults(&mut args, &[null()]))?;
        let bytes = hex::decode(hex)?;
        Ok(encode::deserialize(&bytes)?)
    }

    fn get_raw_transaction_verbose(
        &self,
        txid: &sha256d::Hash,
        block_hash: Option<&sha256d::Hash>,
    ) -> Result<json::GetRawTransactionResult> {
        let mut args = [into_json(txid)?, into_json(true)?, opt_into_json(block_hash)?];
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
        self.call("sendtoaddress", handle_defaults(&mut args, &vec![null(); 8]))
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
        let defaults = [into_json(0i64)?, false.into(), null()];
        self.call("createrawtransaction", handle_defaults(&mut args, &defaults))
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

    fn fund_raw_transaction<R: RawTx>(
        &self,
        tx: R,
        options: Option<json::FundRawTransactionOptions>,
        is_witness: Option<bool>,
    ) -> Result<json::FundRawTransactionResult> {
        let mut args = [tx.raw_hex().into(), opt_into_json(options)?, opt_into_json(is_witness)?];
        let defaults = [empty_obj(), null()];
        self.call("fundrawtransaction", handle_defaults(&mut args, &defaults))
    }

    fn sign_raw_transaction_with_wallet<R: RawTx>(
        &self,
        tx: R,
        utxos: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<bitcoincore_rpc::json::SigHashType>,
    ) -> Result<json::SignRawTransactionResult> {
        let mut args = [tx.raw_hex().into(), opt_into_json(utxos)?, opt_into_json(sighash_type)?];
        let defaults = [empty(), null()];
        self.call("signrawtransactionwithwallet", handle_defaults(&mut args, &defaults))
    }

    fn sign_raw_transaction_with_key<R: RawTx>(
        &self,
        tx: R,
        privkeys: &[&PrivateKey],
        prevtxs: Option<&[json::SignRawTransactionInput]>,
        sighash_type: Option<bitcoincore_rpc::json::SigHashType>,
    ) -> Result<json::SignRawTransactionResult> {
        let mut args = [
            tx.raw_hex().into(),
            into_json(privkeys)?,
            opt_into_json(prevtxs)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [empty(), null()];
        self.call("signrawtransactionwithkey", handle_defaults(&mut args, &defaults))
    }

    fn send_raw_transaction<R: RawTx>(&self, tx: R) -> Result<sha256d::Hash> {
        self.call("sendrawtransaction", handle_defaults(&mut [tx.raw_hex().into()], &[]))
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
        let defaults = [0.into(), 9999999.into(), empty(), true.into(), null()];
        self.call("listunspent", handle_defaults(&mut args, &defaults))
    }

    fn list_transactions(
        &self,
        count: Option<usize>,
        skip: Option<usize>,
        include_watch_only: Option<bool>,
    ) -> Result<Vec<json::ListTransactionsResultEntry>> {
        let mut args = [
            "*".into(),
            opt_into_json(count)?,
            opt_into_json(skip)?,
            opt_into_json(include_watch_only)?,
        ];
        let defaults = [10.into(), 0.into(), null()];
        self.call("listtransactions", handle_defaults(&mut args, &defaults))
    }

    fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<btcjson::AddressType>,
    ) -> Result<String> {
        self.call("getnewaddress", &[opt_into_json(label)?, opt_into_json(address_type)?])
    }

    fn validate_address(&self, address: &str) -> Result<json::ValidateAddressResult> {
        self.call("validateaddress", &[address.into()])
    }

    fn get_address_info(&self, address: &str) -> Result<json::GetAddressInfoResult> {
        self.call("getaddressinfo", &[address.into()])
    }

    fn get_tx_out(
        &self,
        txid: sha256d::Hash,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<json::GetTxOutResult>> {
        let mut args = [into_json(txid)?, vout.into(), opt_into_json(include_mempool)?];
        self.call("gettxout", handle_defaults(&mut args, &[null()])).and_then(opt_result)
    }

    fn get_balance(
        &self,
        min_confirmations: Option<u32>,
        include_watch_only: Option<bool>,
    ) -> Result<HashMap<String, Amount>> {
        let mut args = [
            "*".into(), // backwards compat dummy
            opt_into_json(min_confirmations)?,
            opt_into_json(include_watch_only)?,
        ];
        self.call("getbalance", handle_defaults(&mut args, &[0.into(), null()]))
            .map(convert_balances)
    }

    fn get_balance_asset(
        &self,
        asset_label: &str,
        min_confirmations: Option<u32>,
        include_watch_only: Option<bool>,
    ) -> Result<Amount> {
        let mut args = [
            "*".into(), // backwards compat dummy
            opt_into_json(min_confirmations)?,
            opt_into_json(include_watch_only)?,
            opt_into_json(Some(asset_label))?,
        ];
        self.call("getbalance", handle_defaults(&mut args, &[0.into(), false.into(), null()]))
            .map(deser_amount)
    }

    fn get_unconfirmed_balance(&self) -> Result<HashMap<String, Amount>> {
        self.call("getunconfirmedbalance", handle_defaults(&mut [], &[])).map(convert_balances)
    }

    fn get_received_by_address(
        &self,
        address: &str,
        min_confirmations: Option<u32>,
    ) -> Result<HashMap<String, Amount>> {
        let mut args = [address.into(), opt_into_json(min_confirmations)?];
        self.call("getreceivedbyaddress", handle_defaults(&mut args, &[null()]))
            .map(convert_balances)
    }

    fn get_received_by_address_asset(
        &self,
        address: &str,
        asset_label: &str,
        min_confirmations: Option<u32>,
    ) -> Result<Amount> {
        let mut args =
            [address.into(), opt_into_json(min_confirmations)?, opt_into_json(Some(asset_label))?];
        self.call("getreceivedbyaddress", handle_defaults(&mut args, &[0.into(), null()]))
            .map(deser_amount)
    }

    // TODO(stevenroose)
    // sendmany

    // Liquid-only calls

    fn get_sidechain_info(&self) -> Result<json::GetSidechainInfoResult> {
        self.call("getsidechaininfo", &[])
    }

    fn get_pegin_address(&self) -> Result<json::GetPeginAddressResult> {
        self.call("getpeginaddress", &[])
    }

    fn create_raw_pegin<R: bitcoincore_rpc::RawTx, B: AsRef<[u8]>>(
        &self,
        raw_bitcoin_tx: R,
        txout_proof: B,
        claim_script: Option<&Script>,
    ) -> Result<json::CreateRawPeginResult> {
        let mut args = [
            raw_bitcoin_tx.raw_hex().into(),
            into_json_hex(txout_proof)?,
            opt_into_json_hex(claim_script.map(|s| s.as_bytes()))?,
        ];
        self.call("createrawpegin", handle_defaults(&mut args, &[null()]))
    }

    fn claim_pegin<R: bitcoincore_rpc::RawTx, B: AsRef<[u8]>>(
        &self,
        raw_bitcoin_tx: R,
        txout_proof: B,
        claim_script: Option<&Script>,
    ) -> Result<sha256d::Hash> {
        let mut args = [
            raw_bitcoin_tx.raw_hex().into(),
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
        self.call("initpegoutwallet", handle_defaults(&mut args, &[0.into(), null()]))
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
        self.call("tweakfedpegscript", &[into_json_hex(claim_script.as_bytes())?])
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
        self.call("reissueasset", &[into_json(asset)?, into_json(ser_amount(&asset_amount))?])
    }

    fn raw_issue_asset<R: RawTx>(
        &self,
        raw_tx: R,
        issuances: &[json::RawIssuanceDetails],
    ) -> Result<json::IssueAssetResult> {
        self.call("rawissueasset", &[raw_tx.raw_hex().into(), into_json(issuances)?])
    }

    fn raw_reissue_asset<R: RawTx>(
        &self,
        raw_tx: R,
        issuances: &[json::RawReissuanceDetails],
    ) -> Result<json::RawReissueAssetResult> {
        self.call("rawreissueasset", &[raw_tx.raw_hex().into(), into_json(issuances)?])
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
        let mut args =
            [into_json(asset)?, into_json(ser_amount(&amount))?, opt_into_json(comment)?];
        self.call("destropamount", handle_defaults(&mut args, &[null()]))
    }

    fn blind_raw_transaction<R: RawTx, B: AsRef<[u8]>>(
        &self,
        raw_tx: R,
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
            raw_tx.raw_hex().into(),
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

    fn unblind_raw_transaction<R: RawTx>(
        &self,
        raw_tx: R,
    ) -> Result<json::UnblindRawTransactionResult> {
        self.call("unblindrawtransaction", &[raw_tx.raw_hex().into()])
    }

    fn raw_blind_raw_transaction<R: RawTx, B: AsRef<[u8]>>(
        &self,
        raw_tx: R,
        input_amount_blinding_factors: &[B],
        input_amounts: &[Amount],
        input_assets: &[AssetId],
        input_asset_blinding_factors: &[B],
        ignore_blind_fail: Option<bool>,
    ) -> Result<elements::Transaction> {
        let amount_bfs: Result<Vec<serde_json::Value>> =
            input_amount_blinding_factors.into_iter().map(into_json_hex).collect();
        let amounts: Vec<serde_json::Value> = input_amounts.into_iter().map(ser_amount).collect();
        let assets: Result<Vec<serde_json::Value>> =
            input_assets.into_iter().map(into_json).collect();
        let asset_bfs: Result<Vec<serde_json::Value>> =
            input_asset_blinding_factors.into_iter().map(into_json_hex).collect();
        let mut args = [
            raw_tx.raw_hex().into(),
            into_json(amount_bfs?)?,
            into_json(amounts)?,
            into_json(assets?)?,
            into_json(asset_bfs?)?,
            opt_into_json(ignore_blind_fail)?,
        ];
        let hex: String =
            self.call("rawblindrawtransaction", handle_defaults(&mut args, &[null()]))?;
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
        self.call("importmasterblindingkey", &[master_blinding_key.to_string().into()])
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
        let args = [into_json(txid)?, vin.into(), blinding_key.to_string().into()];
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
        let args = [into_json_hex(encode::serialize(&block))?, into_json(signatures)?];
        self.call("combineblocksigs", &args)
    }

    fn test_proposed_block(
        &self,
        block: elements::Block,
        accept_non_standard: Option<bool>,
    ) -> Result<()> {
        let mut args =
            [into_json_hex(encode::serialize(&block))?, opt_into_json(accept_non_standard)?];
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
/// [liquid_rpc::LiquidRpcApi] trait.  Methods that are shared between Liquid and
/// Bitcoin Core can be used from the former and changed or new methods are
/// provided by the latter.
pub struct Client(bitcoincore_rpc::Client);

impl Client {
    /// Creates a client to a liquidd JSON-RPC server.
    pub fn new(url: String, auth: Auth) -> result::Result<Self, io::Error> {
        let (user, pass) = auth.get_user_pass()?;
        Ok(Client(bitcoincore_rpc::Client::new(url, user, pass)))
    }

    /// Create a new Client.
    pub fn from_jsonrpc(client: jsonrpc::client::Client) -> Self {
        Client(bitcoincore_rpc::Client::from_jsonrpc(client))
    }
}

impl bitcoincore_rpc::RpcApi for Client {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        bitcoincore_rpc::RpcApi::call(&self.0, cmd, args)
    }
}

impl LiquidRpcApi for Client {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        bitcoincore_rpc::RpcApi::call(self, cmd, args)
    }
}
