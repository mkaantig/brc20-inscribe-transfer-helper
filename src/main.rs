#![allow(unused_imports)]

use {
    bitcoin::{
      blockdata::{
        opcodes,
        script::{self, Instruction, Instructions, PushBytesBuf},
      },
      secp256k1::{
        self, constants::SCHNORR_SIGNATURE_SIZE, rand, schnorr::Signature, Secp256k1, XOnlyPublicKey, SecretKey,
      },
      key::{TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair},
      key::PrivateKey,
      taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
      Amount,
      Network,
      Address,
      Transaction,
      TxIn,
      TxOut,
      Witness,
      Sequence,
      Txid,
      sighash:: { TapSighashType, Prevouts, SighashCache},
      ScriptBuf,
      locktime::absolute::LockTime,
    },
    std::{iter::Peekable, str},
    std::str::FromStr,
    std::ptr::null,
    serde::{Deserialize, Serialize},
};

const PROTOCOL_ID: [u8; 3] = *b"ord";
const CONTENT_TYPE_TAG: [u8; 1] = [1];

#[derive(Serialize, Deserialize, Debug)]
struct InscribeTransfer {
  p: String,
  op: String,
  tick: String,
  amt: String
}

impl InscribeTransfer {
  fn new(tick: String, amount_in_normal_unit: String) -> Self {
    Self {
      p: "brc-20".to_string(),
      op: "transfer".to_string(),
      tick: tick,
      amt: amount_in_normal_unit,
    }
  }
}

#[derive(Debug)]
struct UnspentOutputTransaction {
  transaction_id: String,
  output_index: u32,
  amount_in_base_unit: u64,
}

impl UnspentOutputTransaction {
  fn new(previous_transaction_id: &str, utxo_output_index: u32, amount_in_base_unit: u64) -> Self {
    Self {
      transaction_id: previous_transaction_id.to_string(),
      output_index: utxo_output_index,
      amount_in_base_unit: amount_in_base_unit,
    }
  }
}

fn main() {
    let utxo: UnspentOutputTransaction = UnspentOutputTransaction::new("763351c723971eaa36b6c7c5b132821049e4b438cc35bc676e6224c605787271", 0, 4000);
    println!("utxo: {:?}", utxo);
    let secret_key_str = "2de98c37efb97ca35bd06c8bcb785e8160cb4772e86d5f3d418062f8cbba24f7";
    let tick: String = "ordi".to_string();
    let amount_in_normal_unit: String = "0.998".to_string();
    let commit_tx_address = retrieve_commit_tx_address(secret_key_str, tick.clone(), amount_in_normal_unit.clone());
    println!("commit_tx_address: {}", commit_tx_address);
    let reveal_tx = build_reveal_transaction(secret_key_str, utxo, tick.clone(), amount_in_normal_unit.clone());
    println!("{}", reveal_tx);
}

pub(crate) fn retrieve_commit_tx_address(secret_key_str: &str, token: String, amount_in_normal_unit: String) -> bitcoin::Address {
  let secret_key = SecretKey::from_str(secret_key_str).unwrap();
  let secp256k1 = Secp256k1::new();
  let key_pair = UntweakedKeyPair::from_secret_key(&secp256k1, &secret_key);
  let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
  let public_key_script = ScriptBuf::builder()
    .push_slice(&public_key.serialize())
    .push_opcode(opcodes::all::OP_CHECKSIG);
  let reveal_script = build_inscribe_script(public_key_script, token, amount_in_normal_unit);
  let taproot_spend_info = TaprootBuilder::new()
    .add_leaf(0, reveal_script.clone())
    .expect("adding leaf should work")
    .finalize(&secp256k1, public_key)
    .expect("finalizing taproot builder should work");
  Address::p2tr_tweaked(taproot_spend_info.output_key(), Network::Bitcoin)
}

fn build_inscribe_script(mut builder: script::Builder, tick: String, amt: String) -> bitcoin::ScriptBuf { 
  let content_type: Vec<u8> = b"text/plain;charset=utf-8".to_vec();
  builder = builder
    .push_opcode(opcodes::OP_FALSE)
    .push_opcode(opcodes::all::OP_IF)
    .push_slice(PROTOCOL_ID)
    .push_slice(CONTENT_TYPE_TAG)
    .push_slice(PushBytesBuf::try_from(content_type).unwrap())
    .push_slice(&[]);
  let inscribe_transfer_object = InscribeTransfer::new(tick.clone(), amt.clone());
  let inscribe_transfer_bytes = serde_json::to_string(&inscribe_transfer_object).unwrap().as_bytes().to_vec();
  builder = builder
    .push_slice(PushBytesBuf::try_from(inscribe_transfer_bytes).unwrap())
    .push_opcode(opcodes::all::OP_ENDIF);
  builder.into_script()
}

pub(crate) fn build_reveal_transaction(secret_key_str: &str, utxo: UnspentOutputTransaction, token: String, token_amount_in_normal_unit: String) -> String {
  let secret_key = SecretKey::from_str(secret_key_str).unwrap();
  let secp256k1 = Secp256k1::new();
  let key_pair = UntweakedKeyPair::from_secret_key(&secp256k1, &secret_key);
  let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
  let public_key_script = ScriptBuf::builder()
    .push_slice(&public_key.serialize())
    .push_opcode(opcodes::all::OP_CHECKSIG);
  let reveal_script = build_inscribe_script(public_key_script, token, token_amount_in_normal_unit);
  let taproot_spend_info = TaprootBuilder::new()
    .add_leaf(0, reveal_script.clone())
    .expect("adding leaf should work")
    .finalize(&secp256k1, public_key)
    .expect("finalizing taproot builder should work");
  let control_block = taproot_spend_info.control_block(&(reveal_script.clone(), LeafVersion::TapScript));
  let commit_tx_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), Network::Bitcoin);
  let destination = Address::from_str("bc1pah6p83rhsz0m7ytn833lf0melwcxurtnhsj7naslv4yp7j8xrljsnevxk3").unwrap();
  let reveal_tx = Transaction {
    input: vec![TxIn {
      previous_output: bitcoin::OutPoint { txid: Txid::from_str(utxo.transaction_id.as_str()).unwrap(), vout: utxo.output_index },
      script_sig: script::Builder::new().into_script(),
      witness: Witness::new(),
      sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    }],
    output: vec![TxOut {
      script_pubkey: destination.payload.script_pubkey(),
      value: 546,
    }],
    lock_time: LockTime::ZERO,
    version: 1,
  };

  let mut reveal_tx = reveal_tx.clone();

  let output_to_sign = TxOut {
    script_pubkey: commit_tx_address.script_pubkey(),
    value: utxo.amount_in_base_unit,
  };

  reveal_tx.input[0].witness.push(
    Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
      .unwrap()
      .as_ref(),
  );
  reveal_tx.input[0].witness.push(reveal_script.clone());
  reveal_tx.input[0].witness.push(&control_block.clone().expect("REASON").serialize());

  let mut sighash_cache = SighashCache::new(&mut reveal_tx);

  let signature_hash = sighash_cache
    .taproot_script_spend_signature_hash(
      0,
      &Prevouts::All(&[output_to_sign]),
      TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
      TapSighashType::Default,
    )
    .expect("signature hash should compute");

  let signature = secp256k1.sign_schnorr(
    &secp256k1::Message::from_slice(signature_hash.as_ref())
      .expect("should be cryptographically secure hash"),
    &key_pair,
  );
  let signature_as_ref = signature.as_ref();
  let mut witness = Witness::new();
  witness.push(signature_as_ref);
  witness.push(reveal_script.clone());
  witness.push(&control_block.expect("REASON").serialize());
  reveal_tx.input[0].witness = witness.clone();
  let serialized_signed_txn = bitcoin::consensus::encode::serialize(&reveal_tx);
  to_hex_string(serialized_signed_txn)
}

pub fn to_hex_string(bytes: Vec<u8>) -> String {
  let strs: Vec<String> = bytes.iter()
                               .map(|b| format!("{:02X}", b))
                               .collect();
  strs.join("")
}
