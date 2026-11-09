//! Experimental public receipt for one legacy Bitcoin Script input.
//! Network and application tags are domain separators, not consensus validation.
use shinigami_engine::engine::EngineImpl;
use shinigami_engine::hash_cache::HashCacheImpl;
use shinigami_engine::transaction::{EngineInternalTransactionImpl, UTXO};
use shinigami_utils::hash::double_sha256;

const FLAGS: u32 = 0x518; // CSV, CLTV, minimal pushes, push-only scriptSig.
const MAX_MONEY: u64 = 2100000000000000;

#[derive(Drop, Clone, Serde)]
pub struct Request {
    pub network: u8,
    pub application: u8,
    pub request_id: u256,
    pub raw_transaction: ByteArray,
    pub prevout_amount: u64,
    pub prevout_script: ByteArray,
    pub prevout_height: u32,
}

#[derive(Drop, Serde)]
pub struct Receipt {
    pub domain: felt252,
    pub schema: u32,
    pub scope: u32,
    pub flags: u32,
    pub request: Request,
    pub accepted: bool,
    pub error: felt252,
    pub txid: u256,
}

#[executable]
pub fn main(request: Request) -> Receipt {
    // This laboratory is explicitly restricted to regtest and legacy input 0.
    assert(request.network == 3, 'regtest only');
    assert(request.application == 1 || request.application == 2, 'unknown application');
    assert(request.raw_transaction.len() <= 4096, 'transaction budget');
    assert(request.prevout_script.len() <= 1024, 'script budget');
    assert(request.prevout_amount <= MAX_MONEY, 'invalid prevout amount');
    let amount: i64 = request.prevout_amount.try_into().unwrap();
    let mut transaction = EngineInternalTransactionImpl::deserialize(
        request.raw_transaction.clone(), 0,
        array![UTXO {
            amount,
            pubkey_script: request.prevout_script.clone(),
            block_height: request.prevout_height,
        }],
    );
    assert(transaction.transaction_inputs.len() == 1, 'one input required');
    assert(!transaction.is_coinbase(), 'coinbase unsupported');
    assert(transaction.transaction_outputs.len() > 0, 'output required');
    assert(transaction.transaction_outputs.len() <= 8, 'output budget');
    assert(transaction.transaction_inputs[0].witness.is_empty(), 'legacy input only');
    // Bind exactly the bytes that the engine parsed, including sequence and locktime.
    let canonical = transaction.clone().serialize();
    assert(canonical == request.raw_transaction, 'noncanonical transaction');
    let unsigned = transaction.clone().serialize_no_witness();
    let txid = double_sha256(@unsigned);
    transaction.txid = txid;
    let hash_cache = HashCacheImpl::new(@transaction);
    let result = match EngineImpl::new(
        @request.prevout_script, @transaction, 0, FLAGS, amount, @hash_cache,
    ) {
        Result::Ok(mut engine) => engine.execute(),
        Result::Err(error) => Result::Err(error),
    };
    let (accepted, error) = match result {
        Result::Ok(_) => (true, 0),
        Result::Err(error) => (false, error),
    };
    Receipt {
        domain: 'SHINIGAMI_BITVM3_V1', schema: 1, scope: 1, flags: FLAGS,
        request, accepted, error, txid,
    }
}

#[cfg(test)]
mod tests;
