//! Experimental public receipt for fixed CSV/hashlock legacy Script profiles.
//! Network and application tags are domain separators, not consensus validation.
use shinigami_engine::engine::EngineImpl;
use shinigami_engine::hash_cache::HashCacheImpl;
use shinigami_engine::transaction::{EngineInternalTransactionImpl, UTXO};
use shinigami_utils::hash::double_sha256;

const FLAGS: u32 = 0x518;
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

fn check_script_profile(request: @Request) {
    // Keep all signature and Taproot branches unreachable in this pilot.
    // ScriptSig is separately required to be push-only by FLAGS.
    if *request.application == 1 {
        assert(request.prevout_script.len() == 4, 'CSV profile length');
        assert(request.prevout_script[0] == 0x5a, 'CSV delay constant');
        assert(request.prevout_script[1] == 0xb2, 'CSV opcode');
        assert(request.prevout_script[2] == 0x75, 'CSV drop');
        assert(request.prevout_script[3] == 0x51, 'CSV true');
    } else {
        assert(request.prevout_script.len() == 35, 'hashlock length');
        assert(request.prevout_script[0] == 0xa8, 'hashlock SHA256 opcode');
        assert(request.prevout_script[1] == 0x20, 'hashlock digest push');
        assert(request.prevout_script[34] == 0x87, 'hashlock EQUAL opcode');
    }
}

#[executable]
pub fn main(request: Request) -> Receipt {
    assert(request.network == 3, 'regtest only');
    assert(request.application == 1 || request.application == 2, 'unknown application');
    assert(request.raw_transaction.len() <= 4096, 'transaction budget');
    assert(request.prevout_script.len() <= 1024, 'script budget');
    assert(request.prevout_amount <= MAX_MONEY, 'invalid prevout amount');
    check_script_profile(@request);
    let amount: i64 = request.prevout_amount.try_into().unwrap();
    let mut transaction = EngineInternalTransactionImpl::deserialize(
        request.raw_transaction.clone(), 0,
        array![UTXO { amount, pubkey_script: request.prevout_script.clone(),
                     block_height: request.prevout_height }],
    );
    assert(transaction.transaction_inputs.len() == 1, 'one input required');
    assert(!transaction.is_coinbase(), 'coinbase unsupported');
    assert(transaction.transaction_outputs.len() > 0, 'output required');
    assert(transaction.transaction_outputs.len() <= 8, 'output budget');
    assert(transaction.transaction_inputs[0].witness.is_empty(), 'legacy input only');
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
#[cfg(test)]
mod hash_tests;

#[cfg(test)]
mod policy_tests {
    use super::{Request, check_script_profile};
    #[test]
    #[should_panic]
    fn signatures_are_outside_the_profile() {
        let mut script: ByteArray = "";
        script.append_byte(0xac);
        let request = Request {
            network: 3, application: 1, request_id: 1,
            raw_transaction: "", prevout_amount: 1000,
            prevout_script: script, prevout_height: 100,
        };
        check_script_profile(@request);
    }
}
