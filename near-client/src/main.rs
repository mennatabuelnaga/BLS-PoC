use std::ops::Mul;

use bls_sig::hash_to_try_and_increment;
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_jsonrpc_primitives::types::transactions::TransactionInfo;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction};
use near_primitives::types::BlockReference;
use near_primitives::borsh::BorshSerialize;
use serde_json::json;
use tokio::time;

use near_jsonrpc_client::{methods, JsonRpcClient};
use zeropool_bn::{Fr, G2, Group};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let client = JsonRpcClient::connect("https://rpc.testnet.near.org");

    let signer_account_id = "mennat0.testnet".parse()?;
    let signer_secret_key = "ed25519:4uYCFHpffwwZc4fb9x8yVCz3KYYUwKmcRT1RmHTjirokPGZ48DiJKkhCTpy3t8T6QwRwsSyfAmxQwmQmkGgEzEve".parse()?;

    let signer = near_crypto::InMemorySigner::from_secret_key(signer_account_id, signer_secret_key);
    let view = client
    .call(methods::query::RpcQueryRequest {
        block_reference: BlockReference::latest(),
        request: near_primitives::views::QueryRequest::ViewAccount {
            account_id: signer.account_id.clone(),
        },
    })
    .await?;

    let balance_before = match view.kind {
        QueryResponseKind::ViewAccount(account_view) => account_view.amount,
        _ => Err("failed to fetch account balance")?,
    };


    let access_key_query_response = client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: signer.account_id.clone(),
                public_key: signer.public_key.clone(),
            },
        })
        .await?;


    


    let current_nonce = match access_key_query_response.kind {
        QueryResponseKind::AccessKey(access_key) => access_key.nonce,
        _ => Err("failed to extract current nonce")?,
    };

    let rng = &mut rand::thread_rng();

    let sk: Fr = Fr::random(rng);
    let pk_g2_vec = (G2::one().mul(sk)).try_to_vec().expect("pk");
    let msg = "hello".as_bytes();
    let msg_hash_g1 = hash_to_try_and_increment(msg).unwrap();
    let msg_hash_g1_vec = msg_hash_g1.try_to_vec().unwrap();
    
    let sig_g1 = msg_hash_g1.mul(sk);
    let sig_g1_vec = sig_g1.try_to_vec().unwrap();

    

    // let transaction = Transaction {
    //     signer_id: signer.account_id.clone(),
    //     public_key: signer.public_key.clone(),
    //     nonce: current_nonce + 1,
    //     receiver_id: "altbn128.mennat0.testnet".parse()?,
    //     block_hash: access_key_query_response.block_hash,
    //     actions: vec![Action::FunctionCall(FunctionCallAction {
    //         method_name: "verify_sig".to_string(),
    //         args: json!({
    //             "message_hash": msg_hash_g1_vec,
    //             "signature": sig_g1_vec,
    //             "public_key": pk_g2_vec
    //         })
    //         .to_string()
    //         .into_bytes(),
    //         gas: 300_000_000_000_000, // 300 TeraGas
    //         deposit: 0,
    //     })],
    // };

    let transaction = Transaction {
        signer_id: signer.account_id.clone(),
        public_key: signer.public_key.clone(),
        nonce: current_nonce + 1,
        receiver_id: "altbn128.mennat0.testnet".parse()?,
        block_hash: access_key_query_response.block_hash,
        actions: vec![Action::FunctionCall(FunctionCallAction {
            method_name: "verify_sig2".to_string(),
            args: json!({
                "message": msg.to_vec(),
                "signature": sig_g1_vec,
                "public_key": pk_g2_vec
            })
            .to_string()
            .into_bytes(),
            gas: 300_000_000_000_000, // 300 TeraGas
            deposit: 0,
        })],
    };

    let request = methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest {
        signed_transaction: transaction.sign(&signer),
    };

    let sent_at = time::Instant::now();
    let tx_hash = client.call(request).await?;

    loop {
        let response = client
            .call(methods::tx::RpcTransactionStatusRequest {
                transaction_info: TransactionInfo::TransactionId {
                    hash: tx_hash,
                    account_id: signer.account_id.clone(),
                },
            })
            .await;
        let received_at = time::Instant::now();
        let delta = (received_at - sent_at).as_secs();

        if delta > 60 {
            Err("time limit exceeded for the transaction to be recognized")?;
        }
        

        match response {
            Err(err) => match err.handler_error() {
                Some(methods::tx::RpcTransactionError::UnknownTransaction { .. }) => {
                    time::sleep(time::Duration::from_secs(2)).await;
                    continue;
                }
                _ => Err(err)?,
            },
            Ok(response) => {
                println!("response gotten after: {}s", delta);
                // println!("response: {:?}", response);

                println!("tokens_burnt: {:#?}", response.transaction_outcome.outcome.tokens_burnt);
                println!("gas_burnt: {:#?}", response.transaction_outcome.outcome.gas_burnt);
                println!("status: {:#?}", response.status);

                let view = client
                .call(methods::query::RpcQueryRequest {
                    block_reference: BlockReference::latest(),
                    request: near_primitives::views::QueryRequest::ViewAccount {
                        account_id: signer.account_id.clone(),
                    },
                })
                .await?;

                let current_balance = match view.kind {
                    QueryResponseKind::ViewAccount(account_view) => account_view.amount,
                    _ => Err("failed to fetch account balance")?,
                };

                println!("Cost: {:?}", balance_before - current_balance);

                break;
            }
        }
    }

    Ok(())
}


// deployment storage costs ~ 19 NEAR


// calling verify_sig costs ~ 
// tokens_burnt: 243007196850800000000 ~ 0.00024300719
// gas_burnt: 2430071968508 
// Cost: 2560513941875200000000 ~ 0.00256051394



// calling verify_sig2 costs ~ 
// tokens_burnt: 242960242236800000000 ~ 0.00024296024
// gas_burnt: 2429602422368 
// Cost: 2675535682509700000000 ~ 0.00267553568