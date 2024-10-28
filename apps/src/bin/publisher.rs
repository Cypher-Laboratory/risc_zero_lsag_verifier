// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This application demonstrates how to send an off-chain proof request
// to the Bonsai proving service and publish the received proofs directly
// to your deployed app contract.

use alloy::{
    network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
};
use alloy_primitives::{Address, U256};
use anyhow::Result;
use clap::Parser;
use methods::LSAG_VERIFIER_ELF;
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use url::Url;

alloy::sol!(
    #[sol(rpc, all_derives)]
    "../contracts/ILsagVerifier.sol"
);

/// Arguments of the publisher CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Ethereum chain ID
    #[clap(long)]
    chain_id: u64,

    /// Ethereum Node endpoint.
    #[clap(long, env)]
    eth_wallet_private_key: PrivateKeySigner,

    /// Ethereum Node endpoint.
    #[clap(long)]
    rpc_url: Url,

    /// Application's contract address on Ethereum
    #[clap(long)]
    contract: Address,
}

fn main() -> Result<()> {
    env_logger::init();
    // Parse CLI Arguments: The application starts by parsing command-line arguments provided by the user.
    let args = Args::parse();

    // Create an alloy provider for that private key and URL.
    let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.rpc_url);

    let input = "eyJtZXNzYWdlIjoiSGVsbG8gV29ybGQiLCJyaW5nIjpbIjAyMjE4NjljYTNhZTMzYmUzYTczMjdlOWEwMjcyMjAzYWZhNzJjNTJhNTQ2MGNlYjlmNGE1MDkzMDUzMWJkOTI2YSIsIjAzNDI4ZTAyMGYxODRiNzBjYTkzMWE5MTA4NWFjMWMyMzM4MjdhNDFkODUxNmE0YjY0NTVlMjIxZTYzN2M0ZGUwZiIsIjAzNDM4ZmJmMzc3NmNjMjRlMjUzNTgyMjU0NGYxNGQ3YjA1N2Q4OTU3YzcyNjc2MDE4MDA1MmNkYTdiOGJhNmM4MyIsIjAzNTBjMWJkNjRjMzA4N2Y2NWY0ODE3MTdlZTRhNWJkZmJiYTRmMDYwMzE0OTkzZjFlMTVjMGRiMjk3NDhiOGRjMiJdLCJjIjoiM2M3ZDBhYzE4YjBlYWU4N2M1OTFjMGM5ZWRkOWE3ZDU3YjI5ZWUxZDhiNzZlYTFjOGM1NjAxMDQ3MGMwZDViMiIsInJlc3BvbnNlcyI6WyIxOWUzNGNjOTc5Y2E1YWMzYTk2MThkMGNlZThmYjdmNzRlMmY4MzA5MmY2ZDZmOTUyZTA3OWYxMzY1MmNlNjM2IiwiYjRkZGE5ZTc4YzA4OTliYjFjYmNkYTVjMjhiYWRiZjYwYWIzMDc1N2MyZjVhMWIxNWQwZDliNmQ1MzdhMTMwMSIsIjJhY2Q4ZWIzMzZhZjU5YzIwMTVhNDljMGJlMWZhZmE3Yzk0ODRmYWQ4YmY3MmFmYjZjYmIwYzgzMDhhOGUxODUiLCI1Y2IzNWY3OWVmYzBmODEwYTI0NTMxYjU0YWM0NThiNjZkMTZlNzNhMTdjOWEyY2IxYTkyN2QzYzI1YTNkMDY4Il0sImN1cnZlIjoie1wiY3VydmVcIjpcIlNFQ1AyNTZLMVwifSIsImtleUltYWdlIjoiMDJlN2ZmMzQ5MGVlN2RiMzM3NTBmZTlhNzA5MWQ4MmRjYTk1MmU2ZDIyYTdmZDRkZjk3ZDBjYmY4ZjdjYjQ2YWQyIiwibGlua2FiaWxpdHlGbGFnIjoibGlua2FiaWxpdHkiLCJjb25maWciOnsiaGFzaCI6InNoYTI1NiJ9fQ==";

    let env = ExecutorEnv::builder().write(&input).unwrap().build()?;

    let receipt = default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            LSAG_VERIFIER_ELF,
            &ProverOpts::groth16(),
        )?
        .receipt;

    let seal = encode_seal(&receipt)?;
    let journal = receipt.journal.bytes.clone();
    let partial_ring_signature = ILsagVerifier::PartialRingSignatureData {
        message: "Hello World".to_string(),
        linkabilityFlag: "linkability".to_string(),
        ring: vec![
            U256::from_str_radix(
                "15164162595175125008547705889856181828932143716710538299042410382956573856362",
                10,
            )
            .unwrap(),
            U256::from_str_radix(
                "30103554500144535254965021336757008479704861502777924021458799636567575289359",
                10,
            )
            .unwrap(),
            U256::from_str_radix(
                "30558939714202291090863029727820829993227403204286654734430544819396481281155",
                10,
            )
            .unwrap(),
            U256::from_str_radix(
                "36527336516757141982692764653028488263347504639791543174831352430519439297986",
                10,
            )
            .unwrap(),
        ],
        keyImage: U256::from_str_radix(
            "104935176822411412320960095276207223758135305498561321901980579976923376282322",
            10,
        )
        .unwrap(),
    };

    let contract = ILsagVerifier::new(args.contract, provider);
    let call_builder = contract.partialLsagVerification(
        seal.clone().into(),
        journal.clone().into(),
        partial_ring_signature.clone(),
    );

    //set up async runtime with tokio
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        match call_builder.call().await {
            Ok(value) => {
                println!("Raw return value: {:?}", value);
                Ok(value)
            }
            Err(e) => {
                println!("Error details: {:?}", e);
                Err(e)
            }
        }
    })?;
    Ok(())
}
