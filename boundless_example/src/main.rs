use alloy::{
    primitives::{Address, B256},
    signers::local::PrivateKeySigner,
    sol_types::SolCall,
};
use anyhow::{Context, Result, anyhow};
use boundless_market::{
    Client, GuestEnvBuilder, StandardStorageProvider,
    contracts::{FulfillmentData, Predicate, Requirements},
    request_builder::{OfferParams, RequirementParams},
    storage::{StorageProviderConfig, TempFileStorageProvider},
};
use guest::{ECHO_ELF, ECHO_ID};
use tracing_subscriber::{EnvFilter, filter::LevelFilter, prelude::*};
use url::Url;
/// Arguments of the publisher CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// URL of the Ethereum RPC endpoint.
    #[clap(short, long, env)]
    rpc_url: Url,
    /// Private key used to interact with the EvenNumber contract.
    #[clap(short, long, env)]
    private_key: PrivateKeySigner,
    /// Storage provider to use
    #[clap(flatten)]
    storage_config: Option<StorageProviderConfig>,
    /// URL where provers can download the program to be proven.
    #[clap(long, env)]
    program_url: Option<Url>,
    #[clap(flatten, next_help_heading = "Boundless Market Deployment")]
    boundless_deployment: Option<boundless_market::Deployment>,

    #[clap(long, default_value = "stark")]
    proof_type: String,
}
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging.
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::from_str("info")?.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    // NOTE: Using a separate `run` function to facilitate testing below.
    run(args).await
}

/// Main logic which creates the Boundless client, executes the proofs and submits the tx.
async fn run(args: Args) -> Result<()> {
    // Create a Boundless client from the provided parameters.
    let client = Client::builder()
        .with_rpc_url(args.rpc_url)
        .with_deployment(args.deployment)
        .with_storage_provider_config(&args.storage_config)?
        .with_private_key(args.private_key)
        .build()
        .await
        .context("failed to build boundless client")?;

    let echo_message = [
        1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32,
    ];

    let blake3_claim_digest =
        shrink_bitvm2::receipt_claim::ShrinkBitvm2ReceiptClaim::ok(ECHO_ID, echo_message.to_vec())
            .claim_digest();

    // Build the request based on whether program URL is provided
    let request = client
        .new_request()
        .with_requirements(
            RequirementParams::builder()
                .predicate(Predicate::claim_digest_match(blake3_claim_digest)),
        )
        .with_offer(
            OfferParams::builder()
                .min_price(alloy::primitives::utils::parse_ether("0.001")?)
                .max_price(alloy::primitives::utils::parse_ether("0.002")?)
                .timeout(1000)
                .lock_timeout(1000),
        )
        .with_stdin(echo_message.as_bytes())
        .with_shrink_bitvm2_proof();

    request = if let Some(program_url) = args.program_url {
        // Use the provided URL
        request.with_program_url(program_url)?
    } else {
        request.with_program(ECHO_ELF)
    };

    let (request_id, expires_at) = client.submit_onchain(request).await?;

    // Wait for the request to be fulfilled. The market will return the journal and seal.
    tracing::info!("Waiting for request {:x} to be fulfilled", request_id);
    let fulfillment = client
        .wait_for_request_fulfillment(
            request_id,
            Duration::from_secs(5), // check every 5 seconds
            expires_at,
        )
        .await?;
    let fulfillment_data = fulfillment.data()?;
    tracing::info!("Fulfillment data: {:?}", fulfillment.data()?);
    tracing::info!("Request {:x} fulfilled", request_id);

    if !matches!(fulfillment_data, FulfillmentData::None) {
        return Err(anyhow!("Fulfillment data should be none"));
    }

    let seal = fulfillment.seal;

    Ok(())
}
