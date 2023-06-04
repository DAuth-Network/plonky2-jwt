use anyhow::Result;
use log::LevelFilter;

use plonky2_jwt::circuit::{prove, verify};

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init()?;

    let jwt = "{\"iss\":\"https://dev-9h47ajc9.us.au111th0666.com/\",\"sub\":\"twitter|33783412\",\"aud\":\"T15e646b4uhAryyoj4GNRon6zs4MrHFV\",\"iat\":1639173028,\"exp\":1639209028,\"nonce\":\"44017a89\"}";
    let credential = "twitter|33783412";

    let (verifier, proof, jwt_hash, credential_hash) = prove(&jwt.as_bytes(), &credential.as_bytes()).expect("fail to proof");

    log::info!("verifier len: {:?} - proof len: {:?}", verifier.len(), proof.len());
    log::info!("jwt hash: {:?} - credential hash: {:?}", hex::encode(&jwt_hash), hex::encode(&credential_hash));
    verify(&verifier, &proof)
}
