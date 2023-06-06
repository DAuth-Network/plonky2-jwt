use anyhow::Result;
use log::LevelFilter;

use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig, KeccakGoldilocksConfig};
use plonky2_jwt::circuit::{prove, verify, recursive::prove_recursive};

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Info);
    builder.try_init()?;

   {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let jwt = "{\"iss\":\"https://dev-9h47ajc9.us.au111th0666.com/\",\"sub\":\"twitter|33783412\",\"aud\":\"T15e646b4uhAryyoj4GNRon6zs4MrHFV\",\"iat\":1639173028,\"exp\":1639209028,\"nonce\":\"44017a89\"}";
        let credential = "twitter|33783412";

        let (verifier, proof, jwt_hash, credential_hash) = prove(&jwt.as_bytes(), &credential.as_bytes(), false).expect("fail to proof");

        log::info!("verifier len: {:?} - proof len: {:?}", verifier.len(), proof.len());
        log::info!("jwt hash: {:?} - credential hash: {:?}", hex::encode(&jwt_hash), hex::encode(&credential_hash));
        verify::<F, C, D>(&verifier, &proof)
    }?;

    {
        const D: usize = 2;
        type KC = KeccakGoldilocksConfig;
        type F = <KC as GenericConfig<D>>::F;

        let jwt = "{\"iss\":\"https://dev-9h47ajc9.us.au111th0666.com/\",\"sub\":\"twitter|33783412\",\"aud\":\"T15e646b4uhAryyoj4GNRon6zs4MrHFV\",\"iat\":1639173028,\"exp\":1639209028,\"nonce\":\"44017a89\"}";
        let credential = "twitter|33783412";

        let (verifier, proof, jwt_hash, credential_hash) = prove_recursive(&jwt.as_bytes(), &credential.as_bytes()).expect("fail to proof");

        log::info!("verifier len: {:?} - proof len: {:?}", verifier.len(), proof.len());
        log::info!("jwt hash: {:?} - credential hash: {:?}", hex::encode(&jwt_hash), hex::encode(&credential_hash));
        verify::<F, KC, D>(&verifier, &proof)
    }?;

    Ok(())
}
