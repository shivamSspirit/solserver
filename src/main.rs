use actix_web::{web, App, HttpResponse, HttpServer, Result, middleware::Logger};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction
};


use spl_token::{
    instruction as token_instruction
};
use base64;
use bs58;
use std::str::FromStr;


#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: &str) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message.to_string()),
        }
    }
}

// Request structures 
#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

// Response data structures
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignatureData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerificationData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct SolTransferData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenTransferAccount {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct TokenTransferData {
    program_id: String,
    accounts: Vec<TokenTransferAccount>,
    instruction_data: String,
}


fn validate_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    match Pubkey::from_str(pubkey_str) {
        Ok(pk) => Ok(pk),
        Err(_) => Err("Invalid public key format".to_string()),
    }
}

fn validate_secret_key(secret_str: &str) -> Result<Keypair, String> {
    let secret_bytes = match bs58::decode(secret_str).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Err("Invalid secret key format".to_string()),
    };
    
    if secret_bytes.len() != 64 {
        return Err("Invalid secret key length".to_string());
    }
    
    match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => Ok(kp),
        Err(_) => Err("Invalid secret key".to_string()),
    }
}

fn get_associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    spl_associated_token_account::get_associated_token_address(owner, mint)
}

// Endpoint handlers

async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    let response = KeypairData { pubkey, secret };
    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    // Validate the mint authority
    let mint_authority = match validate_pubkey(&req.mint_authority) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e)));
        }
    };

    // Validate the mint pubkey
    let mint = match validate_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e)));
        }
    };

    // Create the initialize mint instruction
    let instruction = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None, // freeze authority is optional
        req.decimals,
    ) {
        Ok(inst) => inst,
        Err(e) => {
            let error_msg = format!("Failed to create instruction: {}", e);
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&error_msg)));
        }
    };

    let accounts: Vec<AccountInfo> = instruction.accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response = InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    let mint = match validate_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let destination = match validate_pubkey(&req.destination) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let authority = match validate_pubkey(&req.authority) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    // Create the mint_to instruction
    let instruction = match token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ) {
        Ok(inst) => inst,
        Err(e) => {
            let error_msg = format!("Failed to create mint instruction: {}", e);
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&error_msg)));
        }
    };

    let accounts: Vec<AccountInfo> = instruction.accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response = InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    if req.message.is_empty() || req.secret.is_empty() {
        return Ok(HttpResponse::BadRequest().json(
            ApiResponse::<()>::error("Missing required fields")
        ));
    }

    // Parse the secret key
    let keypair = match validate_secret_key(&req.secret) {
        Ok(kp) => kp,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    // Sign the message
    let message_bytes = req.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response = SignatureData {
        signature: base64::encode(&signature.as_ref()),
        public_key: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
        message: req.message.clone(),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    // Parse the public key
    let pubkey = match validate_pubkey(&req.pubkey) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    // Decode the signature from base64
    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(
                ApiResponse::<()>::error("Invalid signature format")
            ));
        }
    };

    // Convert to Solana signature type
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(
                ApiResponse::<()>::error("Invalid signature")
            ));
        }
    };

    // Verify the signature
    let message_bytes = req.message.as_bytes();
    let is_valid = signature.verify(pubkey.as_ref(), message_bytes);

    let response = VerificationData {
        valid: is_valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    let from = match validate_pubkey(&req.from) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let to = match validate_pubkey(&req.to) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    if req.lamports == 0 {
        return Ok(HttpResponse::BadRequest().json(
            ApiResponse::<()>::error("Amount must be greater than 0")
        ));
    }

    // Create the transfer instruction
    let instruction = system_instruction::transfer(&from, &to, req.lamports);

    let response = SolTransferData {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts
            .iter()
            .map(|acc| acc.pubkey.to_string())
            .collect(),
        instruction_data: base64::encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    let destination = match validate_pubkey(&req.destination) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let mint = match validate_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    let owner = match validate_pubkey(&req.owner) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e))),
    };

    // Validate amount
    if req.amount == 0 {
        return Ok(HttpResponse::BadRequest().json(
            ApiResponse::<()>::error("Amount must be greater than 0")
        ));
    }

    // Calculate the associated token addresses
    let source_ata = get_associated_token_address(&owner, &mint);
    let dest_ata = get_associated_token_address(&destination, &mint);

    // Create the transfer instruction
    let instruction = match token_instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner,
        &[], // no multisig
        req.amount,
    ) {
        Ok(inst) => inst,
        Err(e) => {
            let error_msg = format!("Failed to create transfer instruction: {}", e);
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(&error_msg)));
        }
    };

    let accounts: Vec<TokenTransferAccount> = instruction.accounts
        .iter()
        .map(|acc| TokenTransferAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    let response = TokenTransferData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    println!("🚀 Starting Solana HTTP Server...");
    println!("📍 Server will be available at: http://127.0.0.1:8080");

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            // Keypair generation
            .route("/keypair", web::post().to(generate_keypair))
            // Token operations
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            // Message signing/verification
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            // Transfer operations
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}