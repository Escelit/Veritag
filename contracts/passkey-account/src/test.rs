extern crate std;

use super::*;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::testutils::Address as _;

fn generate_p256_keypair(env: &Env, seed_byte: u8) -> (SigningKey, BytesN<65>) {
    let mut secret_bytes = [seed_byte; 32];
    secret_bytes[0] = seed_byte.wrapping_add(1);
    let signing_key = SigningKey::from_bytes((&secret_bytes).into()).unwrap();
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let bytes_slice = encoded.as_bytes();
    let mut pubkey_arr = [0u8; 65];
    pubkey_arr.copy_from_slice(bytes_slice);
    (signing_key, BytesN::from_array(env, &pubkey_arr))
}

fn sign_webauthn_challenge(
    env: &Env,
    signing_key: &SigningKey,
    credential_id: &Bytes,
    challenge: &[u8; 32],
    flags: u8,
) -> WebAuthnCredential {
    let b64_challenge = encode_base64url_32(challenge);
    let challenge_str = core::str::from_utf8(&b64_challenge).unwrap();
    let client_json_str = std::format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://veritag.stellar.org","crossOrigin":false}}"#,
        challenge_str
    );

    let mut auth_data = [0u8; 37];
    // rpIdHash = SHA256("veritag.stellar.org")
    let rp_hash = Sha256::digest(b"veritag.stellar.org");
    auth_data[..32].copy_from_slice(&rp_hash);
    auth_data[32] = flags;
    auth_data[33..37].copy_from_slice(&1u32.to_be_bytes());

    let client_data_hash = Sha256::digest(client_json_str.as_bytes());
    let mut signed_bytes = std::vec::Vec::with_capacity(69);
    signed_bytes.extend_from_slice(&auth_data);
    signed_bytes.extend_from_slice(&client_data_hash);

    let msg_digest = Sha256::digest(&signed_bytes);
    let sig: Signature = signing_key.sign_prehash(&msg_digest).unwrap();
    let sig_norm = sig.normalize_s().unwrap_or(sig);
    let sig_bytes = sig_norm.to_bytes();
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    WebAuthnCredential {
        credential_id: credential_id.clone(),
        authenticator_data: Bytes::from_slice(env, &auth_data),
        client_data_json: Bytes::from_slice(env, client_json_str.as_bytes()),
        signature: BytesN::from_array(env, &sig_arr),
    }
}

#[test]
fn test_webauthn_check_auth_success_and_rejections() {
    let env = Env::default();
    let (signing_key, pubkey) = generate_p256_keypair(&env, 7);
    let cred_id = Bytes::from_slice(&env, b"cred-primary-001");
    let recovery = Address::generate(&env);

    let contract_id = env.register(
        PasskeyAccountContract,
        (cred_id.clone(), pubkey.clone(), Some(recovery.clone())),
    );
    let client = PasskeyAccountContractClient::new(&env, &contract_id);

    assert_eq!(client.get_passkey(&cred_id), Some(pubkey));
    assert_eq!(client.get_passkey_count(), 1);
    assert_eq!(client.get_recovery_signer(), Some(recovery));

    let payload_bytes = [0x42u8; 32];
    let payload_hash: Hash<32> = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, &payload_bytes));
    let challenge_arr = nonce_challenge(&payload_hash, 0);

    // 1. Valid WebAuthn assertion with UP (0x01) + UV (0x04) = 0x05
    let valid_cred = sign_webauthn_challenge(&env, &signing_key, &cred_id, &challenge_arr, 0x05);
    env.as_contract(&contract_id, || {
        let res = PasskeyAccountContract::__check_auth(
            env.clone(),
            payload_hash.clone(),
            AccountSignature::WebAuthn(valid_cred),
            Vec::new(&env),
        );
        assert_eq!(res, Ok(()));
    });

    assert_eq!(client.get_nonce(), 1);

    // 2. Reject when User Present flag (bit 0) is 0
    let no_up_cred = sign_webauthn_challenge(&env, &signing_key, &cred_id, &challenge_arr, 0x04);
    env.as_contract(&contract_id, || {
        let res = PasskeyAccountContract::__check_auth(
            env.clone(),
            payload_hash.clone(),
            AccountSignature::WebAuthn(no_up_cred),
            Vec::new(&env),
        );
        assert_eq!(res, Err(AccountError::UserNotPresent));
    });

    // 3. Reject when challenge in clientDataJSON does not match signature_payload
    let wrong_challenge = [0x99u8; 32];
    let wrong_challenge_cred =
        sign_webauthn_challenge(&env, &signing_key, &cred_id, &wrong_challenge, 0x05);
    env.as_contract(&contract_id, || {
        let res = PasskeyAccountContract::__check_auth(
            env.clone(),
            payload_hash.clone(),
            AccountSignature::WebAuthn(wrong_challenge_cred),
            Vec::new(&env),
        );
        assert_eq!(res, Err(AccountError::ChallengeMismatch));
    });

    // 4. Reject when credential_id is unknown
    let unknown_id = Bytes::from_slice(&env, b"cred-unknown");
    let unknown_cred =
        sign_webauthn_challenge(&env, &signing_key, &unknown_id, &challenge_arr, 0x05);
    env.as_contract(&contract_id, || {
        let res = PasskeyAccountContract::__check_auth(
            env.clone(),
            payload_hash.clone(),
            AccountSignature::WebAuthn(unknown_cred),
            Vec::new(&env),
        );
        assert_eq!(res, Err(AccountError::UnknownCredential));
    });
}

#[test]
fn test_passkey_rotation_and_recovery_guards() {
    let env = Env::default();
    env.mock_all_auths();

    let (_sk1, pk1) = generate_p256_keypair(&env, 11);
    let (_sk2, pk2) = generate_p256_keypair(&env, 22);
    let cred1 = Bytes::from_slice(&env, b"cred-1");
    let cred2 = Bytes::from_slice(&env, b"cred-2");

    let contract_id = env.register(
        PasskeyAccountContract,
        (cred1.clone(), pk1.clone(), Option::<Address>::None),
    );
    let client = PasskeyAccountContractClient::new(&env, &contract_id);

    // Cannot remove the only passkey when no recovery signer is configured
    let err = client.try_remove_passkey(&cred1);
    assert_eq!(err, Err(Ok(AccountError::CannotRemoveLastAuthMethod)));

    // Add second passkey, then remove first passkey
    client.add_passkey(&cred2, &pk2);
    assert_eq!(client.get_passkey_count(), 2);
    client.remove_passkey(&cred1);
    assert_eq!(client.get_passkey_count(), 1);
    assert_eq!(client.get_passkey(&cred1), None);
    assert_eq!(client.get_passkey(&cred2), Some(pk2));

    // Configure recovery signer, then verify Recovery auth works
    let recovery = Address::generate(&env);
    client.set_recovery_signer(&Some(recovery.clone()));
    assert_eq!(client.get_recovery_signer(), Some(recovery));

    let payload_hash: Hash<32> = env.crypto().sha256(&Bytes::from_slice(&env, b"recover-me"));
    env.as_contract(&contract_id, || {
        let res = PasskeyAccountContract::__check_auth(
            env.clone(),
            payload_hash,
            AccountSignature::Recovery,
            Vec::new(&env),
        );
        assert_eq!(res, Ok(()));
    });
}

// Construct the client challenge independently from the contract implementation.
fn nonce_challenge(payload: &Hash<32>, nonce: u64) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(payload.to_array());
    digest.update(nonce.to_be_bytes());
    digest.finalize().into()
}

fn check_webauthn(
    env: &Env,
    contract_id: &Address,
    payload: &Hash<32>,
    credential: WebAuthnCredential,
) -> Result<(), Result<AccountError, soroban_sdk::InvokeError>> {
    use soroban_sdk::IntoVal;
    env.try_invoke_contract_check_auth::<AccountError>(
        contract_id,
        &payload.clone().into(),
        AccountSignature::WebAuthn(credential).into_val(env),
        &Vec::new(env),
    )
}

#[test]
fn test_nonce_replay_and_sequential_authorizations() {
    let env = Env::default();
    let (signing_key, public_key) = generate_p256_keypair(&env, 31);
    let credential_id = Bytes::from_slice(&env, b"nonce-credential");
    let contract_id = env.register(
        PasskeyAccountContract,
        (credential_id.clone(), public_key, Option::<Address>::None),
    );
    let client = PasskeyAccountContractClient::new(&env, &contract_id);
    let payload = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, b"same-authorization-payload"));
    assert_eq!(client.get_nonce(), 0);

    let first = sign_webauthn_challenge(
        &env,
        &signing_key,
        &credential_id,
        &nonce_challenge(&payload, 0),
        0x05,
    );
    let second = sign_webauthn_challenge(
        &env,
        &signing_key,
        &credential_id,
        &nonce_challenge(&payload, 1),
        0x05,
    );
    // A future signature cannot execute out of order and does not consume the current nonce.
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, second.clone()),
        Err(Ok(AccountError::ChallengeMismatch))
    );
    assert_eq!(client.get_nonce(), 0);
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, first.clone()),
        Ok(())
    );
    assert_eq!(client.get_nonce(), 1);
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, first.clone()),
        Err(Ok(AccountError::ChallengeMismatch))
    );
    assert_eq!(client.get_nonce(), 1);
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, second.clone()),
        Ok(())
    );
    assert_eq!(client.get_nonce(), 2);
    for stale in [first, second] {
        assert_eq!(
            check_webauthn(&env, &contract_id, &payload, stale),
            Err(Ok(AccountError::ChallengeMismatch))
        );
        assert_eq!(client.get_nonce(), 2);
    }
}

#[test]
fn test_nonce_replay_rejections_do_not_advance_nonce() {
    let env = Env::default();
    let (signing_key, public_key) = generate_p256_keypair(&env, 32);
    let credential_id = Bytes::from_slice(&env, b"rejection-credential");
    let contract_id = env.register(
        PasskeyAccountContract,
        (credential_id.clone(), public_key, Option::<Address>::None),
    );
    let client = PasskeyAccountContractClient::new(&env, &contract_id);
    let payload = env.crypto().sha256(&Bytes::from_slice(&env, b"payload"));
    let challenge = nonce_challenge(&payload, 0);
    let valid = sign_webauthn_challenge(&env, &signing_key, &credential_id, &challenge, 0x05);

    // Signing the raw Soroban hash without the account nonce is no longer valid.
    let raw = sign_webauthn_challenge(
        &env,
        &signing_key,
        &credential_id,
        &payload.to_array(),
        0x05,
    );
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, raw),
        Err(Ok(AccountError::ChallengeMismatch))
    );
    assert_eq!(client.get_nonce(), 0);

    let mut short = valid.clone();
    short.authenticator_data = Bytes::from_slice(&env, &[0u8; 36]);
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, short),
        Err(Ok(AccountError::InvalidAuthenticatorData))
    );
    assert_eq!(client.get_nonce(), 0);

    let no_up = sign_webauthn_challenge(&env, &signing_key, &credential_id, &challenge, 0x04);
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, no_up),
        Err(Ok(AccountError::UserNotPresent))
    );
    assert_eq!(client.get_nonce(), 0);

    let mut unknown = valid.clone();
    unknown.credential_id = Bytes::from_slice(&env, b"unknown");
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, unknown),
        Err(Ok(AccountError::UnknownCredential))
    );
    assert_eq!(client.get_nonce(), 0);

    // The challenge matches, but a different private key signed it.
    let (wrong_key, _) = generate_p256_keypair(&env, 33);
    let bad_signature = sign_webauthn_challenge(&env, &wrong_key, &credential_id, &challenge, 0x05);
    assert!(check_webauthn(&env, &contract_id, &payload, bad_signature).is_err());
    assert_eq!(client.get_nonce(), 0);
    assert_eq!(check_webauthn(&env, &contract_id, &payload, valid), Ok(()));
    assert_eq!(client.get_nonce(), 1);
}

#[test]
fn test_nonce_replay_is_shared_across_passkeys() {
    let env = Env::default();
    env.mock_all_auths();
    let (key1, public_key1) = generate_p256_keypair(&env, 34);
    let (key2, public_key2) = generate_p256_keypair(&env, 35);
    let credential1 = Bytes::from_slice(&env, b"credential-1");
    let credential2 = Bytes::from_slice(&env, b"credential-2");
    let contract_id = env.register(
        PasskeyAccountContract,
        (credential1.clone(), public_key1, Option::<Address>::None),
    );
    let client = PasskeyAccountContractClient::new(&env, &contract_id);
    client.add_passkey(&credential2, &public_key2);
    let payload = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, b"shared-nonce"));
    let first = sign_webauthn_challenge(
        &env,
        &key1,
        &credential1,
        &nonce_challenge(&payload, 0),
        0x05,
    );
    let stale_second = sign_webauthn_challenge(
        &env,
        &key2,
        &credential2,
        &nonce_challenge(&payload, 0),
        0x05,
    );
    assert_eq!(check_webauthn(&env, &contract_id, &payload, first), Ok(()));
    assert_eq!(client.get_nonce(), 1);
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, stale_second),
        Err(Ok(AccountError::ChallengeMismatch))
    );
    let fresh_second = sign_webauthn_challenge(
        &env,
        &key2,
        &credential2,
        &nonce_challenge(&payload, 1),
        0x05,
    );
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, fresh_second),
        Ok(())
    );
    assert_eq!(client.get_nonce(), 2);
}

#[test]
fn test_nonce_replay_overflow_fails_without_wrapping() {
    let env = Env::default();
    let (key, public_key) = generate_p256_keypair(&env, 36);
    let credential_id = Bytes::from_slice(&env, b"overflow-credential");
    let contract_id = env.register(
        PasskeyAccountContract,
        (credential_id.clone(), public_key, Option::<Address>::None),
    );
    let client = PasskeyAccountContractClient::new(&env, &contract_id);
    env.as_contract(&contract_id, || {
        env.storage()
            .instance()
            .set(&DataKey::Nonce, &(u64::MAX - 1))
    });
    let payload = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, b"nonce-limit"));
    let last = sign_webauthn_challenge(
        &env,
        &key,
        &credential_id,
        &nonce_challenge(&payload, u64::MAX - 1),
        0x05,
    );
    assert_eq!(check_webauthn(&env, &contract_id, &payload, last), Ok(()));
    assert_eq!(client.get_nonce(), u64::MAX);
    let exhausted = sign_webauthn_challenge(
        &env,
        &key,
        &credential_id,
        &nonce_challenge(&payload, u64::MAX),
        0x05,
    );
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, exhausted),
        Err(Ok(AccountError::NonceExhausted))
    );
    assert_eq!(client.get_nonce(), u64::MAX);
}

#[test]
fn test_nonce_replay_recovery_advances_shared_nonce() {
    use soroban_sdk::IntoVal;

    let env = Env::default();
    env.mock_all_auths();
    let (key, public_key) = generate_p256_keypair(&env, 37);
    let credential_id = Bytes::from_slice(&env, b"recovery-credential");
    let recovery = Address::generate(&env);
    let contract_id = env.register(
        PasskeyAccountContract,
        (credential_id.clone(), public_key, Some(recovery)),
    );
    let client = PasskeyAccountContractClient::new(&env, &contract_id);
    let payload = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, b"recovery-payload"));
    let stale = sign_webauthn_challenge(
        &env,
        &key,
        &credential_id,
        &nonce_challenge(&payload, 0),
        0x05,
    );
    env.as_contract(&contract_id, || {
        assert_eq!(
            PasskeyAccountContract::__check_auth(
                env.clone(),
                payload.clone(),
                AccountSignature::Recovery,
                Vec::new(&env)
            ),
            Ok(())
        );
    });
    assert_eq!(client.get_nonce(), 1);
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, stale),
        Err(Ok(AccountError::ChallengeMismatch))
    );
    let fresh = sign_webauthn_challenge(
        &env,
        &key,
        &credential_id,
        &nonce_challenge(&payload, 1),
        0x05,
    );
    assert_eq!(check_webauthn(&env, &contract_id, &payload, fresh), Ok(()));
    assert_eq!(client.get_nonce(), 2);

    let no_recovery = env.register(
        PasskeyAccountContract,
        (
            credential_id,
            client
                .get_passkey(&Bytes::from_slice(&env, b"recovery-credential"))
                .unwrap(),
            Option::<Address>::None,
        ),
    );
    assert_eq!(
        env.try_invoke_contract_check_auth::<AccountError>(
            &no_recovery,
            &payload.into(),
            AccountSignature::Recovery.into_val(&env),
            &Vec::new(&env)
        ),
        Err(Ok(AccountError::RecoveryNotConfigured))
    );
    assert_eq!(
        PasskeyAccountContractClient::new(&env, &no_recovery).get_nonce(),
        0
    );
}

#[test]
fn test_nonce_replay_rejects_assertion_with_multiple_nonce_challenges() {
    let env = Env::default();
    let (key, public_key) = generate_p256_keypair(&env, 38);
    let credential_id = Bytes::from_slice(&env, b"ambiguous-credential");
    let contract_id = env.register(
        PasskeyAccountContract,
        (credential_id.clone(), public_key, Option::<Address>::None),
    );
    let client = PasskeyAccountContractClient::new(&env, &contract_id);
    let payload = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, b"ambiguous-payload"));
    let current = nonce_challenge(&payload, 0);
    let next = nonce_challenge(&payload, 1);
    let current_b64 = encode_base64url_32(&current);
    let next_b64 = encode_base64url_32(&next);
    let json = std::format!(
        r#"{{"type":"webauthn.get","challenge":"{}","challenge":"{}"}}"#,
        core::str::from_utf8(&current_b64).unwrap(),
        core::str::from_utf8(&next_b64).unwrap()
    );
    let mut credential = sign_webauthn_challenge(&env, &key, &credential_id, &current, 0x05);
    credential.client_data_json = Bytes::from_slice(&env, json.as_bytes());
    let mut signed_data: std::vec::Vec<u8> = credential.authenticator_data.iter().collect();
    signed_data.extend_from_slice(&Sha256::digest(json.as_bytes()));
    let signature: Signature = key.sign_prehash(&Sha256::digest(&signed_data)).unwrap();
    let normalized = signature.normalize_s().unwrap_or(signature);
    let signature_bytes: [u8; 64] = normalized.to_bytes().into();
    credential.signature = BytesN::from_array(&env, &signature_bytes);
    assert_eq!(
        check_webauthn(&env, &contract_id, &payload, credential),
        Err(Ok(AccountError::ChallengeMismatch))
    );
    assert_eq!(client.get_nonce(), 0);
}
