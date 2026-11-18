use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env, EnvBase, TryFromVal, Val, Vec};

/// Maximum supported Merkle proof depth (supports up to 2^32 units per batch).
pub const MAX_PROOF_DEPTH: u32 = 32;

/// Computes `sha256(data)` as `BytesN<32>`.
pub fn sha256_bytes(env: &Env, data: &Bytes) -> BytesN<32> {
    env.crypto().sha256(data).into()
}

/// Computes `unit_id = sha256(brand_address_xdr || batch_id || serial_hash)`.
///
/// Using `brand.to_xdr(env)` provides canonical domain-separated serialization of the Stellar
/// account or contract address across both Rust Soroban contracts and TypeScript SDK clients.
pub fn compute_unit_id(
    env: &Env,
    brand: &Address,
    batch_id: &BytesN<32>,
    serial_hash: &BytesN<32>,
) -> BytesN<32> {
    let mut payload = brand.to_xdr(env);
    payload.extend_from_array(&batch_id.to_array());
    payload.extend_from_array(&serial_hash.to_array());
    sha256_bytes(env, &payload)
}

/// Computes `leaf = sha256(serial_hash || secret_hash)`.
pub fn compute_leaf(env: &Env, serial_hash: &BytesN<32>, secret_hash: &BytesN<32>) -> BytesN<32> {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&serial_hash.to_array());
    buf[32..].copy_from_slice(&secret_hash.to_array());
    let bytes = Bytes::from_array(env, &buf);
    sha256_bytes(env, &bytes)
}

/// Computes sorted-pair internal node `sha256(min(a, b) || max(a, b))`.
///
/// Sorting sibling pairs eliminates the need to pass directional left/right index vectors
/// alongside `proof: Vec<BytesN<32>>`.
pub fn hash_pair(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
    hash_pair_arrays(env, &a.to_array(), &b.to_array())
}

fn hash_pair_arrays(env: &Env, a: &[u8; 32], b: &[u8; 32]) -> BytesN<32> {
    let mut buf = [0u8; 64];
    if a <= b {
        buf[..32].copy_from_slice(a);
        buf[32..].copy_from_slice(b);
    } else {
        buf[..32].copy_from_slice(b);
        buf[32..].copy_from_slice(a);
    }
    let bytes = Bytes::from_array(env, &buf);
    sha256_bytes(env, &bytes)
}

/// Verifies that `leaf` belongs to the Merkle tree rooted at `merkle_root` using `proof`.
pub fn verify_proof(
    env: &Env,
    merkle_root: &BytesN<32>,
    leaf: &BytesN<32>,
    proof: &Vec<BytesN<32>>,
) -> bool {
    let depth = proof.len() as usize;
    if depth > MAX_PROOF_DEPTH as usize {
        return false;
    }
    if depth == 0 {
        return leaf == merkle_root;
    }

    // Copy the bounded proof's host handles once instead of cloning the Vec and
    // invoking vec_get for every sibling. The same SDK primitive decodes tuples.
    let mut siblings = [Val::VOID.to_val(); MAX_PROOF_DEPTH as usize];
    env.vec_unpack_to_slice(proof.to_object(), &mut siblings[..depth])
        .unwrap();

    let mut computed = leaf.to_array();
    for value in &siblings[..depth - 1] {
        let sibling = <[u8; 32]>::try_from_val(env, value).unwrap();
        computed = hash_pair_arrays(env, &computed, &sibling).to_array();
    }
    // Compare the final host hash directly to avoid copying it and the root.
    let last_sibling = <[u8; 32]>::try_from_val(env, &siblings[depth - 1]).unwrap();
    hash_pair_arrays(env, &computed, &last_sibling) == *merkle_root
}
