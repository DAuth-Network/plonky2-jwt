use plonky2::hash::hash_types::RichField;
use primitive_types::U256;

pub fn array_to_bits(bytes: &[u8]) -> Vec<bool> {
    let len = bytes.len();
    let mut ret = Vec::new();
    for i in 0..len {
        for j in 0..8 {
            let b = (bytes[i] >> (7 - j)) & 1;
            ret.push(b == 1);
        }
    }
    ret
}

pub fn bits_to_array(bits: &[bool]) -> Vec<u8> {
    let len = bits.len();
    let mut ret = Vec::new();
    let mut offset = 0;

    loop {
        if offset >= len {
            break;
        }

        let mut acc = 0;
        acc += (bits[offset] as u8) << 7;
        acc += (bits[offset + 1] as u8) << 6;
        acc += (bits[offset + 2] as u8) << 5;
        acc += (bits[offset + 3] as u8) << 4;
        acc += (bits[offset + 4] as u8) << 3;
        acc += (bits[offset + 5] as u8) << 2;
        acc += (bits[offset + 6] as u8) << 1;
        acc += bits[offset + 7] as u8;
        ret.push(acc);

        offset += 8;
    }

    ret
}

pub fn find_subsequence(haystack: &[bool], needle: &[bool]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

pub fn find_subsequence_u8(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

pub fn extract_hashes_from_public_inputs<F: RichField>(public_inputs: &[F]) -> ([u8; 32], [u8; 32]) {
    let mut jwt_hash_digest = Vec::new();
    let mut credential_hash_digest = Vec::new();

    let mut jwt_hash = Vec::new();
    let mut credential_hash = Vec::new();

    for i in 0..8 {
        jwt_hash_digest.push(public_inputs[i].to_canonical_u64());
        credential_hash_digest.push(public_inputs[i + 8].to_canonical_u64());
    }

    for i in 0..8 {
        for byte in &jwt_hash_digest[i].to_be_bytes()[4..8] {
            jwt_hash.push(*byte);
        }
        for byte in &credential_hash_digest[i].to_be_bytes()[4..8] {
            credential_hash.push(*byte);
        }
    }

    return (
        jwt_hash.try_into().unwrap(),
        credential_hash.try_into().unwrap(),
    );
}

pub fn sha256_hash_u32_digests(msg: &[u8]) -> [u32; 8] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    [
        u32::from_be_bytes(digest[0..4].try_into().unwrap()),
        u32::from_be_bytes(digest[4..8].try_into().unwrap()),
        u32::from_be_bytes(digest[8..12].try_into().unwrap()),
        u32::from_be_bytes(digest[12..16].try_into().unwrap()),
        u32::from_be_bytes(digest[16..20].try_into().unwrap()),
        u32::from_be_bytes(digest[20..24].try_into().unwrap()),
        u32::from_be_bytes(digest[24..28].try_into().unwrap()),
        u32::from_be_bytes(digest[28..32].try_into().unwrap()), 
    ]
}

pub fn sha256_hash_u256_digests(msg: &[u8]) -> U256 {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    U256::from_big_endian(&digest)
}

pub fn asset_u32_8_eq_u256(o: [u32; 8], n: U256) {
    let mut dest = [0u8; 32];
    n.to_big_endian(&mut dest[..]);

    let orig = [
        u32::from_be_bytes(dest[0..4].try_into().unwrap()),
        u32::from_be_bytes(dest[4..8].try_into().unwrap()),
        u32::from_be_bytes(dest[8..12].try_into().unwrap()),
        u32::from_be_bytes(dest[12..16].try_into().unwrap()),
        u32::from_be_bytes(dest[16..20].try_into().unwrap()),
        u32::from_be_bytes(dest[20..24].try_into().unwrap()),
        u32::from_be_bytes(dest[24..28].try_into().unwrap()),
        u32::from_be_bytes(dest[28..32].try_into().unwrap()), 
    ];

    for i in 0..8 {
        assert_eq!(orig[i], o[i]);
    }
}

#[test]
fn bits_smoke_test()  {
    let x = [1, 2, 3, 123];

    let bits = array_to_bits(&x);
    assert_eq!(bits.len(), 32);

    let bytes =  bits_to_array(&bits);
    assert_eq!(bytes, x);
    assert_eq!(bytes.len(), 4);
}

#[test]
fn find_smoke_test()  {
    let x = [1, 2, 3, 123];
    let y = [2, 3];

    let x = array_to_bits(&x);
    let y = array_to_bits(&y);

    let loc = find_subsequence(&x, &y);
    assert_eq!(loc, Some(8));
}

#[test]
fn sha256_smoke_test() {
    let x = b"something";
    let result = sha256_hash_u32_digests(&x[..]);
    let result_u256 = sha256_hash_u256_digests(&x[..]);
    asset_u32_8_eq_u256(result, result_u256);
    assert_eq!(result_u256, U256::from_str_radix("3fc9b689459d738f8c88a3a48aa9e33542016b7a4052e001aaa536fca74813cb", 16).unwrap());
}

// [1070184073, 1167946639, 2357765028, 2326389557, 1107389306, 1079173121, 2862954236, 2806518731]
// 