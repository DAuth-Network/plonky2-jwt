use plonky2::hash::hash_types::RichField;

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
    let mut jwt_hash_bits = Vec::<bool>::new();
    let mut credential_hash_bits = Vec::<bool>::new();

    for i in 0..256 {
        jwt_hash_bits.push(public_inputs[i] == F::ONE);
        credential_hash_bits.push(public_inputs[i + 256] == F::ONE);
    }

    let jwt_hash = bits_to_array(&jwt_hash_bits);
    let credential_hash = bits_to_array(&credential_hash_bits);

    return (
        jwt_hash.try_into().unwrap(),
        credential_hash.try_into().unwrap(),
    );
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
