extern crate rand;
extern crate xxtea;

use rand::Rng;

fn rand_bytes() -> Vec<u8> {
    let num = rand::thread_rng().gen_range(4, 256) * 4;
    (0..num).map(|_| rand::random::<u8>()).collect()
}

pub fn to_hex_byte_string(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    for b in bytes {
        let upper = (b >> 4) & 0x0F;
        let lower = b & 0x0F;
        result.push(upper + b'0');
        result.push(lower + b'0');
    }

    result
}

fn run_test_case() {
    let plaintext_bytes = to_hex_byte_string(rand_bytes().as_slice());
    let plaintext_string = core::str::from_utf8(plaintext_bytes.as_slice()).unwrap();
    let mut data = plaintext_bytes.clone();
    let key = rand_bytes();
    let key = &key[..16];

    xxtea::encrypt(&mut data, key);

    let mut result = data.clone();
    xxtea::decrypt(&mut result, key);

    let decrypted_plaintext = match core::str::from_utf8(result.as_slice()) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    assert_eq!(plaintext_string, decrypted_plaintext);
}

#[test]
fn test() {
    for _ in 0..100 {
        run_test_case();
    }
}
