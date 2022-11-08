#![feature(test)]
extern crate test;

use field_encryption::FieldEncryption;
use field_encryption::FieldEncryptionError;
use test::Bencher;

#[bench]
fn encrypt_simple(b: &mut Bencher) {
    let fe = FieldEncryption::new("[0-9]{1,5}", "[0-9]{1,5}", &[23; 32]).unwrap();
    b.iter(|| fe.encrypt("12321").unwrap())
}

#[bench]
fn decrypt_simple(b: &mut Bencher) {
    let fe = FieldEncryption::new("[0-9]{1,5}", "[0-9]{1,5}", &[23; 32]).unwrap();
    let cipher_text = fe.encrypt("12321").unwrap();
    b.iter(|| fe.decrypt(&cipher_text).unwrap())
}

#[bench]
fn encrypt_decrypt_simple(b: &mut Bencher) {
    let fe = FieldEncryption::new("[0-9]{1,5}", "[0-9]{1,5}", &[23; 32]).unwrap();
    b.iter(|| {
        let cipher_text = fe.encrypt("12321").unwrap();
        fe.decrypt(&cipher_text).unwrap();
    })
}

#[bench]
fn encrypt_complex(b: &mut Bencher) {
    let fe = FieldEncryption::new(
        "[A-Z][a-z]{1,4}[0-9]{1,5}[?|!]?",
        "[?|!]?[A-Z][a-z]{1,4}[0-9]{1,5}",
        &[23; 32],
    )
    .unwrap();
    b.iter(|| fe.encrypt("Abcde23?").unwrap())
}

#[bench]
fn decrypt_complex(b: &mut Bencher) {
    let fe = FieldEncryption::new(
        "[A-Z][a-z]{1,4}[0-9]{1,5}[?|!]?",
        "[?|!]?[A-Z][a-z]{1,4}[0-9]{1,5}",
        &[23; 32],
    )
    .unwrap();
    let cipher_text = fe.encrypt("Abcde23?").unwrap();
    b.iter(|| fe.decrypt(&cipher_text).unwrap())
}

#[bench]
fn encrypt_decrypt_complex(b: &mut Bencher) {
    let fe = FieldEncryption::new(
        "[A-Z][a-z]{1,4}[0-9]{1,5}[?|!]?",
        "[?|!]?[A-Z][a-z]{1,4}[0-9]{1,5}",
        &[23; 32],
    )
    .unwrap();
    b.iter(|| {
        let cipher_text = fe.encrypt("Abcde23?").unwrap();
        fe.decrypt(&cipher_text).unwrap();
    })
}

#[bench]
fn encrypt_large(b: &mut Bencher) {
    let fe = FieldEncryption::new(
        "[A-Z][a-z]{1,4} [0-9]{1,5} [a-z]{1,27}",
        "[A-Z][a-z]{1,4} [0-9]{1,5} [a-z]{1,27}",
        &[23; 32],
    )
    .unwrap();
    b.iter(|| fe.encrypt("Abcde 42 aaaaabbbbbcccccddddd").unwrap())
}
