# Field Encryption

This library provides a `FieldEncryption` struct that allows values in an input format to be encrypted into values in an output format, where the input and output formats are described by regular expressions. So it is similar to a Format Preserving Encryption scheme but allows for flexibility in the format of the encrypted fields.  

```rust
use field_encryption::FieldEncryption;

let fe = FieldEncryption::new(r"[A-Z][a-z]{1,4} [A-Z][a-z]{1-4}!", r"[a-z]{5} [a-z]{7}", &[0;32]).unwrap();
let cipher_text = fe.encrypt("Hello World!").unwrap();
println!("{}", cipher_text);
let plain_text = fe.decrypt(&cipher_text).unwrap(); 
println!("{}", plain_text);
```

Gives the output:
```text
qtzwe mcdzozq
Hello World!
```

The implementation is based on the ['Ciphers with Arbitrary Finite Domains'](https://www.cs.ucdavis.edu/~rogaway/papers/subset.pdf) paper by Black and Rogaway (2002), and works as follows:

- the offset of the input in the variants of the input regex is calculated 
- the offset is encrypted into the domain of the output regex using a Fiestal network
  - the 'cycle walking' approach outlined in the paper is used to arrive at inbounds values
- the output of the encryption is used as an offset 'n' in the variants of the output regex
- the nth variant of the output regex is returned as the cipher text

## Uses
This library might be useful for tokenizing data fields in a way that is compliant with existing data schemas, in order ot anonymize a dataset, for example. 

## Limitations
- I am not a cryptographer! There is no guarantee whatsoever that this library is cryptographically secure.
