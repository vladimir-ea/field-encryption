mod domain;
mod error;
mod fiestal;
mod prf;

pub use error::Error as FieldEncryptionError;

const ROUNDS: usize = 7;

/// `FieldEncryption` struct. Provides methods to encrypt values matching the input regex to a
/// value matching the output regex (and to decrypt).
///
/// Both regular expressions must be finite, i.e. they must contain a bounded number of possible
/// values - so no unbounded expressions such as `.*` or `[0-9]+` are permitted.
///
/// Furthermore the number of possible values of the output regex must be equal to, or greater than,
/// the number of possible values of the input regex, i.e. the 'domain' of the output regex must be
/// greater than or equal to the 'domain' pf the input regex.
pub struct FieldEncryption {
    input: domain::RegexDomain,
    output: domain::RegexDomain,
    fiestal: fiestal::Fiestal,
    trim_bytes: usize,
    top_bits: u32,
}

impl FieldEncryption {
    /// Create a new `FieldEncryption` instance.
    /// # Arguments
    /// * `input_regex` - the regular expression that describes all inputs
    /// * `output_regex` - the regular expression that describes all outputs
    /// * `key` - the encryption key, must be at least 32 bytes
    ///
    /// # Errors
    /// * `InfiniteRegex` - if either regex is infinite
    /// * `OutputDomainTooSmall` - if the domain of the output regex is < domain of the input regex
    /// * `InvalidKeyLength` - of the encryption key is too small
    pub fn new(input_regex: &str, output_regex: &str, key: &[u8]) -> Result<Self, error::Error> {
        let input = domain::RegexDomain::new(input_regex)?;
        let output = domain::RegexDomain::new(output_regex)?;

        if input.len() > output.len() {
            return Err(error::Error::OutputDomainTooSmall);
        }
        let prfs = prf::prfs(key, ROUNDS)?;
        let fiestal = fiestal::Fiestal::new(prfs)?;

        let output_max = output.len();
        let zero_bits = output_max.leading_zeros();
        let trim_bytes = (zero_bits / 8) as usize;
        let mut top_bits = 8 - (zero_bits % 8);
        if top_bits % 2 == 1 {
            // must have even number bits
            top_bits += 1;
        }

        Ok(Self {
            input,
            output,
            fiestal,
            trim_bytes,
            top_bits,
        })
    }

    /// Encrypts the supplied input.
    /// # Errors
    /// * `InvalidInput` - if the specified value does not match the input regex
    pub fn encrypt(&self, input: &str) -> Result<String, error::Error> {
        self.execute(input, &self.input, &self.output, |data, bits| {
            self.fiestal.encrypt(data, bits);
        })
    }

    /// Decrypts the supplied input.
    /// # Errors
    /// * `InvalidInput` - if the specified value does not match the output regex
    pub fn decrypt(&self, input: &str) -> Result<String, error::Error> {
        self.execute(input, &self.output, &self.input, |data, bits| {
            self.fiestal.decrypt(data, bits);
        })
    }

    fn execute(
        &self,
        input: &str,
        from: &domain::RegexDomain,
        to: &domain::RegexDomain,
        func: impl Fn(&mut [u8], u32),
    ) -> Result<String, error::Error> {
        let input_offset = from
            .offset(input.as_bytes())
            .ok_or_else(|| error::Error::InvalidInput(input.to_owned()))?;

        let mut input_bytes = input_offset.to_be_bytes();
        let mut output_offset = self.output.len();
        while output_offset >= self.output.len() {
            func(&mut input_bytes[self.trim_bytes..], self.top_bits);
            output_offset = u128::from_be_bytes(input_bytes);
        }
        let output_bytes = to
            .nth(output_offset)
            .ok_or_else(|| error::Error::InvalidOutputOffset(output_offset))?;

        Ok(String::from_utf8(output_bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let input = "11211";
        let fe = FieldEncryption::new(r"[0-9]{1,9}", r"[a-z]{1,17}", &[23; 32]).unwrap();
        let cipher = fe.encrypt(input).unwrap();
        println!("cipher = {}", cipher);
        let plain = fe.decrypt(&cipher).unwrap();
        println!("plain = {}", plain);
        assert_eq!(input, plain.as_str());
    }

    #[test]
    fn readme() {
        let fe = FieldEncryption::new(
            r"[A-Z][a-z]{1,4} [A-Z][a-z]{1,4}!",
            r"[a-z]{5} [a-z]{7}",
            &[0; 32],
        )
        .unwrap();
        let cipher_text = fe.encrypt("Hello World!").unwrap();
        println!("{}", cipher_text);
        let plain_text = fe.decrypt(&cipher_text).unwrap();
        println!("{}", plain_text);
    }
}
