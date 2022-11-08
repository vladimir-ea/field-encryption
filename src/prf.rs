use crate::error::Error;
use sha3::{Digest, Sha3_256};
use std::cell::RefCell;

const INFO: &[u8] = &[23; 32];

pub(crate) fn prfs(key: &[u8], count: usize) -> Result<Vec<Prf>, Error> {
    if count % 2 == 0 {
        // Require odd number of rounds
        return Err(Error::EvenFiestalRounds);
    }

    let mut hk =
        hkdf::Hkdf::<Sha3_256>::from_prk(key).map_err(|_| Error::InvalidKeyLength(key.len()))?;

    (0..count)
        .map(|_| {
            let mut next_key = [0u8; 32];
            hk.expand(&INFO, &mut next_key)
                .map_err(|_| Error::InvalidKeyExpansion(next_key.len()))?;
            hk = hkdf::Hkdf::<Sha3_256>::from_prk(&next_key)
                .map_err(|_| Error::InvalidKeyLength(next_key.len()))?;
            Ok(Prf::new(next_key.to_vec()))
        })
        .collect::<Result<Vec<_>, _>>()
}

pub(crate) struct Prf {
    key: Vec<u8>,
    digest: RefCell<Sha3_256>,
}

impl Prf {
    pub(crate) fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            digest: RefCell::new(Sha3_256::new()),
        }
    }

    pub(crate) fn execute(
        &self,
        msg: &mut [u8],
        zero_in: u8,
        in_val: u8,
        zero_out: u8,
        out_val: u8,
    ) {
        let mut digest = self.digest.borrow_mut();
        digest.reset();
        digest.update(&self.key);

        let mut mask = zero_in;
        for i in 0..msg.len() {
            digest.update(&[msg[i] & mask]);
            mask = in_val;
        }

        let mut output = digest.finalize_reset();
        let mut output_slice = output.as_slice();

        let mut in_mask = zero_in;
        let mut out_mask = zero_out;
        let mut offset = 0;

        for i in 0..msg.len() {
            msg[i] = (msg[i] & in_mask) | (msg[i] ^ (output_slice[offset] & out_mask));
            in_mask = in_val;
            out_mask = out_val;

            offset += 1;
            if offset == output_slice.len() {
                digest.update(output_slice);
                output = digest.finalize_reset();
                output_slice = output.as_slice();
                offset = 0;
            }
        }
    }
}
