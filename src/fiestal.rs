use crate::error::Error;
use crate::prf::Prf;

pub(crate) struct Fiestal {
    prfs: Vec<Prf>,
}

impl Fiestal {
    pub(crate) fn new(prfs: Vec<Prf>) -> Result<Self, Error> {
        if prfs.len() % 2 == 0 {
            Err(Error::EvenFiestalRounds)
        } else {
            Ok(Self { prfs })
        }
    }

    pub(crate) fn encrypt(&self, msg: &mut [u8], bits: u32) {
        let shift = bits / 2;
        let mut zero_right = 0xFF >> (8 - shift);
        let mut zero_left = zero_right << shift;

        let mut left = 0xF0;
        let mut right = 0x0F;

        for prf in self.prfs.iter() {
            prf.execute(msg, zero_left, left, zero_right, right);
            let tmp = left;
            left = right;
            right = tmp;

            let tmp = zero_left;
            zero_left = zero_right;
            zero_right = tmp;
        }
    }

    pub fn decrypt(&self, msg: &mut [u8], bits: u32) {
        let shift = bits / 2;
        let mut zero_right = 0xFF >> (8 - shift);
        let mut zero_left = zero_right << shift;

        let mut left = 0xF0;
        let mut right = 0x0F;

        for prf in self.prfs.iter().rev() {
            prf.execute(msg, zero_left, left, zero_right, right);
            let tmp = left;
            left = right;
            right = tmp;

            let tmp = zero_left;
            zero_left = zero_right;
            zero_right = tmp;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut prfs = vec![];
        for i in 0..7 {
            let prf = Prf::new(vec![i]);
            prfs.push(prf);
        }
        let fiestal = Fiestal::new(prfs).unwrap();
        let mut string = String::from("Hello, World! Hello, World? Hello?");
        let msg: &mut [u8] = unsafe { string.as_bytes_mut() };
        fiestal.encrypt(msg, 8);
        println!("cipher text: {:?}", msg);
        fiestal.decrypt(msg, 8);
        println!("plain text: {}", std::str::from_utf8(msg).unwrap());
    }
}
