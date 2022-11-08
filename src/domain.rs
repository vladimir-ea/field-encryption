use crate::error::Error;
use regex_automata::dense;
use regex_automata::SparseDFA;
use regex_automata::DFA;
use std::collections::HashMap;

/// Wrapper around the underlying automation. Caches attributes of the
/// automation to support indexing into the input space.
pub(crate) struct RegexDomain {
    dfa: SparseDFA<Vec<u8>>,
    size: u128,
    counts: HashMap<usize, u128>,
    inputs: HashMap<usize, Vec<u8>>,
}

impl RegexDomain {
    pub(crate) fn new(regex: &str) -> Result<Self, Error> {
        let dense = dense::Builder::new().anchored(true).build(regex)?;
        let dfa = dense.to_sparse()?;
        let mut counts = HashMap::new();
        let mut inputs = HashMap::new();
        let mut visited = vec![];
        let size = Self::scan(
            &dfa,
            dfa.start_state(),
            &mut counts,
            &mut inputs,
            &mut visited,
        )?;
        Ok(Self {
            dfa,
            size,
            counts,
            inputs,
        })
    }

    pub(crate) fn nth(&self, offset: u128) -> Option<Vec<u8>> {
        match self.nth_inner(self.dfa.start_state(), offset, 0).1 {
            Some(mut vec) => {
                vec.reverse();
                Some(vec)
            }
            None => None,
        }
    }

    pub(crate) fn offset(&self, bytes: &[u8]) -> Option<u128> {
        self.offset_inner(self.dfa.start_state(), 0, bytes, 0)
    }

    pub(crate) fn len(&self) -> u128 {
        self.size
    }

    fn nth_inner(&self, id: usize, offset: u128, mut count: u128) -> (u128, Option<Vec<u8>>) {
        for b in self.inputs.get(&id).expect("unknown state") {
            let next = self.dfa.next_state(id, *b);
            if let Some(cached) = self.counts.get(&next) {
                if offset > count + cached {
                    count += cached;
                    continue;
                }
            }

            if self.dfa.is_match_state(next) {
                if count == offset {
                    return (count, Some(vec![*b]));
                }
                count += 1;
            }

            let (sub, vec) = self.nth_inner(next, offset, count);
            if let Some(mut val) = vec {
                val.push(*b);
                return (sub, Some(val));
            }
            count = sub;
        }
        (count, None)
    }

    fn offset_inner(
        &self,
        id: usize,
        mut count: u128,
        bytes: &[u8],
        mut index: usize,
    ) -> Option<u128> {
        for b in self.inputs.get(&id).expect("unknown state") {
            let next = self.dfa.next_state(id, *b);

            if *b == bytes[index] {
                index += 1;
                if index == bytes.len() {
                    if self.dfa.is_match_state(next) {
                        return Some(count);
                    } else {
                        return None;
                    }
                }
                if self.dfa.is_match_state(next) {
                    count += 1;
                }
                return self.offset_inner(next, count, bytes, index);
            }
            count += self.counts.get(&next).expect("state not found");
        }
        None
    }

    /// Walks the DFA:
    /// - collects the match count for each state
    /// - collects the valid inputs at each state
    /// - checks for match loops indicating an infinite automaton
    /// - returns the number of different matching inputs
    fn scan(
        dfa: &impl DFA<ID = usize>,
        id: usize,
        counts: &mut HashMap<usize, u128>,
        inputs: &mut HashMap<usize, Vec<u8>>,
        visited: &mut Vec<usize>,
    ) -> Result<u128, Error> {
        visited.push(id);
        let mut count = 0;
        let mut input = vec![];
        for b in 0..=255 {
            let next = dfa.next_state(id, b);
            if !dfa.is_dead_state(next) {
                input.push(b);
            }
            if let Some(cached) = counts.get(&next) {
                // count = count
                //     .checked_add(*cached as u64)
                //     .ok_or_else(|| Error::DomainTooBig)?;
                count += cached;
            } else {
                let mut local = 0;
                if dfa.is_match_state(next) {
                    if visited.contains(&next) {
                        return Err(Error::InfiniteRegex);
                    }
                    local += 1;
                }
                if !dfa.is_dead_state(next) {
                    local += Self::scan(dfa, next, counts, inputs, visited)?;
                }
                // count = count
                //     .checked_add(local as u64)
                //     .ok_or_else(|| Error::DomainTooBig)?;
                count += local;
                counts.insert(next, local);
            }
        }
        visited.pop();
        inputs.insert(id, input);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let rd = RegexDomain::new(r"[A-Z][a-z]{4} [A-Z][a-z]{4}[?|!]").unwrap();

        let start = std::time::Instant::now();
        for i in 0..1000 {
            let rd_nth = rd.nth(i).unwrap();
            let rd_str = String::from_utf8(rd_nth).unwrap();
            let rd_offset = rd.offset(rd_str.as_bytes()).unwrap();
            assert_eq!(i, rd_offset);
        }
        println!("Took {}us", start.elapsed().as_micros());
    }

    #[test]
    fn hello_world() {
        let rd = RegexDomain::new(r"[A-Z][a-z]{4} [A-Z][a-z]{4}[?|!]").unwrap();
        let n = rd.offset("Hello World!".as_bytes()).unwrap();
        let nth = rd.nth(n).unwrap();
        let str = String::from_utf8(nth).unwrap();
        assert_eq!("Hello World!", str.as_str());
    }

    #[test]
    fn infinite() {
        let res = RegexDomain::new(r"[0-9]+");
        assert!(res.is_err());
        assert!(matches!(res, Err(Error::InfiniteRegex)));
    }

    #[test]
    fn complex() {
        let rd = RegexDomain::new(r"\d{1,3}").unwrap();
        let nth = rd.nth(23).unwrap();
        let offset = rd.offset(&nth).unwrap();
        assert_eq!(23, offset);
    }
}
