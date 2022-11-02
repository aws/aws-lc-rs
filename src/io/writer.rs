// Copyright 2018 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

pub trait Accumulator {
    fn write_byte(&mut self, value: u8);
    fn write_bytes(&mut self, value: &[u8]);
}

pub(super) struct LengthMeasurement {
    len: usize,
}

impl From<LengthMeasurement> for usize {
    fn from(len_measurement: LengthMeasurement) -> Self {
        len_measurement.len
    }
}

impl LengthMeasurement {
    #[cfg(test)]
    pub fn zero() -> Self {
        Self { len: 0 }
    }
}

impl Accumulator for LengthMeasurement {
    fn write_byte(&mut self, _value: u8) {
        self.len += 1;
    }
    fn write_bytes(&mut self, value: &[u8]) {
        self.len += value.len();
    }
}

pub(super) struct Writer {
    bytes: Vec<u8>,
    requested_capacity: usize,
}

impl Writer {
    #[cfg(test)]
    pub(super) fn with_capacity(capacity: LengthMeasurement) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity.len),
            requested_capacity: capacity.len,
        }
    }
}

impl From<Writer> for Box<[u8]> {
    fn from(writer: Writer) -> Self {
        assert_eq!(writer.requested_capacity, writer.bytes.len());
        writer.bytes.into_boxed_slice()
    }
}

impl Accumulator for Writer {
    fn write_byte(&mut self, value: u8) {
        self.bytes.push(value);
    }
    fn write_bytes(&mut self, value: &[u8]) {
        self.bytes.extend(value);
    }
}

pub fn write_copy(accumulator: &mut dyn Accumulator, to_copy: untrusted::Input) {
    accumulator.write_bytes(to_copy.as_slice_less_safe())
}

#[cfg(test)]
mod tests {
    use crate::io::writer::{write_copy, Accumulator, LengthMeasurement, Writer};
    use crate::rand::{generate, SystemRandom};
    use rand::RngCore;
    const TEST_DATA_SIZE: usize = 100;

    #[test]
    fn test_writer() {
        let mut writer = Writer::with_capacity(LengthMeasurement {
            len: TEST_DATA_SIZE,
        });

        let data = test_accumulator(&mut writer);

        assert_eq!(writer.bytes.as_slice(), data.as_slice());
    }

    fn test_accumulator(accumulator: &mut dyn Accumulator) -> [u8; TEST_DATA_SIZE] {
        let data: [u8; TEST_DATA_SIZE] = generate(&SystemRandom::new()).unwrap().expose();

        accumulator.write_byte(data[0]);

        let mut index = 1;
        while index < TEST_DATA_SIZE {
            let next_chunk_size = 1 + (rand::thread_rng().next_u32() % 10) as usize;
            let mut next_index = index + next_chunk_size;
            if next_index > TEST_DATA_SIZE {
                next_index = TEST_DATA_SIZE;
            }
            accumulator.write_bytes(&data[index..next_index]);
            index = next_index;
        }

        data
    }

    #[test]
    fn test_length_measurement() {
        let mut length_measurement = LengthMeasurement::zero();

        let data = test_accumulator(&mut length_measurement);
        let acc_len: usize = length_measurement.into();

        assert_eq!(acc_len, data.len());
    }

    #[test]
    fn test_write_copy() {
        let mut length_measurement = LengthMeasurement::zero();
        let data: [u8; TEST_DATA_SIZE] = generate(&SystemRandom::new()).unwrap().expose();

        let input = untrusted::Input::from(&data);
        write_copy(&mut length_measurement, input);

        let acc_len: usize = length_measurement.into();

        assert_eq!(acc_len, data.len());
    }
}
