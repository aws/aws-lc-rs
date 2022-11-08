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

// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: ISC

#[cfg(test)]
use super::{
    der::Tag,
    writer::{write_copy, Accumulator, LengthMeasurement, Writer},
    Positive,
};

#[cfg(test)]
pub(crate) fn write_positive_integer(output: &mut dyn Accumulator, value: &Positive) {
    let first_byte = value.first_byte();
    let value = value.big_endian_without_leading_zero_as_input();
    write_tlv(output, Tag::Integer, |output| {
        if (first_byte & 0x80) != 0 {
            output.write_byte(0); // Disambiguate negative number.
        }
        write_copy(output, value);
    });
}

#[cfg(test)]
pub(crate) fn write_all(tag: Tag, write_value: &dyn Fn(&mut dyn Accumulator)) -> Box<[u8]> {
    let length = {
        let mut length = LengthMeasurement::zero();
        write_tlv(&mut length, tag, write_value);
        length
    };

    let mut output = Writer::with_capacity(&length);
    write_tlv(&mut output, tag, write_value);

    output.into()
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
fn write_tlv<F>(output: &mut dyn Accumulator, tag: Tag, write_value: F)
where
    F: Fn(&mut dyn Accumulator),
{
    let length: usize = {
        let mut length = LengthMeasurement::zero();
        write_value(&mut length);
        length.into()
    };

    output.write_byte(tag as u8);
    if length < 0x80 {
        output.write_byte(length as u8);
    } else if length < 0x1_00 {
        output.write_byte(0x81);
        output.write_byte(length as u8);
    } else if length < 0x1_00_00 {
        output.write_byte(0x82);
        output.write_byte((length / 0x1_00) as u8);
        output.write_byte(length as u8);
    } else {
        unreachable!();
    };

    write_value(output);
}

#[cfg(test)]
mod tests {
    use crate::io::der::Tag;
    use crate::io::der_writer::{write_all, write_positive_integer};
    use crate::io::writer::{Accumulator, LengthMeasurement};
    use crate::io::Positive;
    use crate::rand::{generate, SystemRandom};

    const TEST_DATA_SIZE: usize = 100;
    #[test]
    fn test_write_positive_integer() {
        let mut data: [u8; TEST_DATA_SIZE] = generate(&SystemRandom::new()).unwrap().expose();
        data[0] |= 0x80; //negative
        let positive = Positive::new_non_empty_without_leading_zeros(untrusted::Input::from(&data));
        let mut length_measurement = LengthMeasurement::zero();
        write_positive_integer(&mut length_measurement, &positive);
        let measurement: usize = length_measurement.into();
        assert_eq!(measurement, TEST_DATA_SIZE + 3);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_write_all() {
        let mut data: [u8; TEST_DATA_SIZE] = generate(&SystemRandom::new()).unwrap().expose();
        data[0] |= 0x80; //negative
        let positive = Positive::new_non_empty_without_leading_zeros(untrusted::Input::from(&data));
        let tag = Tag::Integer;

        let func: &dyn Fn(&mut dyn Accumulator) = &|output| {
            write_positive_integer(output, &positive);
        };

        let result = write_all(tag, &func);
        assert_eq!(TEST_DATA_SIZE + 5, result.len());
        assert_eq!(0x02, result[0]);
        assert_eq!((TEST_DATA_SIZE + 3) as u8, result[1]);
        assert_eq!(0x02, result[2]);
        assert_eq!((TEST_DATA_SIZE + 1) as u8, result[3]);
        assert_eq!(0x00, result[4]);

        println!("Result: {} {:?}", result.len(), result.as_ref());
    }
}
