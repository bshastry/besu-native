/* Copyright contributors to Besu.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Tests for the parsing module

use crate::parsing::{read_big, ParsedModExpInput};

#[test]
fn test_read_big_exact_data() {
    let input = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let result = read_big(&input, 1, 4);
    assert_eq!(result, vec![0x02, 0x03, 0x04]);
}

#[test]
fn test_read_big_partial_data() {
    let input = vec![0x01, 0x02, 0x03];
    let result = read_big(&input, 1, 5);
    // Should read [0x02, 0x03] and pad with zeros
    assert_eq!(result, vec![0x02, 0x03, 0x00, 0x00]);
}

#[test]
fn test_read_big_out_of_bounds() {
    let input = vec![0x01, 0x02];
    let result = read_big(&input, 5, 8);
    // Should return all zeros since start is beyond input
    assert_eq!(result, vec![0x00, 0x00, 0x00]);
}

#[test]
fn test_read_big_empty_input() {
    let input = vec![];
    let result = read_big(&input, 0, 4);
    // Should return all zeros
    assert_eq!(result, vec![0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn test_parsed_modexp_basic() {
    let mut input = vec![0u8; 100];
    // Add some data at position 96
    input[96] = 0xAA;
    input[97] = 0xBB;
    input[98] = 0xCC;
    input[99] = 0xDD;

    let parsed = ParsedModExpInput::from_raw_input(&input, 2, 1, 1);

    assert_eq!(parsed.base, vec![0xAA, 0xBB]);
    assert_eq!(parsed.exponent, vec![0xCC]);
    assert_eq!(parsed.modulus, vec![0xDD]);
}

#[test]
fn test_parsed_modexp_with_padding() {
    // Input only has 97 bytes total, but we request more
    let input = vec![0u8; 97];

    let parsed = ParsedModExpInput::from_raw_input(&input, 2, 2, 2);

    // base starts at 96, should get 1 byte then pad
    assert_eq!(parsed.base, vec![0x00, 0x00]);
    // exp starts at 98, which is beyond input, all zeros
    assert_eq!(parsed.exponent, vec![0x00, 0x00]);
    // mod starts at 100, which is beyond input, all zeros
    assert_eq!(parsed.modulus, vec![0x00, 0x00]);
}

#[test]
fn test_parsed_modexp_zero_lengths() {
    let input = vec![0xFF; 100];

    let parsed = ParsedModExpInput::from_raw_input(&input, 0, 0, 0);

    assert_eq!(parsed.base, vec![]);
    assert_eq!(parsed.exponent, vec![]);
    assert_eq!(parsed.modulus, vec![]);
}

#[test]
fn test_parsed_modexp_reproduces_fuzzer_case() {
    // This reproduces the case that caused the fuzzer crash
    // where declared lengths were larger than available data
    let mut input = vec![0u8; 96];
    // Add only 2 bytes of actual data
    input.push(0xFF);
    input.push(0xFF);

    // But declare we want 4 bytes for modulus
    let parsed = ParsedModExpInput::from_raw_input(&input, 0, 0, 4);

    // Should get [0xFF, 0xFF, 0x00, 0x00] due to right padding
    assert_eq!(parsed.modulus, vec![0xFF, 0xFF, 0x00, 0x00]);
}

