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

#![no_main]

#[cfg(not(feature = "raw_bytes_fuzzing"))]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
#[cfg(not(feature = "raw_bytes_fuzzing"))]
use std::cmp::min;

// Import shared testing utilities
use eth_arithmetic::testing::call_modexp_precompiled;
#[cfg(not(feature = "raw_bytes_fuzzing"))]
use eth_arithmetic::testing::{
    ModExpResult,
    ModExpError,
    MAX_COMPONENT_LENGTH,
    U256_SIZE_BYTES,
    HEADER_SIZE_BYTES,
};

#[cfg(not(feature = "raw_bytes_fuzzing"))]
use eth_arithmetic::testing::validation::*;

/// Represents structured input for modular exponentiation operation
///
/// This struct models the input format expected by Ethereum's modexp precompile:
/// - 3 big-endian u256 values specifying lengths (base, exponent, modulus)
/// - Followed by the actual data for base, exponent, and modulus
#[cfg(not(feature = "raw_bytes_fuzzing"))]
#[derive(Debug, Clone, Arbitrary)]
struct ModExpInput {
    /// Length of the base in bytes (0-1024)
    #[arbitrary(with = |u: &mut Unstructured| u.int_in_range(0..=MAX_COMPONENT_LENGTH))]
    base_len: u32,

    /// Length of the exponent in bytes (0-1024)
    #[arbitrary(with = |u: &mut Unstructured| u.int_in_range(0..=MAX_COMPONENT_LENGTH))]
    exp_len: u32,

    /// Length of the modulus in bytes (0-1024)
    #[arbitrary(with = |u: &mut Unstructured| u.int_in_range(0..=MAX_COMPONENT_LENGTH))]
    mod_len: u32,

    /// Base value data
    #[arbitrary(with = generate_bounded_bytes)]
    base_data: Vec<u8>,

    /// Exponent value data
    #[arbitrary(with = generate_bounded_bytes)]
    exp_data: Vec<u8>,

    /// Modulus value data
    #[arbitrary(with = generate_bounded_bytes)]
    mod_data: Vec<u8>,
}

/// Generate arbitrary byte vector with bounded length for fuzzing
#[cfg(not(feature = "raw_bytes_fuzzing"))]
fn generate_bounded_bytes(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=MAX_COMPONENT_LENGTH as usize)?;
    let mut bytes = Vec::with_capacity(len);

    for _ in 0..len {
        bytes.push(u.arbitrary()?);
    }

    Ok(bytes)
}


#[cfg(not(feature = "raw_bytes_fuzzing"))]
impl ModExpInput {
    /// Convert to the byte format expected by modexp_precompiled
    ///
    /// Format:
    /// - Bytes 0-31:   base length (big-endian u256)
    /// - Bytes 32-63:  exponent length (big-endian u256)
    /// - Bytes 64-95:  modulus length (big-endian u256)
    /// - Bytes 96+:    base data || exponent data || modulus data
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.calculate_buffer_size());

        // Append length headers
        buffer.extend_from_slice(&self.encode_u256(self.base_len));
        buffer.extend_from_slice(&self.encode_u256(self.exp_len));
        buffer.extend_from_slice(&self.encode_u256(self.mod_len));

        // Append data with padding
        self.append_padded_data(&mut buffer, &self.base_data, self.base_len as usize);
        self.append_padded_data(&mut buffer, &self.exp_data, self.exp_len as usize);
        self.append_padded_data(&mut buffer, &self.mod_data, self.mod_len as usize);

        buffer
    }

    /// Calculate the expected output size based on Ethereum modexp rules
    fn expected_output_size(&self) -> usize {
        // According to EIP-198, the output is always the same length as the modulus,
        // except when modulus is zero-length which produces empty output
        self.mod_len as usize
    }

    /// Calculate the total buffer size needed for serialization
    fn calculate_buffer_size(&self) -> usize {
        HEADER_SIZE_BYTES +
        self.base_len as usize +
        self.exp_len as usize +
        self.mod_len as usize
    }

    /// Encode a u32 as a big-endian u256 (32 bytes)
    fn encode_u256(&self, value: u32) -> [u8; U256_SIZE_BYTES] {
        let mut bytes = [0u8; U256_SIZE_BYTES];
        let value_bytes = value.to_be_bytes();
        bytes[U256_SIZE_BYTES - value_bytes.len()..].copy_from_slice(&value_bytes);
        bytes
    }

    /// Append data to buffer with proper truncation and padding
    fn append_padded_data(&self, buffer: &mut Vec<u8>, data: &[u8], target_len: usize) {
        let actual_len = min(data.len(), target_len);
        buffer.extend_from_slice(&data[..actual_len]);

        // Pad with zeros if necessary
        if actual_len < target_len {
            buffer.resize(buffer.len() + target_len - actual_len, 0);
        }
    }
}

// Structured fuzzing target - generates well-formed inputs
#[cfg(not(feature = "raw_bytes_fuzzing"))]
fuzz_target!(|input: ModExpInput| {
    let input_bytes = input.to_bytes();
    let expected_output_size = input.expected_output_size();

    match call_modexp_precompiled(&input_bytes) {
        Ok(result) => {
            let ModExpResult { output, parsed_input } = result;
            validate_output(&output, expected_output_size);

            // Additional property-based tests
            if parsed_input.mod_len > 0 {
                // Result should be less than modulus (using parsed modulus data)
                validate_result_less_than_modulus(&output, &parsed_input.modulus, parsed_input.mod_len);
            }

            // Test known mathematical properties using parsed data
            validate_mathematical_properties(&parsed_input, &output);
        }
        Err(error_code) => {
            // Verify we only get expected error codes
            if let Some(known_error) = ModExpError::from_code(error_code) {
                // Expected error, validate it makes sense for the input
                validate_error_condition(known_error, input.base_len, input.exp_len, input.mod_len);
            } else {
                panic!("Unknown error code returned: {}", error_code);
            }
        }
    }
});

// Raw bytes fuzzing target - tests arbitrary input handling
#[cfg(feature = "raw_bytes_fuzzing")]
fuzz_target!(|data: &[u8]| {
    // Test with completely arbitrary input
    let _ = call_modexp_precompiled(data);
});