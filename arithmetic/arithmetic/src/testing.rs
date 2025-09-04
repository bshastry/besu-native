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

//! Testing utilities for modexp precompile validation
//!
//! This module provides shared testing infrastructure for both unit tests and fuzzing,
//! implementing the same constraints as the upstream Java code that calls the FFI.

use crate::{modexp_precompiled, parsing};

// Configuration constants matching Java implementation limits
pub const MAX_COMPONENT_LENGTH: u32 = 1024;
pub const U256_SIZE_BYTES: usize = 32;
pub const HEADER_SIZE_BYTES: usize = 96; // 3 * U256_SIZE_BYTES

/// Error codes returned by the modexp precompiled function
#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ModExpError {
    InvalidInput = 1,
    OutputBufferTooSmall = 2,
    MemoryAllocationFailed = 3,
}

impl ModExpError {
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::InvalidInput),
            2 => Some(Self::OutputBufferTooSmall),
            3 => Some(Self::MemoryAllocationFailed),
            _ => None,
        }
    }
}

/// Input parser for raw modexp bytes
pub struct InputParser<'a> {
    data: &'a [u8],
}

impl<'a> InputParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Parse all three length values from the header
    pub fn parse_lengths(&self) -> Option<(usize, usize, usize)> {
        if self.data.len() < HEADER_SIZE_BYTES {
            return None;
        }

        let base_len = self.parse_u256_at_offset(0);
        let exp_len = self.parse_u256_at_offset(32);
        let mod_len = self.parse_u256_at_offset(64);

        Some((base_len, exp_len, mod_len))
    }

    /// Parse a u256 value from bytes at the given offset
    /// Returns only the least significant bytes that fit in usize
    fn parse_u256_at_offset(&self, offset: usize) -> usize {
        if self.data.len() < offset + U256_SIZE_BYTES {
            return 0;
        }

        // For simplicity, just extract the last 4 bytes for u32, then convert to usize
        // This matches the Java implementation's behavior
        let start = offset + U256_SIZE_BYTES - 4;

        u32::from_be_bytes([
            self.data[start],
            self.data[start + 1],
            self.data[start + 2],
            self.data[start + 3],
        ]) as usize
    }
}

/// Result of calling modexp_precompiled, including parsed input for validation
#[derive(Debug)]
pub struct ModExpResult {
    pub output: Vec<u8>,
    pub parsed_input: parsing::ParsedModExpInput,
}

/// Safe wrapper for calling the modexp_precompiled C function via FFI
///
/// This function provides a safe interface to the unsafe FFI call by:
/// - Validating all input lengths before calling the C function
/// - Ensuring output buffer is properly sized to match the modulus length
/// - Checking for integer overflows in size calculations
/// - Validating the returned output length
/// - Returning parsed input data for validation consistency
///
/// # Returns
/// - `Ok(ModExpResult)` containing the result and parsed input on success
/// - `Err(u32)` containing the error code on failure
pub fn call_modexp_precompiled(input: &[u8]) -> Result<ModExpResult, u32> {
    // Validate and parse input
    let parser = InputParser::new(input);
    let (base_len, exp_len, mod_len) = parser
        .parse_lengths()
        .ok_or(ModExpError::InvalidInput as u32)?;

    // Validate lengths are within bounds
    if !validate_lengths(base_len, exp_len, mod_len) {
        return Err(ModExpError::InvalidInput as u32);
    }

    // Special case: both base_len and mod_len are zero returns empty
    // This matches the behavior in lib.rs line 88-89
    if base_len == 0 && mod_len == 0 {
        let parsed = parsing::ParsedModExpInput::from_raw_input(input, base_len, exp_len, mod_len);
        return Ok(ModExpResult {
            output: Vec::new(),
            parsed_input: parsed,
        });
    }

    // Parse the input using the shared parsing logic
    // This ensures validation sees exactly what the implementation sees
    let parsed = parsing::ParsedModExpInput::from_raw_input(input, base_len, exp_len, mod_len);

    // Check for integer overflow in total input size
    let total_data_size = base_len
        .checked_add(exp_len)
        .and_then(|sum| sum.checked_add(mod_len))
        .ok_or(ModExpError::InvalidInput as u32)?;

    // Validate input has sufficient data
    let required_input_size = HEADER_SIZE_BYTES
        .checked_add(total_data_size)
        .ok_or(ModExpError::InvalidInput as u32)?;

    if input.len() < required_input_size {
        return Err(ModExpError::InvalidInput as u32);
    }

    // Prepare output buffer - exactly mod_len bytes (matching lib.rs behavior)
    // The actual implementation always returns mod_len bytes (or empty for zero modulus)
    let buffer_size = calculate_output_buffer_size(mod_len)?;
    let mut output_buffer = vec![0u8; buffer_size];
    let mut actual_output_len = buffer_size as u32;

    // Call the C function via FFI
    let result = modexp_precompiled(
        input.as_ptr() as *const std::os::raw::c_char,
        input.len() as u32,
        output_buffer.as_mut_ptr() as *mut std::os::raw::c_char,
        &mut actual_output_len,
    );

    match result {
        0 => {
            // Validate output length is sensible
            if actual_output_len as usize > buffer_size {
                return Err(ModExpError::OutputBufferTooSmall as u32);
            }
            // Success - resize buffer to actual output length
            output_buffer.truncate(actual_output_len as usize);
            Ok(ModExpResult {
                output: output_buffer,
                parsed_input: parsed,
            })
        }
        error_code => Err(error_code),
    }
}

/// Validate that all length values are within acceptable bounds
pub fn validate_lengths(base_len: usize, exp_len: usize, mod_len: usize) -> bool {
    base_len <= MAX_COMPONENT_LENGTH as usize
        && exp_len <= MAX_COMPONENT_LENGTH as usize
        && mod_len <= MAX_COMPONENT_LENGTH as usize
}

/// Calculate appropriate output buffer size based on modulus length
///
/// The buffer size should be exactly mod_len bytes to match the Java implementation.
/// For zero-length modulus, we return 0 (the actual modexp function will handle this
/// and return empty vector for zero modulus).
pub fn calculate_output_buffer_size(mod_len: usize) -> Result<usize, u32> {
    // Simply return the modulus length as the buffer size
    // This matches the Java implementation which expects exactly mod_len bytes
    Ok(mod_len)
}

/// Validation helpers for property-based testing
#[cfg(any(test, feature = "fuzzing-utils"))]
pub mod validation {
    use super::*;

    /// Validate that the output conforms to expected properties
    pub fn validate_output(output: &[u8], expected_size: usize) {
        assert_eq!(
            output.len(),
            expected_size,
            "Output length {} does not match expected {}",
            output.len(),
            expected_size
        );
    }

    /// Validate that the result is less than the modulus
    /// Uses the parsed modulus to ensure consistency with implementation
    pub fn validate_result_less_than_modulus(output: &[u8], parsed_modulus: &[u8], mod_len: usize) {
        if parsed_modulus.is_empty() {
            return;
        }

        // The output should be exactly mod_len bytes (padded with leading zeros if necessary)
        assert_eq!(output.len(), mod_len, "Output length should equal mod_len");
        assert_eq!(
            parsed_modulus.len(),
            mod_len,
            "Parsed modulus length should equal mod_len"
        );

        // If modulus is non-zero, result should be strictly less
        if parsed_modulus.iter().any(|&x| x != 0) {
            // Compare as big-endian integers
            for i in 0..mod_len {
                match output[i].cmp(&parsed_modulus[i]) {
                    std::cmp::Ordering::Greater => {
                        panic!("Result is not less than modulus at byte {}", i);
                    }
                    std::cmp::Ordering::Less => {
                        // Result is definitely less than modulus
                        return;
                    }
                    std::cmp::Ordering::Equal => {
                        // Continue checking next bytes
                    }
                }
            }
            // If we get here, output == modulus, which is invalid
            panic!("Result equals modulus, should be strictly less");
        }
    }

    /// Validate known mathematical properties using parsed data
    pub fn validate_mathematical_properties(parsed: &parsing::ParsedModExpInput, output: &[u8]) {
        // Property: base^0 mod m = 1 (for any base, including 0)
        // This matches Ethereum's EIP-198 specification where 0^0 = 1
        if parsed.exponent.is_empty() || parsed.exponent.iter().all(|&x| x == 0) {
            if !parsed.modulus.is_empty() && parsed.modulus.iter().any(|&x| x != 0) {
                // Result should be 1
                let expected = vec![0u8; parsed.mod_len.saturating_sub(1)]
                    .into_iter()
                    .chain(std::iter::once(1))
                    .collect::<Vec<_>>();
                assert_eq!(output, expected.as_slice(), "base^0 mod m should equal 1");
            }
        }

        // Property: 0^exp mod m = 0 (for exp > 0)
        if parsed.base.is_empty() || parsed.base.iter().all(|&x| x == 0) {
            if !parsed.exponent.is_empty() && parsed.exponent.iter().any(|&x| x != 0) {
                assert!(output.iter().all(|&x| x == 0), "0^exp mod m should equal 0");
            }
        }
    }

    /// Validate that error conditions make sense
    pub fn validate_error_condition(error: ModExpError, base_len: u32, exp_len: u32, mod_len: u32) {
        match error {
            ModExpError::InvalidInput => {
                // This is expected for various input validation failures
            }
            ModExpError::OutputBufferTooSmall => {
                // This should generally not happen since we allocate exactly mod_len bytes
                // It could only happen if the FFI function has a bug
            }
            ModExpError::MemoryAllocationFailed => {
                // This should only happen with extremely large inputs
                let total_size = (base_len as u64) + (exp_len as u64) + (mod_len as u64);
                assert!(
                    total_size > 100_000,
                    "Memory allocation failure unexpected for small inputs"
                );
            }
        }
    }
}

