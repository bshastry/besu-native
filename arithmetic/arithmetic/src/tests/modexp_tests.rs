use crate::testing::{call_modexp_precompiled, ModExpError, ModExpResult, MAX_COMPONENT_LENGTH};

#[test]
fn test_zero_length_modulus() {
    let input = vec![0u8; 96]; // All zeros - zero length for all components
    let result = call_modexp_precompiled(&input);
    assert!(result.unwrap().output.is_empty());
}

#[test]
fn test_maximum_lengths() {
    let mut input = vec![0u8; 96];
    // Set maximum lengths (MAX_COMPONENT_LENGTH) for all components
    input[28..32].copy_from_slice(&(MAX_COMPONENT_LENGTH as u32).to_be_bytes());
    input[60..64].copy_from_slice(&(MAX_COMPONENT_LENGTH as u32).to_be_bytes());
    input[92..96].copy_from_slice(&(MAX_COMPONENT_LENGTH as u32).to_be_bytes());

    // Add minimal data
    input.extend(vec![1u8; (MAX_COMPONENT_LENGTH * 3) as usize]);

    let result = call_modexp_precompiled(&input);
    assert!(result.is_ok());
}

#[test]
fn test_overflow_detection() {
    let mut input = vec![0u8; 96];
    // Set base length to value that would overflow when combined with others
    // Using a large but more realistic value (2^31)
    input[28..32].copy_from_slice(&0x80000000u32.to_be_bytes());

    let result = call_modexp_precompiled(&input);
    assert_eq!(result.unwrap_err(), ModExpError::InvalidInput as u32);
}

#[test]
fn test_length_just_above_limit() {
    let mut input = vec![0u8; 96];
    // Set base length to MAX_COMPONENT_LENGTH + 1
    input[28..32].copy_from_slice(&((MAX_COMPONENT_LENGTH + 1) as u32).to_be_bytes());
    // Set reasonable values for exp and mod
    input[60..64].copy_from_slice(&32u32.to_be_bytes());
    input[92..96].copy_from_slice(&32u32.to_be_bytes());

    // Add some data (not enough for the declared length)
    input.extend(vec![1u8; (MAX_COMPONENT_LENGTH + 1 + 32 + 32) as usize]); // MAX_COMPONENT_LENGTH + 1 + 32 + 32

    let result = call_modexp_precompiled(&input);
    assert_eq!(result.unwrap_err(), ModExpError::InvalidInput as u32);
}

#[test]
fn test_partial_data_scenario() {
    let mut input = vec![0u8; 96];
    // Declare 256 bytes for each component
    input[28..32].copy_from_slice(&256u32.to_be_bytes());
    input[60..64].copy_from_slice(&256u32.to_be_bytes());
    input[92..96].copy_from_slice(&256u32.to_be_bytes());

    // Only provide 512 bytes of data (instead of 768)
    input.extend(vec![1u8; 512]);

    let result = call_modexp_precompiled(&input);
    // Should fail due to insufficient data
    assert_eq!(result.unwrap_err(), ModExpError::InvalidInput as u32);
}

#[test]
fn test_boundary_at_max_length() {
    let mut input = vec![0u8; 96];
    // Set all lengths to exactly MAX_COMPONENT_LENGTH
    input[28..32].copy_from_slice(&(MAX_COMPONENT_LENGTH as u32).to_be_bytes());
    input[60..64].copy_from_slice(&(MAX_COMPONENT_LENGTH as u32).to_be_bytes());
    input[92..96].copy_from_slice(&(MAX_COMPONENT_LENGTH as u32).to_be_bytes());

    // Provide exactly the required data
    input.extend(vec![1u8; (MAX_COMPONENT_LENGTH * 3) as usize]); // MAX_COMPONENT_LENGTH * 3

    let result = call_modexp_precompiled(&input);
    // Should succeed as it's exactly at the limit
    assert!(result.is_ok());
}

#[test]
fn test_modexp_precompiled() {
    let mut input = vec![0u8; 96];
    input[31] = 1; // base_len = 1
    input[63] = 1; // exp_len = 1
    input[95] = 1; // mod_len = 1
    input.push(2); // base = 2
    input.push(3); // exp = 3
    input.push(5); // mod = 5

    let result = call_modexp_precompiled(&input);
    assert!(result.is_ok());
    let ModExpResult {
        output,
        parsed_input,
    } = result.unwrap();
    assert_eq!(output.len(), 1); // Expect output length to be 1
    assert_eq!(output[0], 3); // Expect output to be 3 (2^3 % 5 = 3)

    // Verify parsed input matches what we provided
    assert_eq!(parsed_input.base, vec![2]);
    assert_eq!(parsed_input.exponent, vec![3]);
    assert_eq!(parsed_input.modulus, vec![5]);
}

#[test]
fn test_right_padding_behavior() {
    // This test verifies that the validation logic correctly handles
    // right-padding expectations. The implementation right-pads data
    // when reading beyond the provided input.

    use crate::parsing;
    use crate::testing::validation::validate_result_less_than_modulus;

    // Test the validation function with right-padded data
    let output = vec![0xDF, 0x02, 0x62, 0x22]; // 4 bytes

    // Create input that will result in right-padded modulus
    let mut input = vec![0u8; 96];
    input[31] = 1; // base_len = 1
    input[63] = 1; // exp_len = 1
    input[95] = 4; // mod_len = 4
    input.push(2); // base = 2
    input.push(1); // exp = 1
    input.extend_from_slice(&[0xFF, 0xFF]); // Only 2 bytes of modulus data

    // Parse input to get right-padded modulus
    let parsed = parsing::ParsedModExpInput::from_raw_input(&input, 1, 1, 4);

    // The modulus will be right-padded: [0xFF, 0xFF, 0x00, 0x00]
    assert_eq!(parsed.modulus, vec![0xFF, 0xFF, 0x00, 0x00]);

    // Output [0xDF, 0x02, 0x62, 0x22] < [0xFF, 0xFF, 0x00, 0x00]
    // This should not panic
    validate_result_less_than_modulus(&output, &parsed.modulus, 4);
}

#[test]
fn test_zero_power_zero_behavior() {
    // Test what 0^0 mod m actually returns in this implementation

    // Test case 1: 0^0 mod 5
    let mut input = vec![0u8; 96];
    input[31] = 1; // base_len = 1
    input[63] = 1; // exp_len = 1
    input[95] = 1; // mod_len = 1
    input.push(0); // base = 0
    input.push(0); // exp = 0
    input.push(5); // mod = 5

    let result = call_modexp_precompiled(&input);
    assert!(result.is_ok());
    let ModExpResult {
        output,
        parsed_input,
    } = result.unwrap();

    println!("0^0 mod 5 = {}", output[0]);

    // Test case 2: Compare with non-zero base
    let mut input2 = vec![0u8; 96];
    input2[31] = 1; // base_len = 1
    input2[63] = 1; // exp_len = 1
    input2[95] = 1; // mod_len = 1
    input2.push(7); // base = 7
    input2.push(0); // exp = 0
    input2.push(5); // mod = 5

    let result2 = call_modexp_precompiled(&input2);
    assert!(result2.is_ok());
    let ModExpResult {
        output: output2, ..
    } = result2.unwrap();

    println!("7^0 mod 5 = {}", output2[0]);

    // Verify that 0^0 mod m = 1 (standard behavior per EIP-198)
    assert_eq!(output[0], 1, "0^0 mod 5 should equal 1");
    assert_eq!(output2[0], 1, "7^0 mod 5 should equal 1");

    // Verify parsed input for 0^0 case
    assert_eq!(parsed_input.base, vec![0]);
    assert_eq!(parsed_input.exponent, vec![0]);
    assert_eq!(parsed_input.modulus, vec![5]);

    // This confirms the current validation in testing.rs is correct:
    // For any base (including 0), base^0 mod m = 1
}

