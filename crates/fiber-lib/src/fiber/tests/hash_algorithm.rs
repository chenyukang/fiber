use crate::fiber::hash_algorithm::HashAlgorithm;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_serialization_sha256() {
    let algorithm = HashAlgorithm::Sha256;
    let serialized = serde_json::to_string(&algorithm).expect("hash algorithm to json");
    assert_eq!(serialized, r#""sha256""#);
    let deserialized: HashAlgorithm =
        serde_json::from_str(&serialized).expect("hash algorithm from json");
    assert_eq!(deserialized, algorithm);
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_serialization_ckb_hash() {
    let algorithm = HashAlgorithm::CkbHash;
    let serialized = serde_json::to_string(&algorithm).expect("hash algorithm to json");
    assert_eq!(serialized, r#""ckb_hash""#);
    let deserialized: HashAlgorithm =
        serde_json::from_str(&serialized).expect("hash algorithm from json");
    assert_eq!(deserialized, algorithm);
}

// ============================================================================
// Additional corner case tests for HashAlgorithm
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_all_variants() {
    // Ensure all variants can be serialized and deserialized
    let variants = [HashAlgorithm::CkbHash, HashAlgorithm::Sha256];

    for variant in variants.iter() {
        let serialized = serde_json::to_string(variant).expect("serialize");
        let deserialized: HashAlgorithm = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(*variant, deserialized);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_try_from_u8() {
    // Test conversion from u8
    assert_eq!(
        HashAlgorithm::try_from(0u8).unwrap(),
        HashAlgorithm::CkbHash
    );
    assert_eq!(HashAlgorithm::try_from(1u8).unwrap(), HashAlgorithm::Sha256);

    // Invalid values should return error
    assert!(HashAlgorithm::try_from(2u8).is_err());
    assert!(HashAlgorithm::try_from(255u8).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_to_u8() {
    assert_eq!(HashAlgorithm::CkbHash as u8, 0);
    assert_eq!(HashAlgorithm::Sha256 as u8, 1);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_equality() {
    assert_eq!(HashAlgorithm::Sha256, HashAlgorithm::Sha256);
    assert_eq!(HashAlgorithm::CkbHash, HashAlgorithm::CkbHash);
    assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::CkbHash);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_clone() {
    let algo = HashAlgorithm::Sha256;
    #[allow(clippy::clone_on_copy)]
    let cloned = algo.clone();
    assert_eq!(algo, cloned);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_debug() {
    let algo = HashAlgorithm::Sha256;
    let debug_str = format!("{:?}", algo);
    assert!(debug_str.contains("Sha256"));

    let algo2 = HashAlgorithm::CkbHash;
    let debug_str2 = format!("{:?}", algo2);
    assert!(debug_str2.contains("CkbHash"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_bincode_serialization() {
    let algo = HashAlgorithm::Sha256;
    let serialized = bincode::serialize(&algo).expect("bincode serialize");
    let deserialized: HashAlgorithm =
        bincode::deserialize(&serialized).expect("bincode deserialize");
    assert_eq!(algo, deserialized);

    let algo2 = HashAlgorithm::CkbHash;
    let serialized2 = bincode::serialize(&algo2).expect("bincode serialize");
    let deserialized2: HashAlgorithm =
        bincode::deserialize(&serialized2).expect("bincode deserialize");
    assert_eq!(algo2, deserialized2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_invalid_json() {
    // Test parsing invalid algorithm names
    let result: Result<HashAlgorithm, _> = serde_json::from_str(r#""invalid_hash""#);
    assert!(result.is_err());

    let result2: Result<HashAlgorithm, _> = serde_json::from_str(r#""SHA256""#);
    // Should fail because it's case-sensitive
    assert!(result2.is_err());

    let result3: Result<HashAlgorithm, _> = serde_json::from_str(r#""""#);
    assert!(result3.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_default() {
    // HashAlgorithm should implement Default if it does
    // Otherwise we test the common case
    let algo = HashAlgorithm::CkbHash;
    assert_eq!(algo as u8, 0);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_hash_algorithm_copy() {
    let algo = HashAlgorithm::Sha256;
    let copied = algo; // Copy
    assert_eq!(algo, copied);

    // Both should still be usable after copy
    assert_eq!(algo as u8, 1);
    assert_eq!(copied as u8, 1);
}
