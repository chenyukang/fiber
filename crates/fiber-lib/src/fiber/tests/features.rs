use crate::fiber::features::{
    feature_bits::{GOSSIP_QUERIES_OPTIONAL, GOSSIP_QUERIES_REQUIRED},
    *,
};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_bits() {
    let mut vector = FeatureVector::new();

    assert!(vector.is_empty());
    // Set some feature bits
    vector.set_feature(GOSSIP_QUERIES_REQUIRED);

    vector.set_feature(GOSSIP_QUERIES_OPTIONAL);

    // Check if the bits are set correctly
    assert!(vector.requires_feature(GOSSIP_QUERIES_REQUIRED));
    assert!(!vector.requires_feature(GOSSIP_QUERIES_OPTIONAL));

    assert!(vector.supports_feature(GOSSIP_QUERIES_REQUIRED));
    assert!(vector.supports_feature(GOSSIP_QUERIES_OPTIONAL));

    vector.set_basic_mpp_optional();

    assert!(vector.supports_basic_mpp());
    assert!(!vector.requires_basic_mpp());

    vector.set_basic_mpp_required();
    assert!(vector.supports_basic_mpp());
    assert!(vector.requires_basic_mpp());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_support_and_requires() {
    let mut vector = FeatureVector::new();

    vector.set_basic_mpp_optional();

    assert!(vector.supports_basic_mpp());
    assert!(!vector.requires_basic_mpp());

    vector.set_basic_mpp_required();
    assert!(vector.supports_basic_mpp());
    assert!(vector.requires_basic_mpp());

    vector.unset_basic_mpp_optional();
    assert!(vector.supports_basic_mpp());
    assert!(vector.requires_basic_mpp());

    vector.unset_basic_mpp_required();
    assert!(!vector.supports_basic_mpp());
    assert!(!vector.requires_basic_mpp());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_names() {
    let mut vector = FeatureVector::new();
    let debug_str = format!("{:?}", vector);
    assert!(debug_str.contains("FeatureVector"));
    assert!(debug_str.contains("features"));

    vector.set_basic_mpp_optional();
    assert_eq!(
        vector.enabled_features_names(),
        ["BASIC_MPP_OPTIONAL".to_string()]
    );
    vector.set_basic_mpp_required();
    assert_eq!(
        vector.enabled_features_names(),
        [
            "BASIC_MPP_REQUIRED".to_string(),
            "BASIC_MPP_OPTIONAL".to_string(),
        ]
    );

    vector.set_gossip_queries_required();
    assert_eq!(
        vector.enabled_features_names(),
        [
            "GOSSIP_QUERIES_REQUIRED".to_string(),
            "BASIC_MPP_REQUIRED".to_string(),
            "BASIC_MPP_OPTIONAL".to_string(),
        ]
    );
    vector.set_gossip_queries_optional();
    assert_eq!(
        vector.enabled_features_names(),
        [
            "GOSSIP_QUERIES_REQUIRED".to_string(),
            "GOSSIP_QUERIES_OPTIONAL".to_string(),
            "BASIC_MPP_REQUIRED".to_string(),
            "BASIC_MPP_OPTIONAL".to_string(),
        ]
    );

    vector.unset_gossip_queries_required();
    assert_eq!(
        vector.enabled_features_names(),
        [
            "GOSSIP_QUERIES_OPTIONAL".to_string(),
            "BASIC_MPP_REQUIRED".to_string(),
            "BASIC_MPP_OPTIONAL".to_string(),
        ]
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_serialize() {
    let mut vector = FeatureVector::new();
    vector.set_basic_mpp_optional();
    vector.set_basic_mpp_required();
    vector.set_gossip_queries_required();
    vector.set_gossip_queries_optional();

    let serialized = bincode::serialize(&vector).expect("Failed to serialize FeatureVector");
    let deserialized: FeatureVector =
        bincode::deserialize(&serialized).expect("Failed to deserialize FeatureVector");

    assert_eq!(vector, deserialized);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_default() {
    let vector = FeatureVector::default();
    assert!(vector.requires_gossip_queries());
    assert!(vector.supports_gossip_queries());
    assert!(vector.supports_basic_mpp());
    assert!(vector.requires_basic_mpp());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_random() {
    let mut vector = FeatureVector::new();

    for i in 0..512 {
        vector.set_feature(i as u16);
    }

    for i in 0..512 {
        assert!(vector.supports_feature(i as u16));
        if i % 2 == 0 {
            assert!(vector.requires_feature(i as u16));
        } else {
            assert!(!vector.requires_feature(i as u16));
        }
    }

    let features = vector.enabled_features_names();
    assert_eq!(
        features.last().unwrap().to_string(),
        "Unknown Feature".to_string()
    );

    for i in 0..512 {
        vector.unset_feature(i as u16);
    }

    for i in 0..512 {
        assert!(!vector.requires_feature(i as u16));
        assert!(!vector.supports_feature(i as u16));
    }
    assert!(vector.is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_compatibility() {
    let mut vector = FeatureVector::new();
    let mut vector2 = FeatureVector::new();

    assert!(vector.compatible_with(&vector2));

    vector.set_gossip_queries_required();
    assert!(!vector.compatible_with(&vector2));

    vector2.set_gossip_queries_optional();
    assert!(vector.compatible_with(&vector2));

    vector2.unset_gossip_queries_optional();
    assert!(!vector.compatible_with(&vector2));

    vector2.set_gossip_queries_required();
    assert!(vector.compatible_with(&vector2));
    vector2.unset_gossip_queries_required();
    assert!(!vector.compatible_with(&vector2));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_serialize_and_deserialize() {
    let mut vector = FeatureVector::new();
    vector.set_gossip_queries_required();
    vector.set_basic_mpp_optional();

    let serialized = bincode::serialize(&vector).expect("Failed to serialize FeatureVector");
    let deserialized: FeatureVector =
        bincode::deserialize(&serialized).expect("Failed to deserialize FeatureVector");

    assert_eq!(vector, deserialized);
    assert!(deserialized.supports_gossip_queries());
    assert!(deserialized.requires_gossip_queries());
    assert!(deserialized.supports_basic_mpp());
}

// ============================================================================
// Additional corner case tests for FeatureVector
// ============================================================================

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_empty() {
    let vector = FeatureVector::new();

    assert!(vector.is_empty());
    assert!(vector.enabled_features_names().is_empty());

    // Empty vector should be compatible with another empty vector
    let vector2 = FeatureVector::new();
    assert!(vector.compatible_with(&vector2));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_set_unset_same_feature() {
    let mut vector = FeatureVector::new();

    // Set and unset repeatedly
    for _ in 0..10 {
        assert!(!vector.supports_basic_mpp());
        vector.set_basic_mpp_optional();
        assert!(vector.supports_basic_mpp());
        vector.unset_basic_mpp_optional();
        assert!(!vector.supports_basic_mpp());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_unset_already_unset() {
    let mut vector = FeatureVector::new();

    // Unsetting a feature that's not set should be a no-op
    assert!(!vector.supports_basic_mpp());
    vector.unset_basic_mpp_optional();
    assert!(!vector.supports_basic_mpp());
    assert!(vector.is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_set_already_set() {
    let mut vector = FeatureVector::new();

    // Setting a feature that's already set should be a no-op
    vector.set_basic_mpp_optional();
    assert!(vector.supports_basic_mpp());
    vector.set_basic_mpp_optional();
    assert!(vector.supports_basic_mpp());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_high_bit_indices() {
    let mut vector = FeatureVector::new();

    // Test very high bit indices
    let high_bits = [100, 200, 300, 400, 500, 511];

    for bit in high_bits.iter() {
        vector.set_feature(*bit);
        assert!(vector.supports_feature(*bit));
    }

    // Verify all are still set
    for bit in high_bits.iter() {
        assert!(vector.supports_feature(*bit));
    }

    // Unset them all
    for bit in high_bits.iter() {
        vector.unset_feature(*bit);
        assert!(!vector.supports_feature(*bit));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_required_optional_interaction() {
    let mut vector = FeatureVector::new();

    // Setting required implies support
    vector.set_basic_mpp_required();
    assert!(vector.requires_basic_mpp());
    assert!(vector.supports_basic_mpp());

    // Unsetting required doesn't affect optional
    vector.unset_basic_mpp_required();
    assert!(!vector.requires_basic_mpp());
    // After unsetting required, optional should also be unset (based on bit positions)
    // Required is even bit, optional is odd bit

    // Now set optional only
    vector.set_basic_mpp_optional();
    assert!(!vector.requires_basic_mpp());
    assert!(vector.supports_basic_mpp());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_compatibility_one_way() {
    let mut required_vector = FeatureVector::new();
    let mut optional_vector = FeatureVector::new();

    required_vector.set_gossip_queries_required();
    optional_vector.set_gossip_queries_optional();

    // A vector requiring gossip_queries should be compatible with one supporting it
    assert!(required_vector.compatible_with(&optional_vector));
    // But the reverse may not hold if the optional one doesn't support the required feature
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_clone_and_equality() {
    let mut vector1 = FeatureVector::new();
    vector1.set_basic_mpp_optional();
    vector1.set_gossip_queries_required();

    let vector2 = vector1.clone();

    assert_eq!(vector1, vector2);
    assert!(vector2.supports_basic_mpp());
    assert!(vector2.requires_gossip_queries());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_json_serialization() {
    let mut vector = FeatureVector::new();
    vector.set_basic_mpp_optional();

    let json = serde_json::to_string(&vector).expect("serialize");
    let deserialized: FeatureVector = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(vector, deserialized);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_alternating_bits() {
    let mut vector = FeatureVector::new();

    // Set alternating bits (every other bit)
    for i in (0..100).step_by(4) {
        vector.set_feature(i);
    }

    // Verify the bits we set are set
    for i in (0..100).step_by(4) {
        assert!(vector.supports_feature(i), "Bit {} should be set", i);
    }

    // Unset them
    for i in (0..100).step_by(4) {
        vector.unset_feature(i);
    }

    // Verify they're unset
    for i in (0..100).step_by(4) {
        assert!(
            !vector.requires_feature(i),
            "Bit {} should not be required",
            i
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_all_bits_set_unset() {
    let mut vector = FeatureVector::new();

    // Set many bits
    for i in 0..64 {
        vector.set_feature(i);
    }

    assert!(!vector.is_empty());

    // Unset all bits
    for i in 0..64 {
        vector.unset_feature(i);
    }

    assert!(vector.is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_feature_vector_boundary_compatibility() {
    // Test compatibility at bit boundaries
    let mut vector1 = FeatureVector::new();
    let mut vector2 = FeatureVector::new();

    // Both empty - compatible
    assert!(vector1.compatible_with(&vector2));
    assert!(vector2.compatible_with(&vector1));

    // One has optional, other has nothing - compatible
    vector1.set_basic_mpp_optional();
    assert!(vector1.compatible_with(&vector2));
    assert!(vector2.compatible_with(&vector1));

    // One requires, other has optional - compatible
    vector1.set_basic_mpp_required();
    vector2.set_basic_mpp_optional();
    assert!(vector1.compatible_with(&vector2));
    assert!(vector2.compatible_with(&vector1));

    // Both require - compatible
    vector2.set_basic_mpp_required();
    assert!(vector1.compatible_with(&vector2));
    assert!(vector2.compatible_with(&vector1));
}
