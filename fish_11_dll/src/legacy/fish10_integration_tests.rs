//! Integration tests for the complete legacy fish_10 workflow
//!
//! These tests verify that the entire legacy fish_10 workflow works correctly,
//! including key exchange, encryption, and decryption.

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::crypto::{blowfish, dh1080};
    use crate::legacy::fish10_config::{get_encrypt_topic_setting, set_encrypt_topic_setting};
    use crate::legacy::fish10_key_management::store_legacy_key;
    use crate::legacy::{fish10_key_management, fish10_message_detection};

    /// Teardown: clear all legacy keys and DH1080 keys to prevent cross-test contamination
    fn teardown_legacy_state() {
        crate::legacy::test_utils::clear_test_legacy_keys();
        crate::legacy::test_utils::clear_test_dh1080_keys();
    }

    #[test]
    fn test_complete_dh1080_key_exchange_workflow() {
        // Step 1: Generate key pairs for both parties
        let alice_keypair = dh1080::generate_dh1080_keypair().unwrap();
        let bob_keypair = dh1080::generate_dh1080_keypair().unwrap();

        // Step 2: Compute shared secrets (both parties should get the same result)
        let alice_shared = dh1080::compute_dh1080_shared_secret(
            &alice_keypair.private_key(),
            &bob_keypair.public_key,
        )
        .unwrap();

        let bob_shared = dh1080::compute_dh1080_shared_secret(
            &bob_keypair.private_key(),
            &alice_keypair.public_key,
        )
        .unwrap();

        // Step 3: Verify the shared secrets match
        assert_eq!(alice_shared, bob_shared);
        assert!(!alice_shared.is_empty());
    }

    #[test]
    fn test_complete_legacy_encryption_decryption_workflow() {
        // Step 1: Generate a shared secret using DH1080 (simulating key exchange)
        let alice_keypair = dh1080::generate_dh1080_keypair().unwrap();
        let bob_keypair = dh1080::generate_dh1080_keypair().unwrap();

        let shared_secret = dh1080::compute_dh1080_shared_secret(
            &alice_keypair.private_key(),
            &bob_keypair.public_key,
        )
        .unwrap();

        // Step 2: Use the shared secret as the encryption key
        let encryption_key = shared_secret.as_bytes();

        // Step 3: Encrypt a message using Blowfish
        let plaintext = "Hello, this is a test message!";
        let encrypted = blowfish::encrypt_message(encryption_key, plaintext, &[]).unwrap();

        // Step 4: Decrypt the message using the same key
        let decrypted = blowfish::decrypt_message(encryption_key, &encrypted, &[]).unwrap();

        // Step 5: Verify the decrypted message matches the original
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_message_detection_and_parsing() {
        // Test that message detection works correctly
        let fish10_message = "+OK abcdef123456";
        assert!(fish10_message_detection::is_fish10_message(fish10_message));

        let payload = fish10_message_detection::extract_fish10_payload(fish10_message).unwrap();
        assert_eq!(payload, "abcdef123456");

        let mcps_message = "mcps xyz789";
        assert!(fish10_message_detection::is_fish10_message(mcps_message));

        let payload = fish10_message_detection::extract_fish10_payload(mcps_message).unwrap();
        assert_eq!(payload, "xyz789");

        let non_fish10_message = "Hello world";
        assert!(!fish10_message_detection::is_fish10_message(non_fish10_message));
    }

    #[test]
    fn test_legacy_key_storage_and_retrieval() {
        teardown_legacy_state();
        // Test storing and retrieving a legacy key
        let target = "test_user";
        let key = "test_shared_secret_key_12345";

        // Store the key
        store_legacy_key(target, key.as_bytes()).unwrap();

        // Retrieve the key
        let retrieved_key = fish10_key_management::get_legacy_key(target).unwrap();
        assert_eq!(key.as_bytes(), retrieved_key);

        // Test that a non-existent key returns None
        let non_existent_key = fish10_key_management::get_legacy_key("non_existent_user");
        assert!(non_existent_key.is_none() || non_existent_key.unwrap().is_empty());
    }

    #[test]
    fn test_legacy_encryption_with_stored_key() {
        teardown_legacy_state();
        // Test the complete workflow with key storage
        let target = "test_user";
        let plaintext = "This is a test message for legacy encryption";

        // Generate a shared secret (simulating DH1080 exchange)
        let keypair1 = dh1080::generate_dh1080_keypair().unwrap();
        let keypair2 = dh1080::generate_dh1080_keypair().unwrap();

        let shared_secret =
            dh1080::compute_dh1080_shared_secret(&keypair1.private_key(), &keypair2.public_key)
                .unwrap();

        // Store the shared secret as a legacy key
        fish10_key_management::store_legacy_key(target, shared_secret.as_bytes()).unwrap();

        // Encrypt the message using the stored key
        let key = fish10_key_management::get_legacy_key(target).unwrap();
        if !key.is_empty() {
            let encrypted = blowfish::encrypt_message(&key, plaintext, &[]).unwrap();

            // Decrypt the message using the same key
            let decrypted = blowfish::decrypt_message(&key, &encrypted, &[]).unwrap();

            // Verify the decrypted message matches the original
            assert_eq!(plaintext, decrypted);
        } else {
            panic!("Failed to retrieve stored key");
        }
    }

    #[test]
    fn test_dh1080_message_parsing() {
        // Test DH1080 message detection and parsing
        let init_message = "DH1080_INIT some_public_key_data";
        assert!(fish10_message_detection::is_dh1080_message(init_message));

        let message_type =
            fish10_message_detection::parse_dh1080_message_type(init_message).unwrap();
        assert_eq!(message_type, "INIT");

        let public_key = fish10_message_detection::extract_dh1080_public_key(init_message).unwrap();
        assert_eq!(public_key, "some_public_key_data");

        let finish_message = "DH1080_FINISH another_public_key";
        assert!(fish10_message_detection::is_dh1080_message(finish_message));

        let message_type =
            fish10_message_detection::parse_dh1080_message_type(finish_message).unwrap();
        assert_eq!(message_type, "FINISH");

        let public_key =
            fish10_message_detection::extract_dh1080_public_key(finish_message).unwrap();
        assert_eq!(public_key, "another_public_key");
    }

    #[test]
    fn test_legacy_topic_encryption_workflow() {
        teardown_legacy_state();
        // Test the complete topic encryption workflow
        let target = "#test_channel";
        let plaintext_topic = "This is a test topic for encryption";

        // Generate a shared secret (simulating DH1080 exchange)
        let keypair1 = dh1080::generate_dh1080_keypair().unwrap();
        let keypair2 = dh1080::generate_dh1080_keypair().unwrap();
        let shared_secret =
            dh1080::compute_dh1080_shared_secret(&keypair1.private_key(), &keypair2.public_key)
                .unwrap();

        // Convert the shared secret to hex for storage
        let shared_secret_hex = hex::encode(shared_secret.as_bytes());

        // Store the shared secret as a legacy key
        fish10_key_management::set_legacy_key(target, &shared_secret_hex).unwrap();

        // Encrypt the topic using the stored key
        if fish10_key_management::has_legacy_key(target) {
            // Get the key bytes from the stored hex
            let key_bytes = hex::decode(&shared_secret_hex).unwrap();

            // Encrypt the topic
            let encrypted = blowfish::encrypt_message(&key_bytes, plaintext_topic, &[]).unwrap();
            let _encrypted_with_prefix = format!("+OK {}", encrypted);

            // Decrypt the topic using the same key
            let decrypted = blowfish::decrypt_message(&key_bytes, &encrypted, &[]).unwrap();

            // Verify the decrypted topic matches the original
            assert_eq!(plaintext_topic, decrypted);
        } else {
            panic!("Failed to retrieve stored key");
        }
    }

    #[test]
    fn test_topic_encryption_settings() {
        // Test storing and retrieving topic encryption settings
        let network = "test_network_unique_12345";
        let channel = "#test_channel_unique_67890";

        // Set topic encryption to enabled
        let result = set_encrypt_topic_setting(network, channel, true);
        assert!(result.is_ok());

        // Check if the setting was stored correctly
        let result = get_encrypt_topic_setting(network, channel);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Set topic encryption to disabled
        let result = set_encrypt_topic_setting(network, channel, false);
        assert!(result.is_ok());

        // Check if the setting was updated correctly
        let result = get_encrypt_topic_setting(network, channel);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
