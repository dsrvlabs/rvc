//! BnManager config surface tests relocated from bin/rvc tier suites.
//!
//! Pure `HealthTier`/`BnRole` unit coverage already lives in `types.rs`.
//! These cases exercise `BnManagerConfig` defaults and BroadcastTopics
//! wiring that the unit module does not cover.

use std::collections::HashSet;

use rvc_bn_manager::{
    BnManager, BnManagerConfig, BnRole, BroadcastTopics, HealthTier, TierThresholds,
};

#[test]
fn bn_manager_config_carries_broadcast_topics() {
    let topics = BroadcastTopics {
        attestations: true,
        blocks: false,
        sync_committee: true,
        subscriptions: false,
    };
    let mut config = BnManagerConfig::new(vec!["http://bn:5052".to_string()]);
    config.broadcast_topics = topics.clone();
    assert_eq!(config.broadcast_topics, topics);
}

#[test]
fn bn_manager_constructed_with_custom_topics() {
    let mut config = BnManagerConfig::new(vec!["http://bn:5052".to_string()]);
    config.broadcast_topics = BroadcastTopics {
        attestations: false,
        blocks: true,
        sync_committee: false,
        subscriptions: false,
    };
    let manager = BnManager::new(config);
    assert!(manager.is_ok());
}

#[test]
fn default_role_is_all() {
    let config = BnManagerConfig::new(vec!["http://bn:5052".to_string()]);
    assert_eq!(config.roles.len(), 1);
    assert!(config.roles[0].contains(&BnRole::All));
}

#[test]
fn role_plus_tier_composition() {
    let thresholds = TierThresholds::default();

    let tier_a = thresholds.tier_for_distance(5);
    let mut roles_a = HashSet::new();
    roles_a.insert(BnRole::Proposal);

    let tier_b = thresholds.tier_for_distance(12);
    let mut roles_b = HashSet::new();
    roles_b.insert(BnRole::Attestation);

    assert!(BnRole::matches(&roles_a, BnRole::Proposal));
    assert!(tier_a <= HealthTier::Synced);

    assert!(BnRole::matches(&roles_b, BnRole::Attestation));
    assert!(tier_b <= HealthTier::SmallLag);

    assert!(!BnRole::matches(&roles_b, BnRole::Proposal));
}

#[test]
fn role_based_with_health_tiers() {
    let thresholds = TierThresholds::default();

    let tier_1 = thresholds.tier_for_distance(2);
    let mut roles_1 = HashSet::new();
    roles_1.insert(BnRole::Proposal);

    let tier_2 = thresholds.tier_for_distance(10);
    let mut roles_2 = HashSet::new();
    roles_2.insert(BnRole::Attestation);

    let tier_3 = thresholds.tier_for_distance(100);
    let mut roles_3 = HashSet::new();
    roles_3.insert(BnRole::All);

    assert!(BnRole::matches(&roles_1, BnRole::Proposal) && tier_1 <= HealthTier::Synced);
    assert!(!BnRole::matches(&roles_2, BnRole::Proposal));
    assert!(BnRole::matches(&roles_3, BnRole::Proposal));
    assert!(tier_3 > HealthTier::Synced);

    assert!(!BnRole::matches(&roles_1, BnRole::Attestation));
    assert!(BnRole::matches(&roles_2, BnRole::Attestation) && tier_2 <= HealthTier::SmallLag);
}
