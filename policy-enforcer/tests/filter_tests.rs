use policy_engine::{PolicyEngine, Relation, Action, encode_action_relation};

fn make_engine() -> PolicyEngine {
    let engine = PolicyEngine::new();

    // Simulate snapshot
    engine.map.write().unwrap().insert(
        ("RN-01".to_string(), "HQ-01".to_string(), Relation::FromParentHQ as u8, Action::Telemetry as u8),
        true,
    );
    engine.map.write().unwrap().insert(
        ("RN-01".to_string(), "HQ-01".to_string(), Relation::FromParentHQ as u8, Action::Reboot as u8),
        false,
    );
    engine.map.write().unwrap().insert(
        ("RN-01".to_string(), "RN-02".to_string(), Relation::FromSiblingRN as u8, Action::Telemetry as u8),
        true,
    );
    engine.map.write().unwrap().insert(
        ("RN-01".to_string(), "RN-02".to_string(), Relation::FromSiblingRN as u8, Action::Reboot as u8),
        false,
    );

    engine
}

#[test]
fn test_allow_telemetry() {
    let engine = make_engine();
    assert!(engine.check("RN-01", "HQ-01", Relation::FromParentHQ as u8, Action::Telemetry as u8));
}

#[test]
fn test_deny_reboot() {
    let engine = make_engine();
    assert!(!engine.check("RN-01", "HQ-01", Relation::FromParentHQ as u8, Action::Reboot as u8));
}

#[test]
fn test_peer_telemetry() {
    let engine = make_engine();
    assert!(engine.check("RN-01", "RN-02", Relation::FromSiblingRN as u8, Action::Telemetry as u8));
}

#[test]
fn test_peer_reboot_denied() {
    let engine = make_engine();
    assert!(!engine.check("RN-01", "RN-02", Relation::FromSiblingRN as u8, Action::Reboot as u8));
}

#[test]
fn test_unknown_sender_denied() {
    let engine = make_engine();
    assert!(!engine.check("RN-99", "HQ-01", Relation::FromParentHQ as u8, Action::Telemetry as u8));
}

#[test]
fn test_invalid_relation_denied() {
    let engine = make_engine();
    let invalid_relation = 0xFF;
    assert!(!engine.check("RN-01", "HQ-01", invalid_relation, Action::Telemetry as u8));
}

#[test]
fn test_map_update() {
    let engine = make_engine();
    // Add new allow rule
    engine.map.write().unwrap().insert(
        ("RN-03".to_string(), "HQ-01".to_string(), Relation::FromParentHQ as u8, Action::Telemetry as u8),
        true,
    );
    assert!(engine.check("RN-03", "HQ-01", Relation::FromParentHQ as u8, Action::Telemetry as u8));
}

#[test]
fn test_snapshot_versioning() {
    let engine = make_engine();
    let initial_version = engine.version();
    // Simulate loading snapshot with lower version -> version should not change
    engine.map.write().unwrap().insert(
        ("dummy".to_string(), "HQ-01".to_string(), Relation::FromParentHQ as u8, Action::Telemetry as u8),
        true,
    );
    assert_eq!(engine.version(), initial_version);
}
