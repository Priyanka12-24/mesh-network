use anyhow::Result;
use redbpf::load::Loader;
use redbpf::HashMap as BpfHashMap;
use std::fs;
use std::convert::TryInto;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod policy_engine;
use policy_engine::{PolicyEngine, RelationEntry, encode_action_relation, Action, Relation};

/// eBPF map key format
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RelationKey {
    sender: [u8; 8],
    target: [u8; 8],
    action_relation: u8,
    padding: u8,
}

fn main() -> Result<()> {
    // --- 1. Load Policy Engine ---
    let engine = Arc::new(PolicyEngine::new());
    engine.load_snapshot("policy_snapshot_v13.json")?;
    println!("Loaded policy snapshot v{}", engine.version());

    // --- 2. Load eBPF program ---
    let mut loader = Loader::load_file("ebpf/target/bpf/programs/filter_packet/filter_packet.elf")?;
    let xdp_map = loader.map("relation_map").expect("eBPF map not found");
    let mut bpf_map = BpfHashMap::<RelationKey, u8>::new(xdp_map).unwrap();

    // --- 3. Populate eBPF map from policy ---
    for (k, &allow) in engine.map.read().unwrap().iter() {
        let sender_bytes: [u8; 8] = k.0.as_bytes()[0..8].try_into().unwrap();
        let target_bytes: [u8; 8] = k.1.as_bytes()[0..8].try_into().unwrap();
        let action_relation: u8 = (k.2 & 0xF0) | (k.3 & 0x0F);
        let key = RelationKey {
            sender: sender_bytes,
            target: target_bytes,
            action_relation,
            padding: 0,
        };
        bpf_map.set(&key, &if allow { 1u8 } else { 0u8 })?;
    }
    println!("eBPF map populated with {} rules", engine.map.read().unwrap().len());

    // --- 4. Attach XDP program to interface ---
    // Replace "eth0" with your interface
    for prog in loader.xdps_mut() {
        prog.attach_xdp("eth0")?;
    }
    println!("XDP filter attached to eth0");

    // --- 5. Keep updating map every X minutes ---
    let engine_clone = engine.clone();
    thread::spawn(move || loop {
        // In production: pull snapshot updates from CC
        // For demo, reload same snapshot
        engine_clone.load_snapshot("policy_snapshot_v13.json").unwrap();

        // Update eBPF map
        for (k, &allow) in engine_clone.map.read().unwrap().iter() {
            let sender_bytes: [u8; 8] = k.0.as_bytes()[0..8].try_into().unwrap();
            let target_bytes: [u8; 8] = k.1.as_bytes()[0..8].try_into().unwrap();
            let action_relation: u8 = (k.2 & 0xF0) | (k.3 & 0x0F);
            let key = RelationKey {
                sender: sender_bytes,
                target: target_bytes,
                action_relation,
                padding: 0,
            };
            bpf_map.set(&key, &if allow { 1u8 } else { 0u8 }).unwrap();
        }
        println!("Policy snapshot reloaded, eBPF map updated.");
        thread::sleep(Duration::from_secs(60)); // pull interval
    });

    // --- 6. Keep main thread alive ---
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
