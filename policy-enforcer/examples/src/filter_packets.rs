use anyhow::Result;
use redbpf::load::Loader;
use redbpf::HashMap as BpfHashMap;
use std::convert::TryInto;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod policy_engine;
use policy_engine::{PolicyEngine, encode_action_relation, Action, Relation};

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
    // 1️⃣ Load policy engine and snapshot
    let engine = Arc::new(PolicyEngine::new());
    engine.load_snapshot("../policy_snapshots/policy_snapshot_v13.json")?;
    println!("Loaded policy snapshot v{}", engine.version());

    // 2️⃣ Load compiled eBPF program
    let mut loader = Loader::load_file("../ebpf/target/bpf/programs/filter_packet/filter_packet.elf")?;
    let xdp_map = loader.map("relation_map").expect("eBPF map not found");
    let mut bpf_map = BpfHashMap::<RelationKey, u8>::new(xdp_map).unwrap();

    // 3️⃣ Populate eBPF map from snapshot
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

    // 4️⃣ Attach XDP program to interface
    // Replace "eth0" with your HQ interface
    for prog in loader.xdps_mut() {
        prog.attach_xdp("eth0")?;
    }
    println!("XDP filter attached to eth0");

    // 5️⃣ Optional: simulate incoming packet checks in userspace
    let sender_id = "RN-01";
    let target_id = "HQ-01";
    let action_relation = encode_action_relation(Action::Telemetry, Relation::FromParentHQ);

    let allowed = engine.check(sender_id, target_id, 0x10, 0x04); // relation 0x10 = FromParentHQ, action 0x04 = Telemetry
    if allowed {
        println!("Packet from {} -> {} ALLOWED", sender_id, target_id);
    } else {
        println!("Packet from {} -> {} DENIED", sender_id, target_id);
    }

    // 6️⃣ Keep main thread alive to maintain XDP attachment
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
