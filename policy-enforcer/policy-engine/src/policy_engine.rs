use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, RwLock};

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Relation {
    FromParentHQ = 0x10,
    FromSiblingRN = 0x20,
    FromCC = 0x30,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Action {
    Reboot = 0x01,
    SetConfig = 0x02,
    StatusUpdate = 0x03,
    Telemetry = 0x04,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RelationEntry {
    pub sender: String,
    pub target: String,
    pub relation: u8,
    pub action: u8,
    pub allow: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PolicySnapshot {
    pub version: u64,
    pub timestamp: u64,
    pub entries: Vec<RelationEntry>,
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct PolicyEngine {
    pub map: Arc<RwLock<HashMap<(String, String, u8, u8), bool>>>,
    version: Arc<RwLock<u64>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            map: Arc::new(RwLock::new(HashMap::new())),
            version: Arc::new(RwLock::new(0)),
        }
    }

    pub fn load_snapshot(&self, path: &str) -> anyhow::Result<()> {
        let data = fs::read(path)?;
        let snapshot: PolicySnapshot = serde_json::from_slice(&data)?;

        let mut map = self.map.write().unwrap();
        map.clear();

        for entry in snapshot.entries {
            map.insert(
                (entry.sender.clone(), entry.target.clone(), entry.relation, entry.action),
                entry.allow,
            );
        }

        let mut ver = self.version.write().unwrap();
        if snapshot.version > *ver {
            *ver = snapshot.version;
        }

        Ok(())
    }

    pub fn check(&self, sender: &str, target: &str, relation: u8, action: u8) -> bool {
        let map = self.map.read().unwrap();
        map.get(&(sender.to_string(), target.to_string(), relation, action))
            .copied()
            .unwrap_or(false)
    }

    pub fn version(&self) -> u64 {
        *self.version.read().unwrap()
    }
}

/// Combine relation + action into a single byte
pub fn encode_action_relation(action: Action, relation: Relation) -> u8 {
    ((relation as u8) & 0xF0) | ((action as u8) & 0x0F)
}
