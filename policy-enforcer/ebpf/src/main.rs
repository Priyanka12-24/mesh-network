#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

/// Map shared with userspace policy engine
#[map("relation_map")]
static mut RELATION_MAP: HashMap<RelationKey, u8> = HashMap::with_max_entries(1024);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RelationKey {
    sender: [u8; 8],
    target: [u8; 8],
    action_relation: u8, // upper 4 bits relation, lower 4 bits action
    padding: u8,
}

#[xdp]
fn filter_packet(ctx: XdpContext) -> XdpResult {
    // Minimal parse: assume first 18 bytes are:
    // [sender_id(8) | target_id(8) | action_relation(1) | padding(1)]
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data.offset(18).unwrap_or(data_end) > data_end {
        return Ok(XdpAction::Pass);
    }

    let ptr = data.as_ptr();
    let sender_id: [u8; 8] = unsafe { ptr[0..8].try_into().unwrap() };
    let target_id: [u8; 8] = unsafe { ptr[8..16].try_into().unwrap() };
    let action_relation: u8 = unsafe { ptr[16] };

    let key = RelationKey {
        sender,
        target,
        action_relation,
        padding: 0,
    };

    let allow = unsafe { RELATION_MAP.get(&key) }.copied().unwrap_or(0);
    if allow != 0 {
        Ok(XdpAction::Pass)
    } else {
        Ok(XdpAction::Drop)
    }
}
