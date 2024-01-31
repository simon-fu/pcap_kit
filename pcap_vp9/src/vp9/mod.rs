
mod vp9_packet;
pub use vp9_packet::*;

/// Flexible mode 15 bit picture ID
pub const VP9HEADER_SIZE: usize = 3;
pub const MAX_SPATIAL_LAYERS: u8 = 5;
pub const MAX_VP9REF_PICS: usize = 3;
