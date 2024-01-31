use bytes::{Buf, Bytes};
use anyhow::{bail, Result};


use crate::rtp::Depacketizer;

use super::{MAX_SPATIAL_LAYERS, MAX_VP9REF_PICS};



macro_rules! err_shortpacket {
    () => {
        bail!("short packet")
    };
}

macro_rules! err_too_manny_spatial_layers {
    () => {
        bail!("too manny spatial layers")
    };
}

macro_rules! err_too_manny_pdiff {
    () => {
        bail!("too manny pdiff")
    };
}



/// Vp9Packet represents the VP9 header that is stored in the payload of an RTP Packet
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct Vp9Packet {
    /// picture ID is present
    pub i: bool,
    /// inter-picture predicted frame.
    pub p: bool,
    /// layer indices present
    pub l: bool,
    /// flexible mode
    pub f: bool,
    /// start of frame. beginning of new vp9 frame
    pub b: bool,
    /// end of frame
    pub e: bool,
    /// scalability structure (SS) present
    pub v: bool,
    /// Not a reference frame for upper spatial layers
    pub z: bool,

    /// Recommended headers
    /// 7 or 16 bits, picture ID.
    pub picture_id: u16,

    /// Conditionally recommended headers
    /// Temporal layer ID
    pub tid: u8,
    /// Switching up point
    pub u: bool,
    /// Spatial layer ID
    pub sid: u8,
    /// Inter-layer dependency used
    pub d: bool,

    /// Conditionally required headers
    /// Reference index (F=1)
    pub pdiff: Vec<u8>,
    /// Temporal layer zero index (F=0)
    pub tl0picidx: u8,

    /// Scalability structure headers
    /// N_S + 1 indicates the number of spatial layers present in the VP9 stream
    pub ns: u8,
    /// Each spatial layer's frame resolution present
    pub y: bool,
    /// PG description present flag.
    pub g: bool,
    /// N_G indicates the number of pictures in a Picture Group (PG)
    pub ng: u8,
    pub width: Vec<u16>,
    pub height: Vec<u16>,
    /// Temporal layer ID of pictures in a Picture Group
    pub pgtid: Vec<u8>,
    /// Switching up point of pictures in a Picture Group
    pub pgu: Vec<bool>,
    /// Reference indecies of pictures in a Picture Group
    pub pgpdiff: Vec<Vec<u8>>,
}

impl Depacketizer for Vp9Packet {
    /// depacketize parses the passed byte slice and stores the result in the Vp9Packet this method is called upon
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        if packet.is_empty() {
            // return Err(Error::ErrShortPacket);
            err_shortpacket!()
        }

        let reader = &mut packet.clone();
        let b = reader.get_u8();

        self.i = (b & 0x80) != 0;
        self.p = (b & 0x40) != 0;
        self.l = (b & 0x20) != 0;
        self.f = (b & 0x10) != 0;
        self.b = (b & 0x08) != 0;
        self.e = (b & 0x04) != 0;
        self.v = (b & 0x02) != 0;
        self.z = (b & 0x01) != 0;

        let mut payload_index = 1;

        if self.i {
            payload_index = self.parse_picture_id(reader, payload_index)?;
        }

        if self.l {
            payload_index = self.parse_layer_info(reader, payload_index)?;
        }

        if self.f && self.p {
            payload_index = self.parse_ref_indices(reader, payload_index)?;
        }

        if self.v {
            payload_index = self.parse_ssdata(reader, payload_index)?;
        }

        Ok(packet.slice(payload_index..))
    }

    /// is_partition_head checks whether if this is a head of the VP9 partition
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        if payload.is_empty() {
            false
        } else {
            (payload[0] & 0x08) != 0
        }
    }

    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}

impl Vp9Packet {
    // Picture ID:
    //
    //      +-+-+-+-+-+-+-+-+
    // I:   |M| PICTURE ID  |   M:0 => picture id is 7 bits.
    //      +-+-+-+-+-+-+-+-+   M:1 => picture id is 15 bits.
    // M:   | EXTENDED PID  |
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_picture_id(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        if reader.remaining() == 0 {
            // return Err(Error::ErrShortPacket);
            err_shortpacket!()
        }
        let b = reader.get_u8();
        payload_index += 1;
        // PID present?
        if (b & 0x80) != 0 {
            if reader.remaining() == 0 {
                // return Err(Error::ErrShortPacket);
                err_shortpacket!()
            }
            // M == 1, PID is 15bit
            self.picture_id = (((b & 0x7f) as u16) << 8) | (reader.get_u8() as u16);
            payload_index += 1;
        } else {
            self.picture_id = (b & 0x7F) as u16;
        }

        Ok(payload_index)
    }

    fn parse_layer_info(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        payload_index = self.parse_layer_info_common(reader, payload_index)?;

        if self.f {
            Ok(payload_index)
        } else {
            self.parse_layer_info_non_flexible_mode(reader, payload_index)
        }
    }

    // Layer indices (flexible mode):
    //
    //      +-+-+-+-+-+-+-+-+
    // L:   |  T  |U|  S  |D|
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_layer_info_common(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        if reader.remaining() == 0 {
            // return Err(Error::ErrShortPacket);
            err_shortpacket!()
        }
        let b = reader.get_u8();
        payload_index += 1;

        self.tid = b >> 5;
        self.u = b & 0x10 != 0;
        self.sid = (b >> 1) & 0x7;
        self.d = b & 0x01 != 0;

        if self.sid >= MAX_SPATIAL_LAYERS {
            // Err(Error::ErrTooManySpatialLayers)
            err_too_manny_spatial_layers!()
        } else {
            Ok(payload_index)
        }
    }

    // Layer indices (non-flexible mode):
    //
    //      +-+-+-+-+-+-+-+-+
    // L:   |  T  |U|  S  |D|
    //      +-+-+-+-+-+-+-+-+
    //      |   tl0picidx   |
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_layer_info_non_flexible_mode(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        if reader.remaining() == 0 {
            // return Err(Error::ErrShortPacket);
            err_shortpacket!()
        }
        self.tl0picidx = reader.get_u8();
        payload_index += 1;
        Ok(payload_index)
    }

    // Reference indices:
    //
    //      +-+-+-+-+-+-+-+-+                P=1,F=1: At least one reference index
    // P,F: | P_DIFF      |N|  up to 3 times          has to be specified.
    //      +-+-+-+-+-+-+-+-+                    N=1: An additional P_DIFF follows
    //                                                current P_DIFF.
    //
    fn parse_ref_indices(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        let mut b = 1u8;
        while (b & 0x1) != 0 {
            if reader.remaining() == 0 {
                // return Err(Error::ErrShortPacket);
                err_shortpacket!()
            }
            b = reader.get_u8();
            payload_index += 1;

            self.pdiff.push(b >> 1);
            if self.pdiff.len() >= MAX_VP9REF_PICS {
                // return Err(Error::ErrTooManyPDiff);
                err_too_manny_pdiff!()
            }
        }

        Ok(payload_index)
    }

    // Scalability structure (SS):
    //
    //      +-+-+-+-+-+-+-+-+
    // V:   | N_S |Y|G|-|-|-|
    //      +-+-+-+-+-+-+-+-+              -|
    // Y:   |     WIDTH     | (OPTIONAL)    .
    //      +               +               .
    //      |               | (OPTIONAL)    .
    //      +-+-+-+-+-+-+-+-+               . N_S + 1 times
    //      |     HEIGHT    | (OPTIONAL)    .
    //      +               +               .
    //      |               | (OPTIONAL)    .
    //      +-+-+-+-+-+-+-+-+              -|
    // G:   |      N_G      | (OPTIONAL)
    //      +-+-+-+-+-+-+-+-+                           -|
    // N_G: |  T  |U| R |-|-| (OPTIONAL)                 .
    //      +-+-+-+-+-+-+-+-+              -|            . N_G times
    //      |    P_DIFF     | (OPTIONAL)    . R times    .
    //      +-+-+-+-+-+-+-+-+              -|           -|
    //
    fn parse_ssdata(&mut self, reader: &mut dyn Buf, mut payload_index: usize) -> Result<usize> {
        if reader.remaining() == 0 {
            // return Err(Error::ErrShortPacket);
            err_shortpacket!()
        }

        let b = reader.get_u8();
        payload_index += 1;

        self.ns = b >> 5;
        self.y = b & 0x10 != 0;
        self.g = (b >> 1) & 0x7 != 0;

        let ns = (self.ns + 1) as usize;
        self.ng = 0;

        if self.y {
            if reader.remaining() < 4 * ns {
                // return Err(Error::ErrShortPacket);
                err_shortpacket!()
            }

            self.width = vec![0u16; ns];
            self.height = vec![0u16; ns];
            for i in 0..ns {
                self.width[i] = reader.get_u16();
                self.height[i] = reader.get_u16();
            }
            payload_index += 4 * ns;
        }

        if self.g {
            if reader.remaining() == 0 {
                // return Err(Error::ErrShortPacket);
                err_shortpacket!()
            }

            self.ng = reader.get_u8();
            payload_index += 1;
        }

        for i in 0..self.ng as usize {
            if reader.remaining() == 0 {
                // return Err(Error::ErrShortPacket);
                err_shortpacket!()
            }
            let b = reader.get_u8();
            payload_index += 1;

            self.pgtid.push(b >> 5);
            self.pgu.push(b & 0x10 != 0);

            let r = ((b >> 2) & 0x3) as usize;
            if reader.remaining() < r {
                // return Err(Error::ErrShortPacket);
                err_shortpacket!()
            }

            self.pgpdiff.push(vec![]);
            for _ in 0..r {
                let b = reader.get_u8();
                payload_index += 1;

                self.pgpdiff[i].push(b);
            }
        }

        Ok(payload_index)
    }
}
