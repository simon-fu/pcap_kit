use std::{fmt, ops};
use anyhow::{anyhow, Result};
use rtp_rs::RtpReader;


pub struct RtpRef<'a> {
    inner: RtpReader<'a>,
}

impl<'a> RtpRef<'a> {
    fn fmt_pure(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seq: u16 = self.inner.sequence_number().into();

        write!(f, "pt: {}", &self.inner.payload_type())?;
        write!(f, ", seq: {}", seq)?;
        write!(f, ", ts: {}", self.inner.timestamp())?;
        write!(f, ", ssrc: {}", self.inner.ssrc())?;

        if self.inner.mark() {
            f.write_str(", m")?;
        }

        if self.has_padding() {
            f.write_str(", p")?;
        }

        if self.has_extension() {
            f.write_str(", ext")?;
        }

        if self.inner.version() != 2 {
            write!(f, ", v: {}", self.inner.version())?;
        }

        if self.csrc_count() > 0 {
            write!(f, ", csrc: {}", self.inner.csrc_count())?;
        }

        // write!(f, ", {}", self.inner.payload().dump_bin_limit(12))
        write!(f, ", payload {}", self.inner.payload().len())
    }
}

impl<'a> fmt::Display for RtpRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_pure(f)
    }
}

impl<'a> fmt::Debug for RtpRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rtp {{ ")?;
        self.fmt_pure(f)?;
        write!(f, " }}")
    }
}

impl<'a> RtpRef<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let inner = RtpReader::new(data)
        .map_err(|x|anyhow!("illegal rtp {:?}", x))?;
        Ok(Self { inner })
    }

    pub fn has_padding(&self) -> bool {
        self.inner.padding().is_some()
    }

    pub fn has_extension(&self) -> bool {
        self.inner.extension().is_some()
    }

    pub fn has_csrc(&self) -> bool {
        self.inner.csrc_count() > 0
    }

    pub fn seq_value(&self) -> u16 {
        self.inner.sequence_number().into()
    }

    pub fn payload_offset(&self) -> usize {
        self.inner.payload_offset()
    }
}

impl<'a> ops::Deref for RtpRef<'a> {
    type Target = RtpReader<'a>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
