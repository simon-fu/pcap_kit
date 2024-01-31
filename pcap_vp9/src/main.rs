use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use bytes::Bytes;
use libpcap_analyzer::TransportLayerType;
use libpcap_tools::FiveTuple;
use util::{BoxHandler, Handler};
use anyhow::{bail, Context, Result};
use webrtc::{media::io::{ivf_reader::IVFFileHeader, Writer}, rtp::{codecs::vp9::Vp9Packet, packetizer::Depacketizer as _}, util::Unmarshal as _};
// use crate::{rtp::{Depacketizer, RtpRef}, vp9::Vp9Packet};
// use webrtc::media::io::ivf_writer::IVFWriter;
use crate::ivf_rtp_writer::IVFWriter;

use crate::{rtp::RtpRef, util::PcapRunner};

pub mod rtp;
pub mod ivf_rtp_writer;
// pub mod vp9;

fn main() -> Result<()> {
    let cmd = 2;

    match cmd {
        1 => run_pcap_to_ivf(),
        2 => run_pcap_to_udp(),
        _ => bail!("unknown cmd")
    }
}

fn run_pcap_to_udp() -> Result<()> {

    let args = Args {
        src: "192.168.0.101:5018".parse()?,
        dst: "85.17.186.6:53134".parse()?,
        is_reverse: false,
        pcap_filepath: "/Users/simon/Downloads/h264.pcap".into(),
        max_packets: 100000,
        is_simulate: true,
    };

    // let args = Args {
    //     src: "10.2.99.60:16898".parse()?,
    //     dst: "10.1.188.172:16520".parse()?,
    //     is_reverse: false,
    //     pcap_filepath: "/Users/simon/Downloads/1(1).pcap".into(),
    //     max_packets: 100000,
    //     is_simulate: true,
    // };

    // let args = Args {
    //     src: "125.211.130.237:54744".parse()?,
    //     dst: "172.27.92.150:16062".parse()?,
    //     is_reverse: true,
    //     pcap_filepath: "/Users/simon/Downloads/vp9-28.pcap".into(),
    //     max_packets: 100000,
    //     is_simulate: true,
    // };

    let handler = Box::new(UdpSimulateHandler {
        socket: UdpSocket::bind("0.0.0.0:0")?,
        target: "127.0.0.1:1234".parse()?,
    });
    
    println!("simulate udp ...");
    simple_run_pcap(&args, handler)?;
    println!("simulate udp done");

    Ok(())
}

struct UdpSimulateHandler {
    socket: UdpSocket,
    target: SocketAddr,
}

impl Handler for UdpSimulateHandler {
    fn handle(&mut self, info: &util::Info) -> Result<()> {
        println!("No.{} ({}): {:?}, len {}", info.num(), info.pcap_index(), info.five_tuple(), info.data().len());
        self.socket.send_to(info.data(), self.target)?;
        Ok(())
    }

    fn finish(&mut self) {
        
    }
}


fn run_pcap_to_ivf() -> Result<()> {

    let args = Args {
        src: "125.211.130.237:54744".parse()?,
        dst: "172.27.92.150:16062".parse()?,
        is_reverse: false,
        pcap_filepath: "/Users/simon/Downloads/vp9-28.pcap".into(),
        max_packets: 10,
        ..Default::default()
    };

    let payload_type = 103;
    let ivf_filepath = "/tmp/output.ivf";
    let pic_width = 640;
    let pic_height = 360;


    let is_vp9 = true;
    let writer = {
        let file = std::fs::File::create(ivf_filepath)
        .with_context(||format!("failed open [{ivf_filepath}]"))?;

        IVFWriter::new(
            file,
            &IVFFileHeader {
                signature: *b"DKIF",                               // 0-3
                version: 0,                                        // 4-5
                header_size: 32,                                   // 6-7
                four_cc: if is_vp9 { *b"VP90" } else { *b"VP80" }, // 8-11
                width: pic_width,                                  // 12-13
                height: pic_height,                                // 14-15
                timebase_denominator: 30,                          // 16-19
                timebase_numerator: 1,                             // 20-23
                num_frames: 900,                                   // 24-27
                unused: 0,                                         // 28-31
            },
        )?
    };
    


    let handler = Box::new(RtpDumpHandler {
        depack: Vp9Packet::default(),
        writer,
        payload_type,
        written_packes: 0,
    });

    simple_run_pcap(&args, handler)?;
    println!("convert to ivf done");
    Ok(())
}

#[derive(Debug)]
struct Args {
    src: SocketAddr,
    dst: SocketAddr,
    is_reverse: bool,
    pcap_filepath: String,
    max_packets:u64,
    is_simulate: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self { 
            src: default_socketaddr(), 
            dst: default_socketaddr(), 
            is_reverse: Default::default(), 
            pcap_filepath: Default::default(), 
            max_packets: Default::default(),
            is_simulate: Default::default(),
        }
    }
}

fn default_socketaddr() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0))
}

fn simple_run_pcap(args: &Args, handler: BoxHandler) -> Result<()> {
    let (src, dst) = if !args.is_reverse {
        (args.src, args.dst)
    } else {
        (args.dst, args.src)
    };

    let five_tuple = FiveTuple {
        proto: TransportLayerType::Udp as u8,
        src: src.ip(),
        dst: dst.ip(),
        src_port: src.port(),
        dst_port: dst.port(),
    };


    let mut runner = PcapRunner::new(args.max_packets);
    runner = runner.handle(
        five_tuple, 
        handler,
    );

    if !args.is_simulate {
        runner.run_file(&args.pcap_filepath)?;
    } else {
        runner.run_file_simulated(&args.pcap_filepath)?;
    }
    
    
    Ok(())
}

struct RtpDumpHandler {
    depack: Vp9Packet,
    writer: IVFWriter<std::fs::File>,
    payload_type: u8,
    written_packes: u64,
}

impl Handler for RtpDumpHandler {
    fn handle(&mut self, info: &util::Info) -> Result<()> {
        println!("No.{} ({}): {:?}, len {}", info.num(), info.pcap_index(), info.five_tuple(), info.data().len());
        let rtp = RtpRef::parse(info.data())?;
        println!("  {rtp:?}");

        if rtp.payload_type() == self.payload_type {
            let payload: Bytes = Bytes::copy_from_slice(rtp.payload());
            let packet = self.depack.depacketize(&payload)?;
            println!("  {:?}, packet {}", self.depack, packet.len());

            let pkt = webrtc::rtp::packet::Packet::unmarshal(&mut info.data())?;
            self.writer.write_rtp(&pkt)?;
            self.written_packes += 1;
            println!("  write packets [{}]", self.written_packes);
        }

        {

        }

        Ok(())
    }

    fn finish(&mut self) {
        
    }
}


pub mod util {
    use std::{collections::HashMap, sync::Arc, time::{Duration, Instant}};

    use anyhow::{bail, Result};
    use libpcap_analyzer::{
        build_safeplugin, PacketInfo, Plugin, PluginRegistry, PluginResult, PLUGIN_FLOW_DEL, PLUGIN_FLOW_NEW, PLUGIN_L4 
        // packet_info::PacketInfo
    };
    use libpcap_tools::{Flow, Packet, PcapDataEngine, PcapEngine, MICROS_PER_SEC};
    pub use libpcap_tools::FiveTuple;
    pub use libpcap_analyzer::TransportLayerType;
    use parking_lot::Mutex;

    pub struct Info <'s, 'p, 'l3, 'l4, 't, 'f>{
        _packet: &'s libpcap_tools::Packet<'s>,
        pinfo: &'p PacketInfo<'l3, 'l4, 't, 'f>,
        num: u64,
    }
    
    impl Info<'_, '_, '_, '_, '_, '_> {
        #[inline]
        pub fn data(&self) -> &[u8] {
            self.pinfo.l4_payload.as_ref().unwrap()
        }
    
        #[inline]
        pub fn pcap_index(&self) -> usize {
            self.pinfo.pcap_index
        }
    
        #[inline]
        pub fn num(&self) -> u64 {
            self.num
        }
    
        #[inline]
        pub fn to_server(&self) -> bool {
            self.pinfo.to_server
        }
    
        pub fn five_tuple(&self) -> &FiveTuple {
            self.pinfo.five_tuple
        }

        // #[inline]
        // pub fn elapsed(&self) -> &Duration {
        //     &self.elapsed
        // }
    }

    pub trait Handler {
        fn handle(&mut self, info: &Info) -> Result<()>;
        fn finish(&mut self);
    }
    pub type BoxHandler = Box<dyn Handler+Send+Sync+'static>;

    #[derive(Default)]
    pub struct PcapRunner {
        handler_list: Vec<BoxHandler>,
        handlers: HashMap<FiveTuple, usize>,
        max_packets: u64,
        num: u64,
        first_ts: Option<(Duration, Instant)>,
        is_simulated: bool,
    }
    
    impl PcapRunner {
        pub fn new(max_packets: u64) -> Self {
            Self {
                max_packets,
                ..Default::default()
            }
        }
    
        pub fn handle(mut self, five_tuple: FiveTuple, handler: BoxHandler) -> Self {
            self.handler_list.push(handler);
            self.handlers.insert(five_tuple, self.handler_list.len()-1);
            self
        }
    
        pub fn handle_bidirection(mut self, five_tuple: FiveTuple, handler: BoxHandler) -> Self {
            self.handler_list.push(handler);
    
            let reverse = FiveTuple {
                proto: five_tuple.proto,
                src: five_tuple.dst,
                dst: five_tuple.src,
                src_port: five_tuple.dst_port,
                dst_port: five_tuple.src_port,
            };
            self.handlers.insert(reverse, self.handler_list.len()-1);
    
            self.handlers.insert(five_tuple, self.handler_list.len()-1);
    
            self
        }
    
        pub fn run_file(mut self, file: &str, ) -> Result<()> {
            if self.max_packets == 0 { 
                self.max_packets = u64::MAX/2; 
            }
    
            let cfg = libpcap_tools::Config::default();
            run_pcap_file(file, self, cfg)?;
    
            Ok(())
        }
    
        pub fn run_file_simulated(mut self, file: &str, ) -> Result<()> {
            self.is_simulated = true;
            self.run_file(file)
        }
    }

    impl Plugin for PcapRunner {
        fn name(&self) -> &'static str {
            "PcapRunner"
        }
    
        fn plugin_type(&self) -> u16 {
            PLUGIN_FLOW_NEW | PLUGIN_FLOW_DEL | PLUGIN_L4
        }
    
        fn flow_created(&mut self, _flow: &Flow) {
            // info!("H264Dump::flow_created: {:?}", flow);
        }
    
        fn flow_destroyed(&mut self, _flow: &Flow) {
            // info!("H264Dump::flow_destroyed: {:?}", flow);
        }
    
        fn handle_layer_transport<'s, 'i>(
            &'s mut self,
            packet: &'s Packet,
            pinfo: &PacketInfo,
        ) -> PluginResult<'i> {
    
            if self.num >= self.max_packets {
                return PluginResult::None;
            }
    
            if pinfo.l4_payload.is_none() {
                return PluginResult::None;
            }
    
            let r = self.handlers.get_mut(&pinfo.five_tuple);
            if r.is_none() {
                return PluginResult::None;
            }
            
            if self.is_simulated {
                // tracing::info!("--{:?}", _packet.ts);
                let ts = {
                    let micros = (packet.ts.secs as u64 * MICROS_PER_SEC as u64) + packet.ts.micros as u64;
                    Duration::from_micros(micros)
                };
        
                match &self.first_ts {
                    Some(first) => {
                        let elapsed = ts - first.0;
                        if elapsed > first.1.elapsed() {
                            std::thread::sleep(elapsed - first.1.elapsed());
                        }
                    },
                    None => {
                        self.first_ts = Some((ts, Instant::now()));
                    },
                };
            }
    
            self.num += 1;
            let h = r.unwrap();
            let h = &mut self.handler_list[*h];
            let info = Info {
                _packet: packet,
                pinfo,
                num: self.num,
            };
    
            let r = h.handle(&info);
            if let Err(_e) = r {
                return PluginResult::Error(libpcap_tools::Error::Generic("handle error"));
            }
    
            // let five_tuple = &pinfo.five_tuple;
            // info!("PluginDump::handle_l4");
            // debug!("    5-t: {}", five_tuple);
            // debug!("    to_server: {}", pinfo.to_server);
            // debug!("    l3_type: 0x{:x}", pinfo.l3_type);
            // debug!("    l4_data_len: {}", pinfo.l4_data.len());
            // debug!("    l4_type: {} ({})", pinfo.l4_type, l4_type_name(pinfo.l4_type as u16));
            // debug!(
            //     "    l4_payload_len: {}",
            //     pinfo.l4_payload.map_or(0, |d| d.len())
            // );
            // if let Some(flow) = pinfo.flow {
            //     let five_tuple = &flow.five_tuple;
            //     debug!(
            //         "    flow: [{}]:{} -> [{}]:{} [{}]",
            //         five_tuple.src,
            //         five_tuple.src_port,
            //         five_tuple.dst,
            //         five_tuple.dst_port,
            //         five_tuple.proto
            //     );
            // }
            // if let Some(d) = pinfo.l4_payload {
            //     debug!("    l4_payload:\n{}", d.to_hex(16));
            // }
            
            PluginResult::None
        }
    
        fn post_process(&mut self) {
            for h in &mut self.handler_list {
                h.finish();
            }
        }
    }
    
    struct PcapProber {
        flows: Arc<Mutex<Vec<Flow>>>,
    }
    
    impl Plugin for PcapProber {
        fn name(&self) -> &'static str {
            "PcapProber"
        }
    
        fn plugin_type(&self) -> u16 {
            PLUGIN_FLOW_NEW | PLUGIN_FLOW_DEL | PLUGIN_L4
        }
    
        fn flow_created(&mut self, flow: &Flow) {
            // tracing::info!("flow_created: {:?}", flow);
            self.flows.lock().push(flow.clone());
        }
    }
    
    pub fn run_pcap_file<P: Plugin+'static>(
        file: &str, 
        plugin: P,
        mut config: libpcap_tools::Config,
    ) -> Result<()> {
        let mut registry = PluginRegistry::new();
        let r = build(&mut registry, plugin);
        if let Err(e) = r {
            bail!("build plugin fail, {:?}", e);
        }
    
        // let mut config = libpcap_tools::Config::default();
        config.set("do_checksums", false);
    
        // debug!("Plugins loaded:");
        // registry.run_plugins(
        //     |_| true,
        //     |p| {
        //         debug!("  {}", p.name());
        //     },
        // );
    
        let mut input_reader = {
            let file = std::fs::File::open(file)?;
            Box::new(file) as Box<dyn std::io::Read>
        };
    
        let mut engine = {
            let analyzer = libpcap_analyzer::Analyzer::new(Arc::new(registry), &config);
            Box::new(PcapDataEngine::new(analyzer, &config)) //as Box<dyn PcapEngine>
        };
        engine.run(&mut input_reader)?;
    
        // let r = engine.as_mut().data_analyzer().registry().iter_plugins();
        // for p in r {
    
        // }
    
        Ok(())
    }

    fn build<P: Plugin+'static>(
        registry: &mut PluginRegistry,
        plugin: P,
    ) -> Result<(), libpcap_analyzer::PluginBuilderError> {
        // let plugin = $build_fn(config);
        let protos = plugin.plugin_type();
        let safe_p = build_safeplugin!(plugin);
        let id = registry.add_plugin(safe_p);
        if protos & libpcap_analyzer::PLUGIN_L2 != 0 {
            // XXX no filter, so register for all
            registry.register_layer(2, 0, id)?;
        }
        if protos & libpcap_analyzer::PLUGIN_L3 != 0 {
            // XXX no filter, so register for all
            registry.register_layer(3, 0, id)?;
        }
        if protos & libpcap_analyzer::PLUGIN_L4 != 0 {
            // XXX no filter, so register for all
            registry.register_layer(4, 0, id)?;
        }
        Ok(())
    }

    pub fn probe_tcp_flows_by_port(file: &str, port: u16) -> Result<Vec<Flow>> {
        let flows = Arc::new(Mutex::new(Vec::new()));
        let prober = PcapProber{
            flows: flows.clone()
        };
        let cfg = libpcap_tools::Config::default();
        run_pcap_file(file, prober, cfg)?;
    
        let mut flows_r = Vec::new();
        for flow in flows.lock().iter() {
            if flow.five_tuple.proto as u16 == TransportLayerType::Tcp as u16
            && (flow.five_tuple.src_port == port || flow.five_tuple.dst_port == port) {
                flows_r.push(flow.clone());
            }
        }
        Ok(flows_r)
    }
}
