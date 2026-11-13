//! The native `Psiphon` lane: a signed server list, the SSH/OSSH transport in
//! [`crate::psiphon_ssh`], and the loopback SOCKS edge the proxy dials.

use crate::json::{self, Json};
use crate::psiphon_ssh::{
    ApiEncoding, Channel, ChannelChunk, Identity, KeepAlive, Proxy, Server, Session, TlsShape,
    MAX_PADDING, MIN_PADDING,
};
use crate::socks::{Credential, Destination, Version};
use ferrox_core::tls::shaped::{Body, Ext, Profile};
use ferrox_core::tls::Fingerprint;
use flate2::read::ZlibDecoder;
use ring::signature;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::{self, IoSlice, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

const SPONSOR_ID: &str = "07D1ACD69B3AC7A2";
const PROPAGATION_CHANNEL_ID: &str = "EE0B7486ACAE75AA";
const CLIENT_VERSION: &str = "453";
/// The compartment ID the public Android build embeds for its private conduits.
const PRIVATE_COMPARTMENT_ID: &str = "/TYUL7wjyPuXCGAujuiQuxTRlOFhjMglpDX2kzVo/ks";
/// The regions the Android client rejects when its censored-country switch is on.
const CENSORED_COUNTRY_CODES: &[&str] = &["IR", "CN", "RU", "BY", "TM", "KP"];
const UDPGW_HOST: &str = "127.0.0.1";
const UDPGW_PORT: u16 = 7300;
const UDPGW_FLAG_KEEPALIVE: u8 = 1;
const UDPGW_FLAG_REBIND: u8 = 2;
const UDPGW_FLAG_IPV6: u8 = 8;
const UDPGW_MAX_PAYLOAD: usize = 32_768;
const UDPGW_MAX_MESSAGE: usize = 32_768 + 23;
const MAX_LIST_BYTES: u64 = 16 * 1024 * 1024;
const RELAY_BUFFER: usize = 256 * 1024;
const RELAY_BATCH: usize = 64;
/// How long a fetched OSL registry and its files are reused before another attempt.
const OSL_REFRESH: Duration = Duration::from_secs(300);
/// How long one server classification keeps a destination on the direct path.
const SPLIT_TUNNEL_CLASSIFICATION_TTL: Duration = Duration::from_hours(24);
/// The reference's cap on cached split-tunnel classifications.
const SPLIT_TUNNEL_CLASSIFICATION_MAX: usize = 65_536;
const FRONTED_VARIANTS: usize = 256;
const FRONTED_SERVERS: usize = 512;

#[derive(Clone, Copy)]
struct CdnRange {
    first: u32,
    last: u32,
}

#[rustfmt::skip]
const BUILTIN_CDN_RANGES: &[CdnRange] = &[
    CdnRange { first: 0x0210_1388, last: 0x0210_1388 },
    CdnRange { first: 0x0210_1433, last: 0x0210_1433 },
    CdnRange { first: 0x0210_350b, last: 0x0210_350b },
    CdnRange { first: 0x0210_3532, last: 0x0210_3532 },
    CdnRange { first: 0x0210_3539, last: 0x0210_3539 },
    CdnRange { first: 0x0210_3541, last: 0x0210_3541 },
    CdnRange { first: 0x0210_dd25, last: 0x0210_dd25 },
    CdnRange { first: 0x0211_2318, last: 0x0211_2318 },
    CdnRange { first: 0x0211_2328, last: 0x0211_2328 },
    CdnRange { first: 0x0211_23a3, last: 0x0211_23a3 },
    CdnRange { first: 0x0211_23d9, last: 0x0211_23d9 },
    CdnRange { first: 0x0211_6189, last: 0x0211_6189 },
    CdnRange { first: 0x0211_64ea, last: 0x0211_64ea },
    CdnRange { first: 0x0211_6a76, last: 0x0211_6a76 },
    CdnRange { first: 0x0211_6a89, last: 0x0211_6a89 },
    CdnRange { first: 0x0212_3f31, last: 0x0212_3f31 },
    CdnRange { first: 0x0213_7e51, last: 0x0213_7e51 },
    CdnRange { first: 0x0215_0209, last: 0x0215_020a },
    CdnRange { first: 0x0215_0220, last: 0x0215_0220 },
    CdnRange { first: 0x0215_0222, last: 0x0215_0222 },
    CdnRange { first: 0x0215_025b, last: 0x0215_025b },
    CdnRange { first: 0x0215_0268, last: 0x0215_0268 },
    CdnRange { first: 0x0216_fa95, last: 0x0216_fa95 },
    CdnRange { first: 0x0217_2916, last: 0x0217_2916 },
    CdnRange { first: 0x0217_a807, last: 0x0217_a807 },
    CdnRange { first: 0x0217_a82f, last: 0x0217_a82f },
    CdnRange { first: 0x0217_a860, last: 0x0217_a860 },
    CdnRange { first: 0x0217_a890, last: 0x0217_a890 },
    CdnRange { first: 0x0217_a8ae, last: 0x0217_a8ae },
    CdnRange { first: 0x0217_a8d5, last: 0x0217_a8d5 },
    CdnRange { first: 0x0217_a8fa, last: 0x0217_a8fa },
    CdnRange { first: 0x0217_a8fe, last: 0x0217_a8fe },
    CdnRange { first: 0x0217_a90c, last: 0x0217_a90c },
    CdnRange { first: 0x0217_a92a, last: 0x0217_a92a },
    CdnRange { first: 0x0217_a969, last: 0x0217_a969 },
    CdnRange { first: 0x0217_a96f, last: 0x0217_a96f },
    CdnRange { first: 0x0217_a9cf, last: 0x0217_a9cf },
    CdnRange { first: 0x0217_a9f9, last: 0x0217_a9f9 },
    CdnRange { first: 0x0217_aa50, last: 0x0217_aa50 },
    CdnRange { first: 0x030a_1180, last: 0x030a_11ff },
    CdnRange { first: 0x030b_3500, last: 0x030b_35ff },
    CdnRange { first: 0x031d_2840, last: 0x031d_28ff },
    CdnRange { first: 0x031d_3900, last: 0x031d_393f },
    CdnRange { first: 0x0323_8280, last: 0x0323_82ff },
    CdnRange { first: 0x0365_9e00, last: 0x0365_9fff },
    CdnRange { first: 0x036b_2b80, last: 0x036b_2cff },
    CdnRange { first: 0x0380_5d00, last: 0x0380_5dff },
    CdnRange { first: 0x0386_d700, last: 0x0386_d7ff },
    CdnRange { first: 0x0392_e800, last: 0x0392_ebff },
    CdnRange { first: 0x0393_a400, last: 0x0393_a7ff },
    CdnRange { first: 0x0393_f400, last: 0x0393_f7ff },
    CdnRange { first: 0x03a0_0000, last: 0x03ac_7fff },
    CdnRange { first: 0x03ad_0000, last: 0x03af_ffff },
    CdnRange { first: 0x03e7_0200, last: 0x03e7_027f },
    CdnRange { first: 0x03ea_e8e0, last: 0x03ea_e8ff },
    CdnRange { first: 0x03ec_3000, last: 0x03ec_31ff },
    CdnRange { first: 0x03ec_a9c0, last: 0x03ec_a9ff },
    CdnRange { first: 0x04d0_1ac5, last: 0x04d0_1ac6 },
    CdnRange { first: 0x04d0_1ac8, last: 0x04d0_1ac8 },
    CdnRange { first: 0x04e1_0bc2, last: 0x04e1_0bc2 },
    CdnRange { first: 0x04e1_0bc8, last: 0x04e1_0bc9 },
    CdnRange { first: 0x04e4_1f91, last: 0x04e4_1f91 },
    CdnRange { first: 0x04e4_1f95, last: 0x04e4_1f96 },
    CdnRange { first: 0x04ed_1622, last: 0x04ed_1622 },
    CdnRange { first: 0x04ed_1626, last: 0x04ed_1626 },
    CdnRange { first: 0x04ed_1628, last: 0x04ed_1628 },
    CdnRange { first: 0x0509_4777, last: 0x0509_4777 },
    CdnRange { first: 0x0509_622d, last: 0x0509_622d },
    CdnRange { first: 0x0509_6349, last: 0x0509_6349 },
    CdnRange { first: 0x0509_90b2, last: 0x0509_90b2 },
    CdnRange { first: 0x052a_ce42, last: 0x052a_ce42 },
    CdnRange { first: 0x05bd_ca3e, last: 0x05bd_ca3e },
    CdnRange { first: 0x0808_0400, last: 0x0808_04ff },
    CdnRange { first: 0x0808_0800, last: 0x0808_08ff },
    CdnRange { first: 0x0834_8b14, last: 0x0834_8b14 },
    CdnRange { first: 0x0834_8b1c, last: 0x0834_8b1c },
    CdnRange { first: 0x0834_8b24, last: 0x0834_8b24 },
    CdnRange { first: 0x0834_8b2c, last: 0x0834_8b2c },
    CdnRange { first: 0x0834_8b34, last: 0x0834_8b34 },
    CdnRange { first: 0x0834_8b3c, last: 0x0834_8b3c },
    CdnRange { first: 0x0834_8b64, last: 0x0834_8b64 },
    CdnRange { first: 0x0834_8b6c, last: 0x0834_8b6c },
    CdnRange { first: 0x0834_8b94, last: 0x0834_8b94 },
    CdnRange { first: 0x0834_8b9c, last: 0x0834_8b9c },
    CdnRange { first: 0x0834_8bd4, last: 0x0834_8bd4 },
    CdnRange { first: 0x0834_8bdc, last: 0x0834_8bdc },
    CdnRange { first: 0x0834_8be4, last: 0x0834_8be4 },
    CdnRange { first: 0x0834_8bec, last: 0x0834_8bec },
    CdnRange { first: 0x0834_8bf4, last: 0x0834_8bf4 },
    CdnRange { first: 0x0834_b80c, last: 0x0834_b80c },
    CdnRange { first: 0x0834_b834, last: 0x0834_b834 },
    CdnRange { first: 0x0834_b894, last: 0x0834_b894 },
    CdnRange { first: 0x0834_b89c, last: 0x0834_b89c },
    CdnRange { first: 0x0834_b8a4, last: 0x0834_b8a4 },
    CdnRange { first: 0x0834_b8ac, last: 0x0834_b8ac },
    CdnRange { first: 0x0834_b8b4, last: 0x0834_b8b4 },
    CdnRange { first: 0x0834_b8bc, last: 0x0834_b8bc },
    CdnRange { first: 0x0d20_0000, last: 0x0d21_ffff },
    CdnRange { first: 0x0d23_0000, last: 0x0d23_ffff },
    CdnRange { first: 0x0d36_3f80, last: 0x0d36_3fbf },
    CdnRange { first: 0x0d3b_fa00, last: 0x0d3b_fa3f },
    CdnRange { first: 0x0d71_c440, last: 0x0d71_c47f },
    CdnRange { first: 0x0d71_cb00, last: 0x0d71_cbff },
    CdnRange { first: 0x0d7c_c700, last: 0x0d7c_c7ff },
    CdnRange { first: 0x0d86_1800, last: 0x0d86_19ff },
    CdnRange { first: 0x0d86_5e00, last: 0x0d86_5fff },
    CdnRange { first: 0x0dcb_8500, last: 0x0dcb_853f },
    CdnRange { first: 0x0dd2_4380, last: 0x0dd2_43bf },
    CdnRange { first: 0x0de0_0000, last: 0x0de3_ffff },
    CdnRange { first: 0x0de4_4500, last: 0x0de4_45ff },
    CdnRange { first: 0x0de9_b1c0, last: 0x0de9_b1ff },
    CdnRange { first: 0x0df9_0000, last: 0x0df9_ffff },
    CdnRange { first: 0x0f9e_0000, last: 0x0f9e_ffff },
    CdnRange { first: 0x0fbc_b800, last: 0x0fbc_b8ff },
    CdnRange { first: 0x0fcf_0d80, last: 0x0fcf_0dff },
    CdnRange { first: 0x0fcf_d580, last: 0x0fcf_d5ff },
    CdnRange { first: 0x1240_0000, last: 0x1244_ffff },
    CdnRange { first: 0x129a_0000, last: 0x129b_ffff },
    CdnRange { first: 0x12a0_0000, last: 0x12a1_ffff },
    CdnRange { first: 0x12a4_0000, last: 0x12a5_ffff },
    CdnRange { first: 0x12ac_0000, last: 0x12ad_ffff },
    CdnRange { first: 0x12af_4100, last: 0x12af_43ff },
    CdnRange { first: 0x12c0_8e00, last: 0x12c0_8fff },
    CdnRange { first: 0x12c7_4400, last: 0x12c7_4fff },
    CdnRange { first: 0x12c8_d400, last: 0x12c8_d5ff },
    CdnRange { first: 0x12d8_aa80, last: 0x12d8_aaff },
    CdnRange { first: 0x12e5_dcc0, last: 0x12e5_dcff },
    CdnRange { first: 0x12e6_e500, last: 0x12e6_e67f },
    CdnRange { first: 0x12ee_0000, last: 0x12ef_ffff },
    CdnRange { first: 0x12f4_0000, last: 0x12f5_ffff },
    CdnRange { first: 0x141a_9cd2, last: 0x141a_9cd2 },
    CdnRange { first: 0x141a_9cd6, last: 0x141a_9cd7 },
    CdnRange { first: 0x141b_b171, last: 0x141b_b171 },
    CdnRange { first: 0x141b_b174, last: 0x141b_b174 },
    CdnRange { first: 0x141b_b176, last: 0x141b_b176 },
    CdnRange { first: 0x141d_8611, last: 0x141d_8611 },
    CdnRange { first: 0x141d_8613, last: 0x141d_8613 },
    CdnRange { first: 0x141d_8617, last: 0x141d_8617 },
    CdnRange { first: 0x1457_f500, last: 0x1457_f500 },
    CdnRange { first: 0x1457_f504, last: 0x1457_f504 },
    CdnRange { first: 0x1457_f506, last: 0x1457_f506 },
    CdnRange { first: 0x14af_c092, last: 0x14af_c093 },
    CdnRange { first: 0x14af_c095, last: 0x14af_c095 },
    CdnRange { first: 0x14c7_27e3, last: 0x14c7_27e4 },
    CdnRange { first: 0x14c7_27e8, last: 0x14c7_27e8 },
    CdnRange { first: 0x14c8_f5f5, last: 0x14c8_f5f5 },
    CdnRange { first: 0x14c8_f5f7, last: 0x14c8_f5f8 },
    CdnRange { first: 0x14c9_1c94, last: 0x14c9_1c94 },
    CdnRange { first: 0x14c9_1c97, last: 0x14c9_1c98 },
    CdnRange { first: 0x14cd_f3a0, last: 0x14cd_f3a0 },
    CdnRange { first: 0x14cd_f3a6, last: 0x14cd_f3a6 },
    CdnRange { first: 0x14cd_f3a8, last: 0x14cd_f3a8 },
    CdnRange { first: 0x14cf_4952, last: 0x14cf_4953 },
    CdnRange { first: 0x14cf_4955, last: 0x14cf_4955 },
    CdnRange { first: 0x14d9_8700, last: 0x14d9_8700 },
    CdnRange { first: 0x14d9_8704, last: 0x14d9_8705 },
    CdnRange { first: 0x14e9_5391, last: 0x14e9_5392 },
    CdnRange { first: 0x14e9_5395, last: 0x14e9_5395 },
    CdnRange { first: 0x1702_0d88, last: 0x1702_0d88 },
    CdnRange { first: 0x170c_930d, last: 0x170c_930d },
    CdnRange { first: 0x170c_931d, last: 0x170c_931d },
    CdnRange { first: 0x1722_4be5, last: 0x1722_4be5 },
    CdnRange { first: 0x172b_edef, last: 0x172b_edef },
    CdnRange { first: 0x172c_c995, last: 0x172c_c995 },
    CdnRange { first: 0x1730_1785, last: 0x1730_1785 },
    CdnRange { first: 0x1730_1797, last: 0x1730_1797 },
    CdnRange { first: 0x1730_17b2, last: 0x1730_17b2 },
    CdnRange { first: 0x1730_17ba, last: 0x1730_17ba },
    CdnRange { first: 0x1730_17c3, last: 0x1730_17c3 },
    CdnRange { first: 0x1730_cb00, last: 0x1730_cbff },
    CdnRange { first: 0x173a_5f8a, last: 0x173a_5f8a },
    CdnRange { first: 0x173a_c18c, last: 0x173a_c18c },
    CdnRange { first: 0x173e_e600, last: 0x173e_e6ff },
    CdnRange { first: 0x1749_cf08, last: 0x1749_cf08 },
    CdnRange { first: 0x1749_cf0f, last: 0x1749_cf0f },
    CdnRange { first: 0x175b_0000, last: 0x175b_1fff },
    CdnRange { first: 0x17ca_8a7d, last: 0x17ca_8a7d },
    CdnRange { first: 0x17cf_d253, last: 0x17cf_d253 },
    CdnRange { first: 0x17d0_4128, last: 0x17d0_4128 },
    CdnRange { first: 0x17d4_fa4e, last: 0x17d4_fa4e },
    CdnRange { first: 0x17d4_fa5b, last: 0x17d4_fa5b },
    CdnRange { first: 0x17d7_0000, last: 0x17d7_00ff },
    CdnRange { first: 0x17d7_3c29, last: 0x17d7_3c29 },
    CdnRange { first: 0x17d8_4d23, last: 0x17d8_4d23 },
    CdnRange { first: 0x17dd_1c05, last: 0x17dd_1c05 },
    CdnRange { first: 0x17dd_1c39, last: 0x17dd_1c39 },
    CdnRange { first: 0x17dd_1d1d, last: 0x17dd_1d1d },
    CdnRange { first: 0x17e4_d400, last: 0x17e4_d6ff },
    CdnRange { first: 0x17e4_dc00, last: 0x17e4_dfff },
    CdnRange { first: 0x17e4_f400, last: 0x17e4_f4ff },
    CdnRange { first: 0x17ea_c000, last: 0x17ea_ffff },
    CdnRange { first: 0x17eb_2000, last: 0x17eb_2fff },
    CdnRange { first: 0x186e_2000, last: 0x186e_3fff },
    CdnRange { first: 0x226b_8600, last: 0x226b_86ff },
    CdnRange { first: 0x226e_ce00, last: 0x226e_ceff },
    CdnRange { first: 0x22c3_fc00, last: 0x22c3_fcff },
    CdnRange { first: 0x22d8_3300, last: 0x22d8_337f },
    CdnRange { first: 0x22df_0ce0, last: 0x22df_0cff },
    CdnRange { first: 0x22df_50c0, last: 0x22df_50ff },
    CdnRange { first: 0x22e2_0e00, last: 0x22e2_0eff },
    CdnRange { first: 0x235d_a800, last: 0x235d_adff },
    CdnRange { first: 0x239e_8800, last: 0x239e_88ff },
    CdnRange { first: 0x23a2_3fc0, last: 0x23a2_3fff },
    CdnRange { first: 0x23a7_bf80, last: 0x23a7_bfbf },
    CdnRange { first: 0x2467_e800, last: 0x2467_e8bf },
    CdnRange { first: 0x2513_cbb2, last: 0x2513_cbb2 },
    CdnRange { first: 0x2513_cf22, last: 0x2513_cf22 },
    CdnRange { first: 0x2513_cf25, last: 0x2513_cf26 },
    CdnRange { first: 0x2513_d882, last: 0x2513_d882 },
    CdnRange { first: 0x2513_de22, last: 0x2513_de22 },
    CdnRange { first: 0x2513_def8, last: 0x2513_def9 },
    CdnRange { first: 0x251b_873d, last: 0x251b_873d },
    CdnRange { first: 0x25ec_ea02, last: 0x25ec_ea02 },
    CdnRange { first: 0x2620_6e3a, last: 0x2620_6e3a },
    CdnRange { first: 0x2636_035c, last: 0x2636_035c },
    CdnRange { first: 0x2636_0525, last: 0x2636_0525 },
    CdnRange { first: 0x2668_a9ba, last: 0x2668_a9ba },
    CdnRange { first: 0x268e_5eda, last: 0x268e_5eda },
    CdnRange { first: 0x29f2_0212, last: 0x29f2_0212 },
    CdnRange { first: 0x2bda_3840, last: 0x2bda_38ff },
    CdnRange { first: 0x2bda_4700, last: 0x2bda_473f },
    CdnRange { first: 0x2bf9_4800, last: 0x2bf9_4bff },
    CdnRange { first: 0x2cdc_c200, last: 0x2cdc_cbff },
    CdnRange { first: 0x2cde_4200, last: 0x2cde_42ff },
    CdnRange { first: 0x2ce3_b200, last: 0x2ce3_b2ff },
    CdnRange { first: 0x2cea_5afc, last: 0x2cea_5aff },
    CdnRange { first: 0x2cea_6c80, last: 0x2cea_6cff },
    CdnRange { first: 0x2d7d_f739, last: 0x2d7d_f739 },
    CdnRange { first: 0x2d9c_f849, last: 0x2d9c_f849 },
    CdnRange { first: 0x2e04_665a, last: 0x2e04_665a },
    CdnRange { first: 0x2e04_718f, last: 0x2e04_718f },
    CdnRange { first: 0x2e04_7411, last: 0x2e04_7411 },
    CdnRange { first: 0x2e04_7751, last: 0x2e04_7751 },
    CdnRange { first: 0x2e04_7898, last: 0x2e04_7898 },
    CdnRange { first: 0x2e97_c155, last: 0x2e97_c156 },
    CdnRange { first: 0x2e97_c2f2, last: 0x2e97_c2f3 },
    CdnRange { first: 0x2ec7_4b73, last: 0x2ec7_4b73 },
    CdnRange { first: 0x2f81_5200, last: 0x2f81_54ff },
    CdnRange { first: 0x310c_009e, last: 0x310c_009e },
    CdnRange { first: 0x310c_471b, last: 0x310c_471b },
    CdnRange { first: 0x332c_ea00, last: 0x332c_efff },
    CdnRange { first: 0x334a_c000, last: 0x334a_ffff },
    CdnRange { first: 0x3353_aca3, last: 0x3353_aca3 },
    CdnRange { first: 0x340f_7f80, last: 0x340f_7fbf },
    CdnRange { first: 0x342e_0000, last: 0x342e_3fff },
    CdnRange { first: 0x342f_8b00, last: 0x342f_8bff },
    CdnRange { first: 0x3434_bf80, last: 0x3434_bfbf },
    CdnRange { first: 0x3438_7f00, last: 0x3438_7f7f },
    CdnRange { first: 0x3439_fe00, last: 0x3439_feff },
    CdnRange { first: 0x3442_c280, last: 0x3442_c2bf },
    CdnRange { first: 0x344e_f780, last: 0x344e_f7bf },
    CdnRange { first: 0x3452_8000, last: 0x3452_9fff },
    CdnRange { first: 0x3454_0000, last: 0x3455_ffff },
    CdnRange { first: 0x347c_8000, last: 0x347c_ffff },
    CdnRange { first: 0x34c7_7fc0, last: 0x34c7_7fff },
    CdnRange { first: 0x34d4_f800, last: 0x34d4_f83f },
    CdnRange { first: 0x34dc_bf00, last: 0x34dc_bf3f },
    CdnRange { first: 0x34de_8000, last: 0x34de_ffff },
    CdnRange { first: 0x36b6_0000, last: 0x36b6_ffff },
    CdnRange { first: 0x36c0_0000, last: 0x36c0_ffff },
    CdnRange { first: 0x36e6_0000, last: 0x36e6_bfff },
    CdnRange { first: 0x36e6_c800, last: 0x36e6_ffff },
    CdnRange { first: 0x36e9_ff80, last: 0x36e9_ffbf },
    CdnRange { first: 0x36ef_8000, last: 0x36ef_dfff },
    CdnRange { first: 0x36f0_8000, last: 0x36f0_bfff },
    CdnRange { first: 0x387d_2e00, last: 0x387d_2f00 },
    CdnRange { first: 0x387d_3000, last: 0x387d_30ff },
    CdnRange { first: 0x39b6_fd00, last: 0x39b6_fdff },
    CdnRange { first: 0x39b7_2a00, last: 0x39b7_2a7f },
    CdnRange { first: 0x3afe_8a00, last: 0x3afe_8abf },
    CdnRange { first: 0x3f8d_fccb, last: 0x3f8d_fccb },
    CdnRange { first: 0x40b9_e852, last: 0x40b9_e852 },
    CdnRange { first: 0x40b9_e8b2, last: 0x40b9_e8b2 },
    CdnRange { first: 0x40b9_e8c2, last: 0x40b9_e8c2 },
    CdnRange { first: 0x40b9_ea72, last: 0x40b9_ea72 },
    CdnRange { first: 0x40b9_eb5a, last: 0x40b9_eb5a },
    CdnRange { first: 0x40e9_b400, last: 0x40e9_b4ff },
    CdnRange { first: 0x40fc_4000, last: 0x40fc_bfff },
    CdnRange { first: 0x4108_0000, last: 0x4109_bfff },
    CdnRange { first: 0x42b5_a34a, last: 0x42b5_a34a },
    CdnRange { first: 0x4684_0000, last: 0x4684_3fff },
    CdnRange { first: 0x4798_0000, last: 0x4798_7fff },
    CdnRange { first: 0x48f6_1c25, last: 0x48f6_1c25 },
    CdnRange { first: 0x4c4c_1500, last: 0x4c4c_15ff },
    CdnRange { first: 0x4e2e_45c7, last: 0x4e2e_45c7 },
    CdnRange { first: 0x4e2e_4a55, last: 0x4e2e_4a56 },
    CdnRange { first: 0x4e2e_5c76, last: 0x4e2e_5c76 },
    CdnRange { first: 0x4e2e_7b11, last: 0x4e2e_7b11 },
    CdnRange { first: 0x4e2e_9c59, last: 0x4e2e_9c59 },
    CdnRange { first: 0x4e2f_5e9c, last: 0x4e2f_5e9c },
    CdnRange { first: 0x4f7f_8681, last: 0x4f7f_8685 },
    CdnRange { first: 0x4f7f_86e1, last: 0x4f7f_86e7 },
    CdnRange { first: 0x4f7f_86ea, last: 0x4f7f_86eb },
    CdnRange { first: 0x4f7f_bcc1, last: 0x4f7f_bcc4 },
    CdnRange { first: 0x4f7f_cc71, last: 0x4f7f_cc71 },
    CdnRange { first: 0x4f7f_d5d1, last: 0x4f7f_d5d2 },
    CdnRange { first: 0x4f7f_d5d6, last: 0x4f7f_d5d9 },
    CdnRange { first: 0x4f7f_d842, last: 0x4f7f_d842 },
    CdnRange { first: 0x4f7f_d86f, last: 0x4f7f_d870 },
    CdnRange { first: 0x4f7f_dbc6, last: 0x4f7f_dbc6 },
    CdnRange { first: 0x4f7f_dd92, last: 0x4f7f_dd92 },
    CdnRange { first: 0x4f7f_e2c2, last: 0x4f7f_e2c3 },
    CdnRange { first: 0x4f7f_e2cf, last: 0x4f7f_e2cf },
    CdnRange { first: 0x4f7f_ed63, last: 0x4f7f_ed63 },
    CdnRange { first: 0x4f7f_ed68, last: 0x4f7f_ed68 },
    CdnRange { first: 0x4f7f_ed84, last: 0x4f7f_ed84 },
    CdnRange { first: 0x4f7f_f259, last: 0x4f7f_f259 },
    CdnRange { first: 0x4f7f_f3bb, last: 0x4f7f_f3bb },
    CdnRange { first: 0x5411_25d1, last: 0x5411_25d1 },
    CdnRange { first: 0x5411_25d3, last: 0x5411_25d3 },
    CdnRange { first: 0x5411_25d9, last: 0x5411_25d9 },
    CdnRange { first: 0x5411_26e1, last: 0x5411_26ea },
    CdnRange { first: 0x5411_26f3, last: 0x5411_26f8 },
    CdnRange { first: 0x5411_26fa, last: 0x5411_26fb },
    CdnRange { first: 0x5411_2e31, last: 0x5411_2e31 },
    CdnRange { first: 0x5411_2e35, last: 0x5411_2e36 },
    CdnRange { first: 0x5411_3b73, last: 0x5411_3b73 },
    CdnRange { first: 0x5411_3b75, last: 0x5411_3b75 },
    CdnRange { first: 0x5411_3b77, last: 0x5411_3b78 },
    CdnRange { first: 0x5411_3fb2, last: 0x5411_3fb2 },
    CdnRange { first: 0x57f9_8934, last: 0x57f9_8934 },
    CdnRange { first: 0x5863_1a61, last: 0x5863_1a61 },
    CdnRange { first: 0x5863_1abd, last: 0x5863_1abd },
    CdnRange { first: 0x5863_3f71, last: 0x5863_3f71 },
    CdnRange { first: 0x5863_5fdd, last: 0x5863_5fdd },
    CdnRange { first: 0x58c6_099b, last: 0x58c6_099b },
    CdnRange { first: 0x58c6_1667, last: 0x58c6_1667 },
    CdnRange { first: 0x58c6_3932, last: 0x58c6_3932 },
    CdnRange { first: 0x58da_03be, last: 0x58da_03be },
    CdnRange { first: 0x59bb_a2f2, last: 0x59bb_a2f2 },
    CdnRange { first: 0x59bb_a2f9, last: 0x59bb_a2f9 },
    CdnRange { first: 0x59bb_a5c2, last: 0x59bb_a5c2 },
    CdnRange { first: 0x59bb_a92f, last: 0x59bb_a92f },
    CdnRange { first: 0x59bb_b022, last: 0x59bb_b022 },
    CdnRange { first: 0x59bb_b307, last: 0x59bb_b307 },
    CdnRange { first: 0x59bb_b8ad, last: 0x59bb_b8ad },
    CdnRange { first: 0x59bb_b8b0, last: 0x59bb_b8b3 },
    CdnRange { first: 0x59bb_bce3, last: 0x59bb_bce4 },
    CdnRange { first: 0x5c7a_117c, last: 0x5c7a_117c },
    CdnRange { first: 0x5c7a_a6ed, last: 0x5c7a_a6ed },
    CdnRange { first: 0x5c7b_662b, last: 0x5c7b_662b },
    CdnRange { first: 0x5c7b_6a0b, last: 0x5c7b_6a0b },
    CdnRange { first: 0x5c7b_6a5a, last: 0x5c7b_6a5a },
    CdnRange { first: 0x5db4_d9d6, last: 0x5db4_d9d6 },
    CdnRange { first: 0x5e14_9a16, last: 0x5e14_9a16 },
    CdnRange { first: 0x5e2e_1bba, last: 0x5e2e_1bba },
    CdnRange { first: 0x5e80_fea6, last: 0x5e80_fea6 },
    CdnRange { first: 0x5e82_447a, last: 0x5e82_447a },
    CdnRange { first: 0x5e82_cc6e, last: 0x5e82_cc6e },
    CdnRange { first: 0x5f65_236a, last: 0x5f65_236a },
    CdnRange { first: 0x5f65_2370, last: 0x5f65_2370 },
    CdnRange { first: 0x5f65_852a, last: 0x5f65_852a },
    CdnRange { first: 0x5f65_8552, last: 0x5f65_8552 },
    CdnRange { first: 0x5f65_8583, last: 0x5f65_8583 },
    CdnRange { first: 0x6262_f28e, last: 0x6262_f28e },
    CdnRange { first: 0x634f_a900, last: 0x634f_a9ff },
    CdnRange { first: 0x6354_0000, last: 0x6354_ffff },
    CdnRange { first: 0x6356_0000, last: 0x6356_ffff },
    CdnRange { first: 0x6643_8a9b, last: 0x6643_8a9b },
    CdnRange { first: 0x66db_7e14, last: 0x66db_7e14 },
    CdnRange { first: 0x6715_f400, last: 0x6715_f7ff },
    CdnRange { first: 0x6716_c800, last: 0x6716_cbff },
    CdnRange { first: 0x671f_0400, last: 0x671f_07ff },
    CdnRange { first: 0x673c_0fa2, last: 0x673c_0fa7 },
    CdnRange { first: 0x673c_0fa9, last: 0x673c_0fad },
    CdnRange { first: 0x676c_e505, last: 0x676c_e505 },
    CdnRange { first: 0x676c_e729, last: 0x676c_e729 },
    CdnRange { first: 0x67d4_e309, last: 0x67d4_e309 },
    CdnRange { first: 0x67d6_145f, last: 0x67d6_145f },
    CdnRange { first: 0x67d8_dc09, last: 0x67d8_dc09 },
    CdnRange { first: 0x67eb_c7aa, last: 0x67eb_c7aa },
    CdnRange { first: 0x67f4_3200, last: 0x67f4_32ff },
    CdnRange { first: 0x67f5_de00, last: 0x67f5_e0ff },
    CdnRange { first: 0x6810_0000, last: 0x681b_ffff },
    CdnRange { first: 0x6861_5500, last: 0x6861_55ff },
    CdnRange { first: 0x6867_4007, last: 0x6867_4007 },
    CdnRange { first: 0x6867_4105, last: 0x6867_4105 },
    CdnRange { first: 0x6867_4132, last: 0x6867_4132 },
    CdnRange { first: 0x6867_414a, last: 0x6867_414a },
    CdnRange { first: 0x6870_9252, last: 0x6870_9252 },
    CdnRange { first: 0x689c_5000, last: 0x689c_5fff },
    CdnRange { first: 0x68a6_906a, last: 0x68a6_906a },
    CdnRange { first: 0x68ed_333a, last: 0x68ed_333a },
    CdnRange { first: 0x68ed_354a, last: 0x68ed_354a },
    CdnRange { first: 0x68ed_369a, last: 0x68ed_369a },
    CdnRange { first: 0x6b9b_2f92, last: 0x6b9b_2f92 },
    CdnRange { first: 0x6bb6_a3a2, last: 0x6bb6_a3a2 },
    CdnRange { first: 0x6c8a_0000, last: 0x6c8b_ffff },
    CdnRange { first: 0x6c9c_0000, last: 0x6c9f_ffff },
    CdnRange { first: 0x6ca2_c000, last: 0x6ca2_ffff },
    CdnRange { first: 0x6d3d_5361, last: 0x6d3d_5363 },
    CdnRange { first: 0x6d3d_53f1, last: 0x6d3d_53f7 },
    CdnRange { first: 0x6d3d_53f9, last: 0x6d3d_53fb },
    CdnRange { first: 0x6d3d_56c1, last: 0x6d3d_56c1 },
    CdnRange { first: 0x6d3d_5934, last: 0x6d3d_5934 },
    CdnRange { first: 0x6d3d_593a, last: 0x6d3d_593a },
    CdnRange { first: 0x6df8_2b67, last: 0x6df8_2b67 },
    CdnRange { first: 0x6df8_2b74, last: 0x6df8_2b75 },
    CdnRange { first: 0x6df8_2b9f, last: 0x6df8_2ba0 },
    CdnRange { first: 0x6df8_2ba2, last: 0x6df8_2ba5 },
    CdnRange { first: 0x6df8_2bb3, last: 0x6df8_2bb3 },
    CdnRange { first: 0x6df8_2bd0, last: 0x6df8_2bd0 },
    CdnRange { first: 0x6df8_2be7, last: 0x6df8_2be8 },
    CdnRange { first: 0x6df8_2bec, last: 0x6df8_2bec },
    CdnRange { first: 0x6df8_2bf0, last: 0x6df8_2bf1 },
    CdnRange { first: 0x6f0d_ab80, last: 0x6f0d_abff },
    CdnRange { first: 0x6f0d_b920, last: 0x6f0d_b95f },
    CdnRange { first: 0x7481_e200, last: 0x7481_e2bf },
    CdnRange { first: 0x74ca_501d, last: 0x74ca_501d },
    CdnRange { first: 0x74ca_50f7, last: 0x74ca_50f7 },
    CdnRange { first: 0x74ca_76c2, last: 0x74ca_76c2 },
    CdnRange { first: 0x74ca_9b92, last: 0x74ca_9b92 },
    CdnRange { first: 0x74ca_c1b2, last: 0x74ca_c1b2 },
    CdnRange { first: 0x74ca_e0a8, last: 0x74ca_e0a8 },
    CdnRange { first: 0x74ca_eb10, last: 0x74ca_eb10 },
    CdnRange { first: 0x76c1_6140, last: 0x76c1_61ff },
    CdnRange { first: 0x7793_b600, last: 0x7793_b6bf },
    CdnRange { first: 0x7834_0c40, last: 0x7834_0c7f },
    CdnRange { first: 0x7834_1660, last: 0x7834_167f },
    CdnRange { first: 0x7834_2780, last: 0x7834_279f },
    CdnRange { first: 0x7834_99c0, last: 0x7834_99ff },
    CdnRange { first: 0x78e8_ec00, last: 0x78e8_ecbf },
    CdnRange { first: 0x78fd_f0c0, last: 0x78fd_f0ff },
    CdnRange { first: 0x78fd_f1a0, last: 0x78fd_f1bf },
    CdnRange { first: 0x78fd_f580, last: 0x78fd_f5df },
    CdnRange { first: 0x7a0a_fb82, last: 0x7a0a_fb82 },
    CdnRange { first: 0x8001_23aa, last: 0x8001_23aa },
    CdnRange { first: 0x8001_34b3, last: 0x8001_34b3 },
    CdnRange { first: 0x808c_468d, last: 0x808c_468d },
    CdnRange { first: 0x81e3_b312, last: 0x81e3_b312 },
    CdnRange { first: 0x81e3_d9b2, last: 0x81e3_d9b3 },
    CdnRange { first: 0x820e_1d00, last: 0x820e_1dff },
    CdnRange { first: 0x82b0_0000, last: 0x82b0_efff },
    CdnRange { first: 0x8300_4800, last: 0x8300_4bff },
    CdnRange { first: 0x88f3_02ec, last: 0x88f3_02ec },
    CdnRange { first: 0x88f3_1031, last: 0x88f3_1031 },
    CdnRange { first: 0x88f3_2a0a, last: 0x88f3_2a0a },
    CdnRange { first: 0x88f3_2a5a, last: 0x88f3_2a5a },
    CdnRange { first: 0x88f3_46aa, last: 0x88f3_46aa },
    CdnRange { first: 0x8ac7_0481, last: 0x8ac7_0481 },
    CdnRange { first: 0x8ac7_0488, last: 0x8ac7_0488 },
    CdnRange { first: 0x8ac7_04b1, last: 0x8ac7_04b3 },
    CdnRange { first: 0x8ac7_0968, last: 0x8ac7_0968 },
    CdnRange { first: 0x8ac7_0fc1, last: 0x8ac7_0fc1 },
    CdnRange { first: 0x8ac7_18d1, last: 0x8ac7_18d1 },
    CdnRange { first: 0x8ac7_18d3, last: 0x8ac7_18d3 },
    CdnRange { first: 0x8ac7_18da, last: 0x8ac7_18db },
    CdnRange { first: 0x8ac7_2139, last: 0x8ac7_2139 },
    CdnRange { first: 0x8ac7_2407, last: 0x8ac7_240b },
    CdnRange { first: 0x8ac7_25e1, last: 0x8ac7_25e1 },
    CdnRange { first: 0x8ac7_25e3, last: 0x8ac7_25e3 },
    CdnRange { first: 0x8ac7_25e5, last: 0x8ac7_25e8 },
    CdnRange { first: 0x8ac7_283a, last: 0x8ac7_283a },
    CdnRange { first: 0x8ac7_2e41, last: 0x8ac7_2e45 },
    CdnRange { first: 0x8ac9_14a8, last: 0x8ac9_14a8 },
    CdnRange { first: 0x8ac9_3359, last: 0x8ac9_3359 },
    CdnRange { first: 0x8ac9_567a, last: 0x8ac9_567a },
    CdnRange { first: 0x8b54_a390, last: 0x8b54_a390 },
    CdnRange { first: 0x8b63_ae07, last: 0x8b63_ae07 },
    CdnRange { first: 0x8bb4_81d8, last: 0x8bb4_81d8 },
    CdnRange { first: 0x8c52_7000, last: 0x8c52_7fff },
    CdnRange { first: 0x8cf8_4000, last: 0x8cf8_ffff },
    CdnRange { first: 0x8d65_4000, last: 0x8d65_7fff },
    CdnRange { first: 0x8da4_23a0, last: 0x8da4_23a0 },
    CdnRange { first: 0x8de3_8ef2, last: 0x8de3_8ef2 },
    CdnRange { first: 0x8e36_b2d3, last: 0x8e36_b2d3 },
    CdnRange { first: 0x8e84_df4f, last: 0x8e84_df51 },
    CdnRange { first: 0x8efb_9600, last: 0x8efb_9dff },
    CdnRange { first: 0x8efb_a300, last: 0x8efb_a3ff },
    CdnRange { first: 0x8efb_a700, last: 0x8efb_a7ff },
    CdnRange { first: 0x8efb_b300, last: 0x8efb_b3ff },
    CdnRange { first: 0x8f37_4000, last: 0x8f37_4fff },
    CdnRange { first: 0x8fcc_0000, last: 0x8fcc_ffff },
    CdnRange { first: 0x8ff4_2681, last: 0x8ff4_2681 },
    CdnRange { first: 0x8ff4_2685, last: 0x8ff4_2686 },
    CdnRange { first: 0x8ff4_2688, last: 0x8ff4_2688 },
    CdnRange { first: 0x8ff4_2db1, last: 0x8ff4_2db1 },
    CdnRange { first: 0x8ff4_31b1, last: 0x8ff4_31b4 },
    CdnRange { first: 0x8ff4_31b7, last: 0x8ff4_31b7 },
    CdnRange { first: 0x8ff4_3252, last: 0x8ff4_325b },
    CdnRange { first: 0x8ff4_32d1, last: 0x8ff4_32d6 },
    CdnRange { first: 0x8ff4_3831, last: 0x8ff4_383a },
    CdnRange { first: 0x8ff4_3cc1, last: 0x8ff4_3cc1 },
    CdnRange { first: 0x8ff4_3cc3, last: 0x8ff4_3cc5 },
    CdnRange { first: 0x8ff4_3ed5, last: 0x8ff4_3ed5 },
    CdnRange { first: 0x904c_41d5, last: 0x904c_41d5 },
    CdnRange { first: 0x904c_4f16, last: 0x904c_4f16 },
    CdnRange { first: 0x904c_ec2c, last: 0x904c_ec2c },
    CdnRange { first: 0x90dc_0000, last: 0x90dc_ffff },
    CdnRange { first: 0x923b_45ca, last: 0x923b_45ca },
    CdnRange { first: 0x924b_0000, last: 0x924b_7fff },
    CdnRange { first: 0x92b9_f80f, last: 0x92b9_f80f },
    CdnRange { first: 0x9471_bea1, last: 0x9471_bea1 },
    CdnRange { first: 0x94fb_29f4, last: 0x94fb_29f4 },
    CdnRange { first: 0x94fb_2a7b, last: 0x94fb_2a7b },
    CdnRange { first: 0x94fb_8184, last: 0x94fb_8184 },
    CdnRange { first: 0x94fb_81d9, last: 0x94fb_81d9 },
    CdnRange { first: 0x94fb_8349, last: 0x94fb_834a },
    CdnRange { first: 0x94fb_83ee, last: 0x94fb_83ee },
    CdnRange { first: 0x9765_0000, last: 0x9765_ffff },
    CdnRange { first: 0x9859_a01a, last: 0x9859_a01a },
    CdnRange { first: 0x98e9_1661, last: 0x98e9_1667 },
    CdnRange { first: 0x9a5d_5647, last: 0x9a5d_5647 },
    CdnRange { first: 0x9a5f_564c, last: 0x9a5f_564c },
    CdnRange { first: 0x9c3b_42b6, last: 0x9c3b_42b6 },
    CdnRange { first: 0x9c3b_5c7e, last: 0x9c3b_5c7e },
    CdnRange { first: 0x9c3b_5fda, last: 0x9c3b_5fda },
    CdnRange { first: 0x9c3b_7e4e, last: 0x9c3b_7e4e },
    CdnRange { first: 0x9c92_2831, last: 0x9c92_2831 },
    CdnRange { first: 0x9c92_2b41, last: 0x9c92_2b41 },
    CdnRange { first: 0x9c92_2b44, last: 0x9c92_2b44 },
    CdnRange { first: 0x9c92_2b46, last: 0x9c92_2b48 },
    CdnRange { first: 0x9c92_38a1, last: 0x9c92_38a3 },
    CdnRange { first: 0x9c92_38a6, last: 0x9c92_38ab },
    CdnRange { first: 0x9d34_4000, last: 0x9d34_7fff },
    CdnRange { first: 0x9d5a_b4cd, last: 0x9d5a_b4cd },
    CdnRange { first: 0x9e33_7bcd, last: 0x9e33_7bcd },
    CdnRange { first: 0x9f45_3950, last: 0x9f45_3950 },
    CdnRange { first: 0x9f45_44ab, last: 0x9f45_44ab },
    CdnRange { first: 0xa237_870b, last: 0xa237_870b },
    CdnRange { first: 0xa29e_0000, last: 0xa29f_ffff },
    CdnRange { first: 0xa570_0700, last: 0xa570_07ff },
    CdnRange { first: 0xa752_0000, last: 0xa752_8fff },
    CdnRange { first: 0xa752_a000, last: 0xa752_afff },
    CdnRange { first: 0xa752_e000, last: 0xa752_efff },
    CdnRange { first: 0xa7eb_72a7, last: 0xa7eb_72a7 },
    CdnRange { first: 0xa877_0cbc, last: 0xa877_0cbc },
    CdnRange { first: 0xa877_27ee, last: 0xa877_27ee },
    CdnRange { first: 0xa996_cad2, last: 0xa996_cad2 },
    CdnRange { first: 0xa996_cf31, last: 0xa996_cf31 },
    CdnRange { first: 0xa996_cf33, last: 0xa996_cf33 },
    CdnRange { first: 0xa996_cfd2, last: 0xa996_cfd9 },
    CdnRange { first: 0xa996_d532, last: 0xa996_d532 },
    CdnRange { first: 0xa996_d773, last: 0xa996_d773 },
    CdnRange { first: 0xa996_db72, last: 0xa996_db72 },
    CdnRange { first: 0xa996_dce4, last: 0xa996_dce7 },
    CdnRange { first: 0xa996_dceb, last: 0xa996_dceb },
    CdnRange { first: 0xa996_dd93, last: 0xa996_dd93 },
    CdnRange { first: 0xa996_e122, last: 0xa996_e12b },
    CdnRange { first: 0xa996_ec61, last: 0xa996_ec64 },
    CdnRange { first: 0xa996_ec6a, last: 0xa996_ec6b },
    CdnRange { first: 0xa996_ee13, last: 0xa996_ee13 },
    CdnRange { first: 0xa996_f2c1, last: 0xa996_f2c1 },
    CdnRange { first: 0xa996_f721, last: 0xa996_f728 },
    CdnRange { first: 0xa996_f7b3, last: 0xa996_f7b6 },
    CdnRange { first: 0xa996_f9a2, last: 0xa996_f9a9 },
    CdnRange { first: 0xa996_fcd1, last: 0xa996_fcd1 },
    CdnRange { first: 0xac40_0000, last: 0xac47_ffff },
    CdnRange { first: 0xac6f_4000, last: 0xac6f_7fff },
    CdnRange { first: 0xacea_9f3a, last: 0xacea_9f3a },
    CdnRange { first: 0xacea_c70f, last: 0xacea_c70f },
    CdnRange { first: 0xacfd_8b00, last: 0xacfd_8bff },
    CdnRange { first: 0xacff_fd8c, last: 0xacff_fd8c },
    CdnRange { first: 0xadf5_3000, last: 0xadf5_3fff },
    CdnRange { first: 0xb009_8b37, last: 0xb009_8b37 },
    CdnRange { first: 0xb009_8b5e, last: 0xb009_8b5e },
    CdnRange { first: 0xb23f_0270, last: 0xb23f_0270 },
    CdnRange { first: 0xb23f_1534, last: 0xb23f_1534 },
    CdnRange { first: 0xb23f_29ea, last: 0xb23f_29ea },
    CdnRange { first: 0xb23f_29f2, last: 0xb23f_29f2 },
    CdnRange { first: 0xb23f_29f7, last: 0xb23f_29f7 },
    CdnRange { first: 0xb2af_8633, last: 0xb2af_8633 },
    CdnRange { first: 0xb495_e7af, last: 0xb495_e7af },
    CdnRange { first: 0xb4a3_3900, last: 0xb4a3_39bf },
    CdnRange { first: 0xb5ae_a866, last: 0xb5ae_a866 },
    CdnRange { first: 0xb818_4d05, last: 0xb818_4d05 },
    CdnRange { first: 0xb818_4d07, last: 0xb818_4d07 },
    CdnRange { first: 0xb818_4d0b, last: 0xb818_4d0b },
    CdnRange { first: 0xb818_4d10, last: 0xb818_4d10 },
    CdnRange { first: 0xb818_4d15, last: 0xb818_4d15 },
    CdnRange { first: 0xb818_4d1d, last: 0xb818_4d1d },
    CdnRange { first: 0xb818_4d20, last: 0xb818_4d20 },
    CdnRange { first: 0xb818_4d24, last: 0xb818_4d24 },
    CdnRange { first: 0xb818_4d2a, last: 0xb818_4d2a },
    CdnRange { first: 0xb833_fc04, last: 0xb833_fc04 },
    CdnRange { first: 0xb854_dd22, last: 0xb854_dd22 },
    CdnRange { first: 0xb918_0b12, last: 0xb918_0b13 },
    CdnRange { first: 0xb91f_1000, last: 0xb91f_13ff },
    CdnRange { first: 0xb928_6a75, last: 0xb928_6a75 },
    CdnRange { first: 0xb93b_dcc6, last: 0xb93b_dcc7 },
    CdnRange { first: 0xb95d_01f2, last: 0xb95d_01f7 },
    CdnRange { first: 0xb95d_01f9, last: 0xb95d_01fb },
    CdnRange { first: 0xb95d_02f3, last: 0xb95d_02f6 },
    CdnRange { first: 0xb95d_02f8, last: 0xb95d_02f8 },
    CdnRange { first: 0xb95d_02fb, last: 0xb95d_02fb },
    CdnRange { first: 0xb95d_03f3, last: 0xb95d_03f4 },
    CdnRange { first: 0xb95d_03f6, last: 0xb95d_03f6 },
    CdnRange { first: 0xb966_d941, last: 0xb966_d941 },
    CdnRange { first: 0xb96f_6f9a, last: 0xb96f_6fa0 },
    CdnRange { first: 0xb96f_6fa4, last: 0xb96f_6fa4 },
    CdnRange { first: 0xb96f_6fa6, last: 0xb96f_6fac },
    CdnRange { first: 0xb983_407c, last: 0xb983_407c },
    CdnRange { first: 0xb987_559a, last: 0xb987_559a },
    CdnRange { first: 0xb998_4011, last: 0xb998_4011 },
    CdnRange { first: 0xb998_4013, last: 0xb998_4013 },
    CdnRange { first: 0xb998_4017, last: 0xb998_4017 },
    CdnRange { first: 0xb998_42f7, last: 0xb998_42f7 },
    CdnRange { first: 0xb9a5_aa4a, last: 0xb9a5_aa4a },
    CdnRange { first: 0xb9b4_0c44, last: 0xb9b4_0c44 },
    CdnRange { first: 0xb9b4_0efa, last: 0xb9b4_0efa },
    CdnRange { first: 0xb9c7_6c00, last: 0xb9c7_6fff },
    CdnRange { first: 0xb9c8_e829, last: 0xb9c8_e82b },
    CdnRange { first: 0xb9c8_e831, last: 0xb9c8_e832 },
    CdnRange { first: 0xbc28_7ee3, last: 0xbc28_7ee3 },
    CdnRange { first: 0xbc72_6000, last: 0xbc72_6fff },
    CdnRange { first: 0xbe5d_f000, last: 0xbe5d_ffff },
    CdnRange { first: 0xc01e_fc00, last: 0xc01e_ffff },
    CdnRange { first: 0xc0a9_78a2, last: 0xc0a9_78a2 },
    CdnRange { first: 0xc0bd_4192, last: 0xc0bd_4192 },
    CdnRange { first: 0xc1a2_8301, last: 0xc1a2_8301 },
    CdnRange { first: 0xc1c9_beae, last: 0xc1c9_beae },
    CdnRange { first: 0xc2f2_0bba, last: 0xc2f2_0bba },
    CdnRange { first: 0xc345_8c70, last: 0xc345_8c70 },
    CdnRange { first: 0xc3b5_a3c2, last: 0xc3b5_a3c4 },
    CdnRange { first: 0xc3b5_a3c6, last: 0xc3b5_a3c6 },
    CdnRange { first: 0xc3b5_a3ca, last: 0xc3b5_a3cb },
    CdnRange { first: 0xc3b5_a69e, last: 0xc3b5_a69e },
    CdnRange { first: 0xc3c9_0b9c, last: 0xc3c9_0b9c },
    CdnRange { first: 0xc3c9_51d9, last: 0xc3c9_51d9 },
    CdnRange { first: 0xc3c9_6d3b, last: 0xc3c9_6d3b },
    CdnRange { first: 0xc3ce_e545, last: 0xc3ce_e545 },
    CdnRange { first: 0xc3ee_7f62, last: 0xc3ee_7f62 },
    CdnRange { first: 0xc5ea_f000, last: 0xc5ea_f3ff },
    CdnRange { first: 0xc629_8000, last: 0xc629_ffff },
    CdnRange { first: 0xc71b_4800, last: 0xc71b_4fff },
    CdnRange { first: 0xc7e8_0000, last: 0xc7e8_ffff },
    CdnRange { first: 0xc819_0b08, last: 0xc819_0b08 },
    CdnRange { first: 0xc819_1067, last: 0xc819_1067 },
    CdnRange { first: 0xc819_1249, last: 0xc819_1249 },
    CdnRange { first: 0xc819_1606, last: 0xc819_1606 },
    CdnRange { first: 0xc819_2083, last: 0xc819_2083 },
    CdnRange { first: 0xc819_24a6, last: 0xc819_24a6 },
    CdnRange { first: 0xc819_2645, last: 0xc819_2645 },
    CdnRange { first: 0xc819_2a46, last: 0xc819_2a46 },
    CdnRange { first: 0xc819_2d04, last: 0xc819_2d04 },
    CdnRange { first: 0xc819_3505, last: 0xc819_3505 },
    CdnRange { first: 0xc819_3905, last: 0xc819_3905 },
    CdnRange { first: 0xc819_3e05, last: 0xc819_3e05 },
    CdnRange { first: 0xc819_4665, last: 0xc819_4665 },
    CdnRange { first: 0xc819_504a, last: 0xc819_504a },
    CdnRange { first: 0xc819_565a, last: 0xc819_565a },
    CdnRange { first: 0xcb39_5261, last: 0xcb39_5261 },
    CdnRange { first: 0xcb39_5263, last: 0xcb39_5263 },
    CdnRange { first: 0xcb39_5265, last: 0xcb39_5265 },
    CdnRange { first: 0xccf6_a400, last: 0xccf6_bfff },
    CdnRange { first: 0xcdfb_ca00, last: 0xcdfb_dfff },
    CdnRange { first: 0xcdfb_f900, last: 0xcdfb_feff },
    CdnRange { first: 0xcf79_0f5c, last: 0xcf79_0f5c },
    CdnRange { first: 0xcf79_0f64, last: 0xcf79_0f64 },
    CdnRange { first: 0xcf79_0f6c, last: 0xcf79_0f6c },
    CdnRange { first: 0xcf79_0f7c, last: 0xcf79_0f7c },
    CdnRange { first: 0xcf79_0fac, last: 0xcf79_0fac },
    CdnRange { first: 0xcf79_0fb4, last: 0xcf79_0fb4 },
    CdnRange { first: 0xcf79_0fc4, last: 0xcf79_0fc4 },
    CdnRange { first: 0xcf79_0fcc, last: 0xcf79_0fcc },
    CdnRange { first: 0xcf79_0fd4, last: 0xcf79_0fd4 },
    CdnRange { first: 0xcf79_0fdc, last: 0xcf79_0fdc },
    CdnRange { first: 0xcf79_0fe4, last: 0xcf79_0fe4 },
    CdnRange { first: 0xcf79_0fec, last: 0xcf79_0fec },
    CdnRange { first: 0xcf79_0ff4, last: 0xcf79_0ff4 },
    CdnRange { first: 0xcf79_0ffc, last: 0xcf79_0ffc },
    CdnRange { first: 0xcf79_2e94, last: 0xcf79_2e94 },
    CdnRange { first: 0xcf79_2e9c, last: 0xcf79_2e9c },
    CdnRange { first: 0xcf79_2ebc, last: 0xcf79_2ebc },
    CdnRange { first: 0xcf79_2ed4, last: 0xcf79_2ed4 },
    CdnRange { first: 0xcf79_2edc, last: 0xcf79_2edc },
    CdnRange { first: 0xcf79_2ee4, last: 0xcf79_2ee4 },
    CdnRange { first: 0xcf79_2eec, last: 0xcf79_2eec },
    CdnRange { first: 0xcf79_4b84, last: 0xcf79_4b84 },
    CdnRange { first: 0xcf79_500c, last: 0xcf79_500c },
    CdnRange { first: 0xcf79_50ac, last: 0xcf79_50ac },
    CdnRange { first: 0xcf79_5a3c, last: 0xcf79_5a3c },
    CdnRange { first: 0xcfd3_d691, last: 0xcfd3_d691 },
    CdnRange { first: 0xd053_eae0, last: 0xd053_eae0 },
    CdnRange { first: 0xd05b_6fe3, last: 0xd05b_6fe3 },
    CdnRange { first: 0xd1b1_57c5, last: 0xd1b1_57c5 },
    CdnRange { first: 0xd466_2871, last: 0xd466_2872 },
    CdnRange { first: 0xd466_2878, last: 0xd466_2878 },
    CdnRange { first: 0xd466_2e73, last: 0xd466_2e73 },
    CdnRange { first: 0xd466_2e76, last: 0xd466_2e77 },
    CdnRange { first: 0xd466_3231, last: 0xd466_3232 },
    CdnRange { first: 0xd466_3234, last: 0xd466_3234 },
    CdnRange { first: 0xd466_3236, last: 0xd466_3236 },
    CdnRange { first: 0xd466_323b, last: 0xd466_323b },
    CdnRange { first: 0xd889_2000, last: 0xd889_3fff },
    CdnRange { first: 0xd8ca_c234, last: 0xd8ca_c234 },
    CdnRange { first: 0xd8ca_c2fc, last: 0xd8ca_c2fc },
];
const BUILTIN_CDN_SNIS: &[&str] = &[
    "a.akamaihd-staging.net",
    "a.akamaihd.net",
    "a.akamaized-staging.net",
    "a.akamaized.net",
    "a248.e.akamai.net",
    "www.akamai.com",
    "alchzwwfzmrtgoaf-a.akamaihd.net",
    "aparat.com",
    "b-cdn.net",
    "bbe-getimage.akamaized.net",
    "bmi.ir",
    "digikala.com",
    "google.com",
    "jkiysqntxacscicm-a.akamaihd.net",
    "prfzquobemaspprl-a.akamaihd.net",
    "prod.global.ssl.fastly.net",
    "quic.map.fastly.net",
    "snapp.ir",
    "telewebion.com",
    "varzesh3.com",
    "yryirjrhqffsxwpg-a.akamaihd.net",
    "megram-supg-instem.b-cdn.net",
    "pirtus-moding-hareware.b-cdn.net",
    "cdn.ncbi.nlm.nih.gov",
    "ncbi.nlm.nih.gov",
    "pmc.ncbi.nlm.nih.gov",
    "pubmed.ncbi.nlm.nih.gov",
    "pubmed.redirect",
    "www.ncbi.nlm.nih.gov",
    "www.st-va.ncbi.nlm.nih.gov",
    "actions.githubusercontent.com",
    "alambic-origin.githubusercontent.com",
    "alive.github.com",
    "api.github.com",
    "api.githubcopilot.com",
    "api.individual.githubcopilot.com",
    "avatars.githubusercontent.com",
    "buzzfeed.com",
    "camo-origin.githubusercontent.com",
    "camo.githubusercontent.com",
    "central.github.com",
    "codeload.github.com",
    "collector.github.com",
    "developer.fastly.com",
    "fastly.com",
    "fastly.redirect",
    "gist.github.com",
    "github-alive.redirect",
    "github-com-2.redirect",
    "github-com.redirect",
    "github-uploads.redirect",
    "github.com",
    "github.githubassets.com",
    "github.io",
    "githubassets.com",
    "githubusercontent.com",
    "glb-db52c2cf8be544.github.com",
    "live.github.com",
    "objects-origin.githubusercontent.com",
    "private-user-images.githubusercontent.com",
    "pypi.org",
    "raw.githubusercontent.com",
    "reddit.com",
    "release-assets.githubusercontent.com",
    "uploads.github.com",
    "www.fastly.com",
    "www.github.com",
    "www.python.org",
    "xtls.github.io",
    "cdnjs.cloudflare.com",
    "cloudflare.com",
    "lickbash-nonal-nonink.psiphon3.net",
    "morer-actocumerl-reless.psiphon3.net",
    "serce-sourite-docurch.psiphon3.net",
    "www.cloudflare.com",
    "1.aws-lbr.amazonaws.com",
    "amazonaws-china.com",
    "aws-us-east-1.amazon.com",
    "aws-us-west-2.amazon.com",
    "aws.amazon.com",
    "kubernetes.io",
    "letsencrypt.org",
    "netlify.redirect",
    "www.amazonaws-china.com",
    "www.aws.amazon.com",
    "www.netlify.com",
    "ai-sdk.dev",
    "cursor.com",
    "err.sh",
    "hyper.is",
    "nextjs.org",
    "now.sh",
    "react.dev",
    "skills.sh",
    "static.fun",
    "title.sh",
    "turborepo.org",
    "vercel-dns.com",
    "vercel-sites.redirect",
    "vercel-status.com",
    "vercel.app",
    "vercel.blog",
    "vercel.com",
    "vercel.dev",
    "vercel.events",
    "vercel.live",
    "vercel.pub",
    "vercel.sh",
    "vercel.store",
    "zeit-world.co.uk",
    "zeit-world.com",
    "zeit-world.net",
    "zeit-world.org",
    "zeit.co",
    "zeit.sh",
    "zeitworld.com",
    "dns.google",
    "google-main-services.redirect",
    "googlevideo.com",
    "www.google.com",
    "www.googlevideo.com",
    "www.youtube.com",
];

fn builtin_cdn_ips(limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let total: u64 = BUILTIN_CDN_RANGES
        .iter()
        .map(|range| u64::from(range.last - range.first) + 1)
        .sum();
    if total <= u64::try_from(limit).unwrap_or(u64::MAX) {
        let mut out = Vec::with_capacity(usize::try_from(total).unwrap_or(limit));
        for range in BUILTIN_CDN_RANGES {
            for address in range.first..=range.last {
                out.push(Ipv4Addr::from(address).to_string());
            }
        }
        return out;
    }
    (0..limit)
        .filter_map(|index| {
            let mut offset =
                u64::try_from(index).unwrap_or(0) * total / u64::try_from(limit).unwrap_or(1);
            for range in BUILTIN_CDN_RANGES {
                let span = u64::from(range.last - range.first) + 1;
                if offset < span {
                    let address = range.first + u32::try_from(offset).unwrap_or(0);
                    return Some(Ipv4Addr::from(address).to_string());
                }
                offset -= span;
            }
            None
        })
        .collect()
}

const CDN_FRONTING_PROTOCOLS: &[&str] = &[
    "FRONTED-MEEK-CDN-OSSH",
    "FRONTED-MEEK-CDN-HTTP-OSSH",
    "FRONTED-MEEK-CDN-QUIC-OSSH",
];
const DIRECT_PROTOCOLS: &[&str] = &[
    "SSH",
    "OSSH",
    "TLS-OSSH",
    "UNFRONTED-MEEK-OSSH",
    "UNFRONTED-MEEK-HTTPS-OSSH",
    "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
    "QUIC-OSSH",
    "SHADOWSOCKS-OSSH",
    "FRONTED-MEEK-OSSH",
    "FRONTED-MEEK-CDN-OSSH",
    "FRONTED-MEEK-HTTP-OSSH",
    "FRONTED-MEEK-CDN-HTTP-OSSH",
    "FRONTED-MEEK-QUIC-OSSH",
    "FRONTED-MEEK-CDN-QUIC-OSSH",
];
const MAX_REQUEST: usize = 16 * 1024;
const DIAL_ATTEMPTS: usize = 64;
const DIAL_WORKERS: usize = 10;
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
const HOLD_OFF_LIMIT: Duration = Duration::from_secs(60);
const FLOW_STACK: usize = 128 * 1024;

static NO_CREDENTIAL: Credential = Credential {
    user: String::new(),
    pass: String::new(),
};

/// The outbound as a flow sees it: a native tunnel and the loopback SOCKS edge over it.
#[derive(Clone)]
pub(crate) struct PsiphonOut {
    inner: Option<Arc<Inner>>,
    endpoint: SocketAddr,
    credential: Arc<Credential>,
    version: Version,
    loopback: bool,
}

struct Inner {
    settings: Settings,
    config_state: u64,
    entries: Mutex<Arc<Vec<Server>>>,
    sloks: Arc<crate::psiphon_osl::SlokStore>,
    requests: Arc<crate::psiphon_osl::ServerEvents>,
    osl_seeded: Arc<AtomicBool>,
    last_osl: Mutex<Option<Instant>>,
    last_osl_failure: Mutex<Option<Instant>>,
    sessions: Mutex<Vec<Arc<Session>>>,
    next_session: AtomicUsize,
    affinity: Mutex<Option<(String, u16)>>,
    moved_to_front: Mutex<HashSet<String>>,
    connecting: Mutex<()>,
    session_id: String,
    stopping: AtomicBool,
    endpoint: SocketAddr,
    http_endpoint: Option<SocketAddr>,
    udpgw: Mutex<Option<Arc<UdpGateway>>>,
    conduit: Mutex<Option<Arc<crate::psiphon_webrtc::Conduit>>>,
    split_untunneled: Mutex<HashMap<String, Instant>>,
    replay: Arc<crate::psiphon_replay::Cache>,
    light: Option<Arc<crate::psiphon_light::Client>>,
}

/// The reference's protocol hold-off: a jittered delay before a new tunnel is activated.
#[derive(Clone, Debug, Default)]
struct HoldOff {
    names: Vec<String>,
    probability: f64,
    min: Duration,
    max: Duration,
}

impl HoldOff {
    /// The hold-off for a protocol, zero when it is not named.
    fn duration(&self, protocol: &str) -> Duration {
        if self.names.is_empty()
            || !self
                .names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(protocol))
            || !coin(self.probability)
        {
            return Duration::ZERO;
        }
        let low = u64::try_from(self.min.as_millis()).unwrap_or(u64::MAX);
        let high = u64::try_from(self.max.as_millis())
            .unwrap_or(u64::MAX)
            .max(low);
        let span = high.saturating_sub(low).saturating_add(1);
        Duration::from_millis(low + u64::from_le_bytes(random::<8>()) % span)
    }
}

/// The reference's provider-scoped hold-off: direct and inproxy key on provider/region,
/// fronting keys on the fronting provider ID.
#[derive(Clone, Debug, Default)]
struct HoldOffClass {
    providers: Vec<(String, Vec<String>)>,
    region_scoped: bool,
    probability: f64,
    min: Duration,
    max: Duration,
}

impl HoldOffClass {
    fn delay(&self, provider: Option<&str>, region: Option<&str>) -> Duration {
        if self.providers.is_empty() || !coin(self.probability) {
            return Duration::ZERO;
        }
        let Some(provider) = provider else {
            return Duration::ZERO;
        };
        let matched = self.providers.iter().any(|(id, regions)| {
            id == provider
                && (!self.region_scoped
                    || regions
                        .iter()
                        .any(|allowed| allowed.is_empty() || Some(allowed.as_str()) == region))
        });
        if !matched {
            return Duration::ZERO;
        }
        let low = u64::try_from(self.min.as_millis()).unwrap_or(u64::MAX);
        let high = u64::try_from(self.max.as_millis())
            .unwrap_or(u64::MAX)
            .max(low);
        let span = high.saturating_sub(low).saturating_add(1);
        Duration::from_millis(low + u64::from_le_bytes(random::<8>()) % span)
    }
}

#[derive(Clone, Debug)]
struct LivenessSpec {
    pattern: String,
    min_upstream: usize,
    max_upstream: usize,
    min_downstream: usize,
    max_downstream: usize,
}

/// The reference's liveness probes, keyed by tunnel-protocol pattern.
#[derive(Clone, Debug, Default)]
struct Liveness {
    initial: Vec<LivenessSpec>,
    periodic: Vec<LivenessSpec>,
}

impl Liveness {
    /// The first probe spec naming this protocol in the given state.
    fn spec(&self, protocol: &str, established: bool) -> Option<LivenessSpec> {
        let probes = if established {
            &self.periodic
        } else {
            &self.initial
        };
        let mut matched: Option<&LivenessSpec> = None;
        let mut fallback = None;
        for probe in probes {
            if probe.pattern.is_empty() {
                fallback = Some(probe);
            } else if wildcard_match(&probe.pattern, protocol)
                && matched.is_none_or(|best| probe.pattern.len() > best.pattern.len())
            {
                matched = Some(probe);
            }
        }
        matched.or(fallback).cloned()
    }
}

/// The reference's protocol wildcard: `*` matches any run of bytes, everything else is literal.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(mut rest) = text.strip_prefix(parts.next().unwrap_or_default()) else {
        return false;
    };
    let mut part = parts.next();
    while let Some(current) = part {
        part = parts.next();
        if part.is_none() {
            return current.is_empty() || rest.ends_with(current);
        }
        if current.is_empty() {
            continue;
        }
        let Some(at) = rest.find(current) else {
            return false;
        };
        rest = &rest[at + current.len()..];
    }
    rest.is_empty()
}

#[allow(clippy::struct_excessive_bools)]
struct Settings {
    state: PathBuf,
    listen: SocketAddr,
    http_listen: Option<u16>,
    region: Option<String>,
    ready: Duration,
    entries: Option<PathBuf>,
    target: Option<String>,
    protocols: Vec<String>,
    initial_protocols: Vec<String>,
    fronted: bool,
    fronted_fallback: bool,
    cdn_ips: Vec<String>,
    cdn_snis: Vec<String>,
    fronted_overrides: Vec<FrontedOverride>,
    initial_count: usize,
    pool: usize,
    latency: Latency,
    establish: Option<Duration>,
    workers: usize,
    intensive_workers: usize,
    stagger: Duration,
    pause: Duration,
    affinity_grace: Duration,
    keepalive: Option<KeepAlive>,
    propagation: String,
    platform: String,
    client_version: String,
    api_encoding: ApiEncoding,
    device_region: Option<String>,
    device_location: Option<String>,
    client_features: Vec<String>,
    split_tunnel_own_region: bool,
    split_tunnel_regions: Vec<String>,
    compartment: String,
    conduit: bool,
    conduit_mode: ConduitMode,
    conduit_timeout: Duration,
    conduit_protocols: Vec<String>,
    reject_countries: Vec<String>,
    reject_cidrs: Vec<String>,
    geoip_path: Option<String>,
    dns_servers: Vec<SocketAddr>,
    dns: crate::psiphon_dns::Config,
    limit_quic_versions: Vec<String>,
    quic_noise: Option<String>,
    tls_shape: TlsShape,
    meek_padding: (u16, u16),
    limit_meek_buffers: bool,
    relay_buffer: usize,
    rate: Option<crate::psiphon_rate::Rate>,
    holdoff: HoldOff,
    holdoff_direct: HoldOffClass,
    holdoff_fronting: HoldOffClass,
    holdoff_inproxy: HoldOffClass,
    compress_tactics: bool,
    server_entry_max_move_to_front: i64,
    server_entry_reset_probability: f64,
    restrict_direct_regions: Vec<(String, Vec<String>)>,
    restrict_direct_probability: f64,
    restrict_inproxy_regions: Vec<(String, Vec<String>)>,
    restrict_inproxy_probability: f64,
    restrict_fronting_ids: Vec<String>,
    restrict_fronting_probability: f64,
    liveness: Liveness,
    dial_ports: Vec<(String, PortList)>,
    dial_ports_probability: f64,
    prioritize_protocols: Vec<String>,
    prioritize_count: usize,
    prioritize_probability: f64,
    limit_protocols_probability: f64,
    initial_limit_probability: f64,
    replay: crate::psiphon_replay::Settings,
    disable_tactics: bool,
    meek_headers: Vec<(String, String)>,
    ssh_channel_window: u32,
    server_lists: Vec<String>,
    server_lists_explicit: bool,
    remote_fetch_disabled: bool,
    server_list_key: String,
    osl_roots: Vec<TransferRoot>,
    remote_list_key: String,
    remote_list_retry: Duration,
    limit_cpu: bool,
    disable_api: bool,
    ssh_algorithms: Option<[String; 4]>,
    emit_sloks: bool,
    emit_server_alerts: bool,
    headers: Vec<(String, String)>,
    proxy: Option<Proxy>,
    sponsor: String,
    session_id: Option<String>,
    authorizations: Vec<String>,
    proxy_user: Option<String>,
    proxy_pass: Option<String>,
    burst: Option<crate::psiphon_burst::Config>,
    light: Option<crate::psiphon_light::Config>,
    raw: Option<Json>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConduitMode {
    Auto,
    Public,
    Shirokhorshid,
}

/// One `LimitTunnelDialPortNumbers` entry: the port numbers, as single ports or closed ranges.
#[derive(Clone, Debug, Default)]
struct PortList {
    ranges: Vec<(u16, u16)>,
}

impl PortList {
    fn contains(&self, port: u16) -> bool {
        self.ranges
            .iter()
            .any(|(low, high)| port >= *low && port <= *high)
    }
}

#[derive(Debug, Clone)]
struct FrontedOverride {
    override_id: Option<String>,
    dials: Vec<String>,
    snis: Vec<String>,
    disable_sni: bool,
    alpn: Vec<Vec<u8>>,
    match_providers: Vec<regex::Regex>,
    match_dials: Vec<regex::Regex>,
    match_hosts: Vec<regex::Regex>,
    verify_server_names: Vec<String>,
    verify_pins: Vec<String>,
    tls_profile: Option<String>,
    skip_cert_verify: bool,
}

impl FrontedOverride {
    /// The reference applies an override only when every named match group finds a value.
    fn matches(&self, meek: &crate::psiphon_meek::Meek) -> bool {
        let mut dials = Vec::with_capacity(meek.fronts.len() + 1);
        dials.push(meek.dial.as_str());
        dials.extend(meek.fronts.iter().map(|(dial, _)| dial.as_str()));
        regex_matches_any(
            &self.match_providers,
            &[meek.provider_id.as_deref().unwrap_or("")],
        ) && regex_matches_any(&self.match_dials, &dials)
            && regex_matches_any(&self.match_hosts, &[meek.host.as_str()])
    }
}

/// One `ObfuscatedServerListRootURLs` entry: a base URL and its per-URL transfer policy.
#[derive(Debug, Clone)]
struct TransferRoot {
    url: String,
    skip_verify: bool,
    headers: Vec<(String, String)>,
}

fn regex_matches_any(patterns: &[regex::Regex], values: &[&str]) -> bool {
    patterns.is_empty()
        || values
            .iter()
            .any(|value| patterns.iter().any(|pattern| pattern.is_match(value)))
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for PsiphonOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsiphonOut")
            .field("endpoint", &self.endpoint)
            .field("version", &self.version)
            .field("loopback", &self.loopback)
            .field("connected", &self.inner.is_some())
            .finish()
    }
}

impl PsiphonOut {
    /// Start the native tunnel and its loopback SOCKS edge.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn new(settings: Option<&Json>) -> Result<Self, String> {
        let settings = Settings::from_json(settings)?;
        warn_ignored(settings.raw.as_ref());
        if !settings.reject_countries.is_empty() && settings.geoip_path.is_none() {
            eprintln!(
                "psiphon: GeoIPDatabasePath is not set, so proxy-country filtering is skipped"
            );
        }
        if settings.compartment != PRIVATE_COMPARTMENT_ID && !settings.conduit {
            eprintln!(
                "psiphon: a custom compartment is set, but this transport dials SSH/OSSH only"
            );
        }
        let endpoint = settings.listen;
        let listener = TcpListener::bind(endpoint)
            .map_err(|error| format!("psiphon: listen {endpoint}: {error}"))?;
        let endpoint = listener
            .local_addr()
            .map_err(|error| format!("psiphon: listen address: {error}"))?;
        let entries = load_entries(&settings)?;
        if entries.is_empty() {
            return Err("psiphon: the server list holds no SSH entries".to_owned());
        }
        let slok_path = state_is_ours(&settings.state).then(|| settings.state.join("osl-sloks"));
        let sloks = crate::psiphon_osl::SlokStore::open(slok_path);
        let osl_seeded = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(crate::psiphon_osl::ServerEvents {
            sloks: Arc::clone(&sloks),
            seeded: Arc::clone(&osl_seeded),
            emit_alerts: settings.emit_server_alerts,
            emit_sloks: settings.emit_sloks,
        });
        let http = settings
            .http_listen
            .map(|port| {
                TcpListener::bind(SocketAddr::new(endpoint.ip(), port))
                    .map_err(|error| format!("psiphon: http listen {port}: {error}"))
            })
            .transpose()?;
        let http_endpoint = http
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()
            .map_err(|error| format!("psiphon: http listen address: {error}"))?;
        let session_id = settings
            .session_id
            .clone()
            .unwrap_or_else(|| hex(&random::<16>()));
        let config_state = settings.config_state();
        let replay = Arc::new(crate::psiphon_replay::Cache::new(settings.replay.clone()));
        let light = settings.light.clone().and_then(|mut config| {
            config.session_id.clone_from(&session_id);
            match crate::psiphon_light::Client::new(config) {
                Ok(client) => Some(Arc::new(client)),
                Err(error) => {
                    eprintln!("psiphon: {error}");
                    None
                }
            }
        });
        let inner = Arc::new(Inner {
            session_id,
            settings,
            config_state,
            entries: Mutex::new(Arc::new(entries)),
            sloks,
            requests,
            osl_seeded,
            last_osl: Mutex::new(None),
            last_osl_failure: Mutex::new(None),
            sessions: Mutex::new(Vec::new()),
            next_session: AtomicUsize::new(0),
            affinity: Mutex::new(None),
            moved_to_front: Mutex::new(HashSet::new()),
            connecting: Mutex::new(()),
            stopping: AtomicBool::new(false),
            endpoint,
            http_endpoint,
            udpgw: Mutex::new(None),
            conduit: Mutex::new(None),
            split_untunneled: Mutex::new(HashMap::new()),
            replay,
            light,
        });
        // The edge binds before a tunnel exists, so a refusal is retried, never a lane that exits.
        let weak = Arc::downgrade(&inner);
        thread::Builder::new()
            .name("psiphon-tunnel".to_owned())
            .spawn(move || warm_tunnel(&weak))
            .map_err(|error| format!("psiphon: tunnel thread: {error}"))?;
        if let Some(http) = http {
            let weak = Arc::downgrade(&inner);
            thread::Builder::new()
                .name("psiphon-http".to_owned())
                .spawn(move || accept_http(http, weak))
                .map_err(|error| format!("psiphon: http listener thread: {error}"))?;
        }
        let credential = Arc::new(Credential {
            user: inner.settings.proxy_user.clone().unwrap_or_default(),
            pass: inner.settings.proxy_pass.clone().unwrap_or_default(),
        });
        let loopback = endpoint.ip().is_loopback();
        let weak = Arc::downgrade(&inner);
        thread::Builder::new()
            .name("psiphon-socks".to_owned())
            .spawn(move || accept_loop(listener, weak))
            .map_err(|error| format!("psiphon: listener thread: {error}"))?;
        Ok(Self {
            inner: Some(inner),
            endpoint,
            credential,
            version: Version::V5,
            loopback,
        })
    }

    /// Validate the settings without opening a socket or downloading a list.
    pub(crate) fn validate(settings: Option<&Json>) -> Result<Self, String> {
        let settings = Settings::from_json(settings)?;
        warn_ignored(settings.raw.as_ref());
        if !settings.reject_countries.is_empty() && settings.geoip_path.is_none() {
            eprintln!(
                "psiphon: GeoIPDatabasePath is not set, so proxy-country filtering is skipped"
            );
        }
        if settings.compartment != PRIVATE_COMPARTMENT_ID && !settings.conduit {
            eprintln!(
                "psiphon: a custom compartment is set, but this transport dials SSH/OSSH only"
            );
        }
        if let Some(config) = settings.light.clone() {
            if let Err(error) = crate::psiphon_light::Client::new(config) {
                eprintln!("psiphon: {error}");
            }
        }
        let endpoint = settings.listen;
        Ok(Self {
            inner: None,
            endpoint,
            credential: Arc::new(Credential {
                user: settings.proxy_user.unwrap_or_default(),
                pass: settings.proxy_pass.unwrap_or_default(),
            }),
            version: Version::V5,
            loopback: endpoint.ip().is_loopback(),
        })
    }

    /// The local SOCKS credential: a loopback edge that names none needs none.
    pub(crate) fn credential(&self) -> &Credential {
        if self.loopback && self.credential.user.is_empty() {
            &NO_CREDENTIAL
        } else {
            &self.credential
        }
    }

    /// The handshake a flow pays: SOCKS4 only where the edge demands nothing and the target fits.
    pub(crate) fn session(&self, target: &Destination<'_>) -> (Version, &Credential) {
        if self.loopback
            && self.credential.user.is_empty()
            && !matches!(target, Destination::V6(..))
        {
            (Version::V4, &NO_CREDENTIAL)
        } else {
            (Version::V5, self.credential())
        }
    }

    #[must_use]
    pub(crate) fn version(&self) -> Version {
        self.version
    }

    #[must_use]
    pub(crate) fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect(wake_address(self.endpoint));
        if let Some(http) = self.http_endpoint {
            let _ = TcpStream::connect(wake_address(http));
        }
        if let Some(gateway) = lock(&self.udpgw).take() {
            gateway.close();
        }
        for session in lock(&self.sessions).drain(..) {
            session.close();
        }
    }
}

/// A listener on the wildcard address is woken through the loopback it also covers.
fn wake_address(endpoint: SocketAddr) -> SocketAddr {
    let ip = match endpoint.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, endpoint.port())
}

impl Inner {
    /// Live sessions, with dead ones retired before any count is read.
    fn live(&self) -> usize {
        let mut sessions = lock(&self.sessions);
        self.replay.promote(sessions.as_slice());
        sessions.retain(|session| !session.is_closed());
        sessions.len()
    }

    /// Spread flows over the pool round-robin, so one tunnel's window is not a global cap.
    fn pick(&self) -> Option<Arc<Session>> {
        let mut sessions = lock(&self.sessions);
        self.replay.promote(sessions.as_slice());
        sessions.retain(|session| !session.is_closed());
        if sessions.is_empty() {
            return None;
        }
        let at = self.next_session.fetch_add(1, Ordering::Relaxed) % sessions.len();
        Some(Arc::clone(&sessions[at]))
    }

    /// The first entry to dial and the head start its affinity buys, read once per batch.
    fn start(&self) -> (usize, Duration) {
        let entries = {
            let mut guard = lock(&self.entries);
            if guard.is_empty() {
                return (0, Duration::ZERO);
            }
            if self.settings.fronted_overrides.is_empty()
                && coin(self.settings.server_entry_reset_probability)
            {
                let entries = Arc::make_mut(&mut *guard);
                shuffle(entries.as_mut_slice());
                lock(&self.moved_to_front).clear();
            }
            Arc::clone(&*guard)
        };
        let affinity = lock(&self.affinity);
        match affinity_index(&entries, affinity.as_ref()) {
            Some(base) => (base, self.settings.affinity_grace),
            None => (0, Duration::ZERO),
        }
    }

    /// Record a live server: it becomes the affinity and, under the cap, the next first entry.
    fn remember(&self, host: &str) {
        let affinity = host
            .rsplit_once(':')
            .and_then(|(name, port)| port.parse().ok().map(|port| (name, port)));
        if let Some((name, port)) = affinity {
            *lock(&self.affinity) = Some((name.to_owned(), port));
        }
        let mut guard = lock(&self.entries);
        let max = self.settings.server_entry_max_move_to_front;
        if max == 0 {
            return;
        }
        let mut moved = lock(&self.moved_to_front);
        if max > 0 && i64::try_from(moved.len()).unwrap_or(i64::MAX) >= max {
            return;
        }
        if let Some((name, port)) = affinity {
            if move_to_front(Arc::make_mut(&mut *guard), name, port) {
                moved.insert(host.to_owned());
            }
        }
    }

    /// Dial and add one tunnel; the pool path passes no guard and the single-dial
    /// paths hand over the `connecting` guard so the wait below never holds it.
    #[allow(clippy::too_many_lines)]
    fn connect_locked(
        &self,
        mut start: usize,
        affinity_lead: Duration,
        mut connecting: Option<std::sync::MutexGuard<'_, ()>>,
    ) -> Result<Arc<Session>, String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("psiphon: the lane is stopping".to_owned());
        }
        {
            let sessions = lock(&self.sessions);
            self.replay.promote(sessions.as_slice());
        }
        let entries = Arc::clone(&lock(&self.entries));
        if entries.is_empty() {
            return Err("psiphon: the server list holds no SSH entries".to_owned());
        }
        let entries = if self.replay.wants_move_to_front() {
            let mut reordered = (*entries).clone();
            self.replay.move_to_front(&mut reordered);
            let affinity = lock(&self.affinity);
            if let (Some(old), Some(new)) = (
                affinity_index(&entries, affinity.as_ref()),
                affinity_index(&reordered, affinity.as_ref()),
            ) {
                let count = reordered.len();
                if count != 0 {
                    let offset = (start + count - old) % count;
                    let preferred = reordered.remove(new);
                    reordered.insert(0, preferred);
                    start = offset % count;
                }
            }
            Arc::new(reordered)
        } else {
            entries
        };
        let deadline = Instant::now() + self.settings.ready;
        let limit = entries.len().min(DIAL_ATTEMPTS);
        let conduit_timeout = self.settings.conduit_timeout;
        let dial_timeout = self.settings.dial_timeout();
        let timeout = if self.settings.conduit {
            conduit_timeout
        } else {
            dial_timeout
        };
        let mut last = String::new();
        let mut offset = 0;
        let mut first_batch = true;
        while offset < limit {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let width = self.settings.workers.min(limit - offset);
            if width == 0 {
                break;
            }
            let (batch, taken) = take_dial_batch(
                &entries,
                start,
                offset,
                limit,
                width,
                self.settings.intensive_workers,
                self.settings.conduit,
            );
            offset += taken;
            if taken == 0 {
                break;
            }
            let batch: Vec<Server> = batch
                .into_iter()
                .filter(|server| !self.settings.restricted(server, self.settings.conduit))
                .collect();
            if batch.is_empty() {
                continue;
            }
            let lead = if std::mem::take(&mut first_batch) {
                affinity_lead
            } else {
                Duration::ZERO
            };
            let lead = if lead.saturating_add(timeout) <= remaining {
                lead
            } else {
                Duration::ZERO
            };
            let last_delay = lead.saturating_add(
                self.settings
                    .stagger
                    .saturating_mul(u32::try_from(taken.saturating_sub(1)).unwrap_or(u32::MAX)),
            );
            let stagger = if last_delay.saturating_add(timeout) <= remaining {
                self.settings.stagger
            } else {
                Duration::ZERO
            };
            let budget = if stagger.is_zero() {
                remaining.min(timeout.saturating_add(lead))
            } else {
                last_delay.saturating_add(timeout).min(remaining)
            };
            let session_id = self.session_id.clone();
            let authorizations = self.settings.authorizations.clone();
            let sponsor = self.settings.sponsor.clone();
            let propagation = self.settings.propagation.clone();
            let platform = self.settings.platform.clone();
            let client_version = self.settings.client_version.clone();
            let api_encoding = self.settings.api_encoding;
            let compress_tactics = self.settings.compress_tactics;
            let egress_region = self.settings.region.clone();
            let device_region = self.settings.device_region.clone();
            let device_location = self.settings.device_location.clone();
            let client_features = self.settings.client_features.clone();
            let split_tunnel = self.settings.split_tunnel_own_region;
            let split_tunnel_regions = self.settings.split_tunnel_regions.clone();
            let proxy = self.settings.proxy.clone();
            let dns = self.settings.dns.clone();
            let keepalive = self.settings.keepalive;
            let limit_meek_buffers = self.settings.limit_meek_buffers;
            let tls_shape = self.settings.tls_shape.clone();
            let burst = self.settings.burst;
            let disable_api = self.settings.disable_api;
            let ssh_algorithms = self.settings.ssh_algorithms.clone();
            let config_state = self.config_state;
            let replay = Arc::clone(&self.replay);
            let conduit =
                if self.settings.conduit && batch.iter().any(|server| server.inproxy.is_some()) {
                    match self.conduit() {
                        Ok(conduit) => Some(conduit),
                        Err(error) => {
                            eprintln!("psiphon: conduit unavailable: {error}");
                            None
                        }
                    }
                } else {
                    None
                };
            let requests =
                Arc::clone(&self.requests) as Arc<dyn crate::psiphon_ssh::ServerRequests>;
            let attempt = move |server: &Server| {
                let lease = replay.begin(server, config_state);
                let _scope = crate::psiphon_ssh::dial_seed_scope(lease.seed());
                let selected = lease.server();
                let timeout = if conduit.is_some() && selected.inproxy.is_some() {
                    conduit_timeout
                } else {
                    dial_timeout
                };
                let identity = Identity {
                    session_id: &session_id,
                    authorizations: &authorizations,
                    sponsor: &sponsor,
                    propagation: &propagation,
                    platform: &platform,
                    version: &client_version,
                    egress_region: egress_region.as_deref(),
                    device_region: device_region.as_deref(),
                    device_location: device_location.as_deref(),
                    client_features: &client_features,
                    split_tunnel,
                    split_tunnel_regions: &split_tunnel_regions,
                    api_encoding,
                    compress_tactics,
                    disable_api,
                    ssh_algorithms: ssh_algorithms.as_ref(),
                };
                match Session::connect(
                    selected,
                    &identity,
                    timeout,
                    proxy.as_ref(),
                    &dns,
                    conduit.as_deref(),
                    keepalive,
                    &tls_shape,
                    limit_meek_buffers,
                    Some(Arc::clone(&requests)),
                    burst,
                ) {
                    Ok(session) => Ok((session, lease)),
                    Err(why) => {
                        lease.failed();
                        Err(why)
                    }
                }
            };
            match race(batch, attempt, budget, stagger, lead) {
                Ok((session, lease)) => {
                    drop(connecting.take());
                    if self.stopping.load(Ordering::Acquire) {
                        session.close();
                        return Err("psiphon: the lane is stopping".to_owned());
                    }
                    let protocol = session.protocol();
                    let hold_off =
                        self.settings
                            .holdoff
                            .duration(protocol)
                            .max(self.settings.holdoff_for(
                                protocol,
                                session.provider_id(),
                                session.region(),
                                session.fronting_provider_id(),
                            ));
                    if !hold_off.is_zero() {
                        eprintln!(
                            "psiphon: holding off {protocol} for {} ms",
                            hold_off.as_millis()
                        );
                        let deadline = Instant::now() + hold_off;
                        loop {
                            if self.stopping.load(Ordering::Acquire) {
                                session.close();
                                return Err("psiphon: the lane is stopping".to_owned());
                            }
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if remaining.is_zero() {
                                break;
                            }
                            thread::sleep(remaining.min(Duration::from_millis(50)));
                        }
                    }
                    self.apply_handshake(&session);
                    let established = !lock(&self.sessions).is_empty();
                    if let Some(probe) = self.settings.liveness.spec(protocol, established) {
                        if let Err(why) = session.liveness_test(
                            probe.min_upstream,
                            probe.max_upstream,
                            probe.min_downstream,
                            probe.max_downstream,
                            self.settings.dial_timeout(),
                        ) {
                            session.close();
                            lease.failed();
                            last = format!("psiphon: liveness test on {protocol}: {why}");
                            continue;
                        }
                    }
                    lease.succeeded(session.id());
                    let session = Arc::new(session);
                    eprintln!(
                        "psiphon: tunnel up via {} {}",
                        session.server(),
                        session.protocol()
                    );
                    let mut sessions = lock(&self.sessions);
                    sessions.retain(|session| !session.is_closed());
                    if sessions.len() >= self.settings.pool {
                        let at = self.next_session.fetch_add(1, Ordering::Relaxed) % sessions.len();
                        let existing = Arc::clone(&sessions[at]);
                        drop(sessions);
                        self.replay.promote(std::slice::from_ref(&session));
                        session.close();
                        return Ok(existing);
                    }
                    sessions.push(Arc::clone(&session));
                    return Ok(session);
                }
                Err(why) => last = why,
            }
        }
        Err(format!("psiphon: no server accepted the tunnel: {last}"))
    }

    /// Apply the server's handshake reply: a steering IP for the fronting provider and new entries.
    fn apply_handshake(&self, session: &Session) {
        let state = session.handshake();
        if let Some(provider) = session.fronting_provider_id() {
            if let Some(address) = state
                .steering_ip
                .as_deref()
                .and_then(|text| text.parse::<IpAddr>().ok())
                .filter(|address| !is_bogon(*address))
            {
                self.settings.dns.remember_steering(provider, address);
            }
        }
        if state.encoded_server_list.is_empty() {
            return;
        }
        let mut entries = lock(&self.entries);
        let list = Arc::make_mut(&mut *entries);
        for encoded in &state.encoded_server_list {
            let Some(server) = decode_entry_with(encoded, true, &self.settings.conduit_protocols)
            else {
                continue;
            };
            if !entry_allowed(&server, &self.settings.protocols, self.settings.fronted) {
                continue;
            }
            if !list
                .iter()
                .any(|known| known.host == server.host && known.port == server.port)
            {
                list.push(server);
            }
        }
    }

    /// Build the broker conduit once from the tactics payload and selected compartments.
    fn conduit(&self) -> Result<Arc<crate::psiphon_webrtc::Conduit>, String> {
        if let Some(conduit) = lock(&self.conduit).clone() {
            return Ok(conduit);
        }
        if self.settings.proxy.is_some() {
            return Err(
                "psiphon conduit: UpstreamProxyURL cannot carry the required direct UDP".to_owned(),
            );
        }
        let geoip = if self.settings.reject_countries.is_empty() {
            None
        } else if let Some(path) = self.settings.geoip_path.as_deref() {
            match crate::psiphon_geoip::GeoIp::open(path, &self.settings.reject_countries) {
                Ok(geoip) => geoip,
                Err(error) => {
                    eprintln!("{error}; skipping proxy-country filtering");
                    None
                }
            }
        } else {
            None
        };
        let servers = load_tactics_entries(&self.settings)?;
        let session_id = hex(&random::<16>());
        let tactics = fetch_tactics_from(&self.settings, &servers, &session_id)?;
        let broker = tactics
            .brokers
            .first()
            .ok_or_else(|| "psiphon conduit: tactics names no broker".to_owned())?;
        let fronts = broker_fronts(broker);
        let common = decode_compartments(&tactics.compartments)?;
        let personal = decode_compartment(&self.settings.compartment)?;
        let (common, personal) = match self.settings.conduit_mode {
            ConduitMode::Public => (common, Vec::new()),
            ConduitMode::Shirokhorshid => (Vec::new(), vec![personal]),
            ConduitMode::Auto => (common, vec![personal]),
        };
        if common.is_empty() && personal.is_empty() {
            return Err("psiphon conduit: no compartments".to_owned());
        }
        let conduit = Arc::new(crate::psiphon_webrtc::Conduit::new(
            crate::psiphon_broker::Broker {
                public_key: broker.public_key.clone(),
                root_secret: broker.root_secret.clone(),
            },
            fronts,
            common,
            personal,
            tactics.stun_servers.clone(),
            self.settings.conduit_protocols.clone(),
            self.settings.conduit_timeout,
            self.settings.meek_headers.clone(),
            self.settings.dns.clone(),
            &self.settings.reject_cidrs,
            geoip,
        ));
        *lock(&self.conduit) = Some(Arc::clone(&conduit));
        Ok(conduit)
    }

    fn udp(&self) -> Result<Arc<UdpGateway>, String> {
        if let Some(gateway) = lock(&self.udpgw).as_ref() {
            if !gateway.is_closed() {
                return Ok(Arc::clone(gateway));
            }
        }
        let channel = self.dial_tunnel(UDPGW_HOST, UDPGW_PORT, self.split_tunnel_enabled())?;
        let mut slot = lock(&self.udpgw);
        if let Some(gateway) = slot.as_ref() {
            if !gateway.is_closed() {
                channel.close();
                return Ok(Arc::clone(gateway));
            }
        }
        let gateway = UdpGateway::start(channel);
        *slot = Some(Arc::clone(&gateway));
        Ok(gateway)
    }

    fn dial(&self, host: &str, port: u16) -> Result<Flow, String> {
        if let Some(light) = self.light.as_ref() {
            if light.routes(host, port) && !self.recent_tunnel(light.inactive()) {
                match light.dial(host, port, self.settings.proxy.as_ref()) {
                    Ok(stream) => {
                        if std::env::var_os("AETHER_PSIPHON_TRACE_FLOWS").is_some() {
                            eprintln!("psiphon: light proxy carried {host}:{port}");
                        }
                        return Ok(Flow::Direct(stream));
                    }
                    Err(error) => eprintln!("psiphon: {error}"),
                }
            }
        }
        if !self.split_tunnel_enabled() {
            return self.dial_tunnel(host, port, false).map(Flow::Tunnel);
        }
        let key = format!("{host}:{port}");
        if self.split_is_untunneled(&key) {
            return self.direct(host, port).map(Flow::Direct);
        }
        self.dial_split(host, port, &key)
    }

    /// A server-tunneled dial: UDP gateways and plain lanes never take the direct path.
    fn dial_tunnel(&self, host: &str, port: u16, always_tunneled: bool) -> Result<Channel, String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("psiphon: the lane is stopping".to_owned());
        }
        for _ in 0..2 {
            let session = self.ensure()?;
            let opened = if always_tunneled {
                session.open_tunneled(host, port)
            } else {
                session.open(host, port)
            };
            match opened {
                Ok(channel) => return Ok(channel),
                // A refused target says nothing about the tunnel; a dead one is replaced and retried.
                Err(why) if !session.is_closed() => return Err(why),
                Err(_) => self.retire(&session),
            }
        }
        Err(format!("psiphon: {host}:{port} was not reachable"))
    }

    /// Ask the server to classify a target, then tunnel it or dial it direct.
    fn dial_split(&self, host: &str, port: u16, key: &str) -> Result<Flow, String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("psiphon: the lane is stopping".to_owned());
        }
        for _ in 0..2 {
            let session = self.ensure()?;
            match session.open_split(host, port) {
                Ok(Some(channel)) => {
                    self.split_forget(key);
                    return Ok(Flow::Tunnel(channel));
                }
                Ok(None) => {
                    self.split_remember(key);
                    return self.direct(host, port).map(Flow::Direct);
                }
                // A refused target says nothing about the tunnel; a dead one is replaced and retried.
                Err(why) if !session.is_closed() => return Err(why),
                Err(_) => self.retire(&session),
            }
        }
        Err(format!("psiphon: {host}:{port} was not reachable"))
    }

    fn retire(&self, session: &Arc<Session>) {
        self.replay.promote(std::slice::from_ref(session));
        session.close();
        lock(&self.sessions).retain(|current| !Arc::ptr_eq(current, session));
    }

    fn split_tunnel_enabled(&self) -> bool {
        self.settings.split_tunnel_own_region || !self.settings.split_tunnel_regions.is_empty()
    }

    /// Whether any tunnel read within `threshold`, which keeps the light fallback off.
    fn recent_tunnel(&self, threshold: Duration) -> bool {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|session| !session.is_closed());
        sessions.iter().any(|session| session.idle() < threshold)
    }

    fn split_is_untunneled(&self, key: &str) -> bool {
        let mut cache = lock(&self.split_untunneled);
        match cache.get(key).copied() {
            Some(at) if at.elapsed() < SPLIT_TUNNEL_CLASSIFICATION_TTL => true,
            Some(_) => {
                cache.remove(key);
                false
            }
            None => false,
        }
    }

    fn split_remember(&self, key: &str) {
        let mut cache = lock(&self.split_untunneled);
        if cache.len() >= SPLIT_TUNNEL_CLASSIFICATION_MAX && !cache.contains_key(key) {
            cache.retain(|_, at| at.elapsed() < SPLIT_TUNNEL_CLASSIFICATION_TTL);
            if cache.len() >= SPLIT_TUNNEL_CLASSIFICATION_MAX {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(key, _)| key.clone())
                {
                    cache.remove(&oldest);
                }
            }
        }
        cache.insert(key.to_owned(), Instant::now());
    }

    fn split_forget(&self, key: &str) {
        lock(&self.split_untunneled).remove(key);
    }

    /// The direct half of split tunnel: the reference's untunneled dial, proxy included.
    fn direct(&self, host: &str, port: u16) -> Result<TcpStream, String> {
        if let Some(proxy) = self.settings.proxy.as_ref() {
            let stream = proxy.connect_host(host, port, self.settings.dial_timeout())?;
            let _ = stream.set_read_timeout(None);
            let _ = stream.set_write_timeout(None);
            return Ok(stream);
        }
        let timeout = self.settings.dial_timeout();
        let addresses = crate::psiphon_dns::resolve_with(&self.settings.dns, host, port)
            .map_err(|error| format!("psiphon: split tunnel could not resolve {host}: {error}"))?;
        let mut last = format!("no address for {host}");
        for address in addresses {
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(stream);
                }
                Err(error) => last = format!("{address}: {error}"),
            }
        }
        Err(format!(
            "psiphon: split tunnel could not dial {host}:{port}: {last}"
        ))
    }

    /// A live tunnel, dialing at most one beside any other caller.
    fn ensure(&self) -> Result<Arc<Session>, String> {
        if let Some(session) = self.pick() {
            return Ok(session);
        }
        let connecting = lock(&self.connecting);
        if let Some(session) = self.pick() {
            return Ok(session);
        }
        self.replay.start_pass();
        let (start, lead) = self.start();
        let session = self.connect_locked(start, lead, Some(connecting))?;
        self.remember(session.server());
        Ok(session)
    }

    /// Fill the configured pool a batch of tunnels at a time, so a wide pool costs
    /// one handshake window instead of one per tunnel.
    fn fill(self: &Arc<Self>) -> Result<(), String> {
        let fill_workers = if self.settings.limit_cpu { 1 } else { 8 };
        self.replay.start_pass();
        let mut first_round = true;
        loop {
            if self.stopping.load(Ordering::Acquire) {
                return Err("psiphon: the lane is stopping".to_owned());
            }
            let missing = self.settings.pool.saturating_sub(self.live());
            if missing == 0 {
                return Ok(());
            }
            if !std::mem::take(&mut first_round) {
                self.replay.next_round();
            }
            if missing == 1 {
                let connecting = lock(&self.connecting);
                if self.live() >= self.settings.pool {
                    return Ok(());
                }
                let (start, lead) = self.start();
                let session = self.connect_locked(start, lead, Some(connecting))?;
                self.remember(session.server());
                continue;
            }
            let width = missing.min(fill_workers);
            let (base, lead) = self.start();
            let count = lock(&self.entries).len();
            if count == 0 {
                return Err("psiphon: the server list holds no SSH entries".to_owned());
            }
            let mut handles = Vec::with_capacity(width);
            for spread in 0..width {
                let lane = Arc::clone(self);
                let start = base.wrapping_add(spread) % count;
                let worker_lead = if spread == 0 { lead } else { Duration::ZERO };
                handles.push(
                    thread::Builder::new()
                        .name("psiphon-pool".to_owned())
                        .spawn(move || lane.connect_locked(start, worker_lead, None))
                        .map_err(|error| format!("psiphon: pool thread: {error}"))?,
                );
            }
            let mut last = String::new();
            let mut succeeded = 0usize;
            let mut reached = None;
            for handle in handles {
                match handle.join() {
                    Ok(Ok(session)) => {
                        succeeded += 1;
                        reached = Some(session.server().to_owned());
                    }
                    Ok(Err(why)) => last = why,
                    Err(_) => "psiphon: a pool dial panicked".clone_into(&mut last),
                }
            }
            if let Some(host) = reached {
                self.remember(&host);
            }
            if succeeded == 0 {
                return Err(last);
            }
        }
    }

    /// Fetch and import the seeded obfuscated server lists, at most once per interval.
    fn refresh_osl(&self) {
        if self.settings.osl_roots.is_empty()
            || self.settings.remote_fetch_disabled
            || self.settings.target.is_some()
        {
            return;
        }
        let forced = self.osl_seeded.swap(false, Ordering::AcqRel);
        let failed = lock(&self.last_osl_failure);
        let retry = self.settings.remote_list_retry;
        if !forced && failed.is_some_and(|at| retry > Duration::ZERO && at.elapsed() < retry) {
            return;
        }
        drop(failed);
        let mut last = lock(&self.last_osl);
        if !forced && last.is_some_and(|at| at.elapsed() < OSL_REFRESH) {
            return;
        }
        *last = Some(Instant::now());
        drop(last);
        match fetch_osl_entries(&self.settings, &self.sloks) {
            Ok(entries) => {
                *lock(&self.last_osl_failure) = None;
                let added = self.add_entries(entries);
                if added > 0 {
                    eprintln!("psiphon: imported {added} obfuscated server entries");
                }
            }
            Err(why) => {
                *lock(&self.last_osl_failure) = Some(Instant::now());
                eprintln!("psiphon: {why}");
            }
        }
    }

    /// Append entries the lane does not already dial, keeping the snapshot stable.
    fn add_entries(&self, entries: Vec<Server>) -> usize {
        let mut current = lock(&self.entries);
        let added = new_entries(&current, entries);
        let count = added.len();
        if count > 0 {
            let mut list = (**current).clone();
            list.extend(added);
            *current = Arc::new(list);
        }
        count
    }
}

/// Keep the pool warm beside the edge: a refused dial is a retry, not an exit.
fn warm_tunnel(lane: &Weak<Inner>) {
    let mut logged: Option<Instant> = None;
    loop {
        let Some(inner) = lane.upgrade() else {
            return;
        };
        if inner.stopping.load(Ordering::Acquire) {
            return;
        }
        let pause = inner.settings.pause;
        let outcome = inner.fill();
        if outcome.is_ok() {
            inner.refresh_osl();
        }
        drop(inner);
        match outcome {
            Ok(()) => {
                thread::sleep(pause);
                continue;
            }
            Err(why) => {
                let now = Instant::now();
                // One line per cycle at most, so an instantly refused list cannot flood the log.
                if logged.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(10)) {
                    eprintln!("psiphon: {why}; retrying");
                    logged = Some(now);
                }
            }
        }
        thread::sleep(pause);
    }
}

#[allow(clippy::needless_pass_by_value)]
fn accept_loop(listener: TcpListener, inner: Weak<Inner>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { break };
        let Some(inner) = inner.upgrade() else { break };
        if inner.stopping.load(Ordering::Acquire) {
            break;
        }
        let _ = thread::Builder::new()
            .name("psiphon-flow".to_owned())
            .stack_size(FLOW_STACK)
            .spawn(move || serve(stream, &inner));
    }
}

fn serve(mut client: TcpStream, inner: &Arc<Inner>) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));
    let Some((version, ask)) = read_request(&mut client, inner) else {
        return;
    };
    match ask {
        Ask::Connect(host, port) => match inner.dial(&host, port) {
            Ok(flow) => {
                trace_flow(&flow);
                if !ask_reply(&mut client, version, Ok(())) {
                    flow.close();
                    return;
                }
                let _ = client.set_read_timeout(None);
                let _ = client.set_write_timeout(None);
                let rate = inner
                    .settings
                    .rate
                    .as_ref()
                    .map(|rate| Arc::new(Mutex::new(rate.clone())));
                relay_flow(client, flow, inner.settings.relay_buffer, rate.as_ref());
            }
            Err(why) => {
                eprintln!("psiphon: {why}");
                let _ = ask_reply(&mut client, version, Err(5));
            }
        },
        Ask::Udp => serve_udp(client, inner),
    }
}

enum Ask {
    Connect(String, u16),
    Udp,
}

/// One accepted flow: inside the SSH tunnel or directly out when split tunnel says so.
enum Flow {
    Tunnel(Channel),
    Direct(TcpStream),
}

impl Flow {
    fn close(&self) {
        match self {
            Self::Tunnel(channel) => channel.close(),
            Self::Direct(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }
}

impl Write for Flow {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tunnel(channel) => channel.write(buffer),
            Self::Direct(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tunnel(channel) => channel.flush(),
            Self::Direct(stream) => stream.flush(),
        }
    }
}

fn read_request(client: &mut TcpStream, inner: &Inner) -> Option<(Version, Ask)> {
    let mut first = [0u8; 1];
    client.read_exact(&mut first).ok()?;
    match first[0] {
        // SOCKS4 carries no credential exchange, so a credentialed edge refuses it instead of serving it open.
        4 if inner.settings.proxy_user.is_none() => read_v4(client).map(|ask| (Version::V4, ask)),
        4 => {
            let _ = client.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]);
            None
        }
        5 => read_v5(client, inner).map(|ask| (Version::V5, ask)),
        _ => None,
    }
}

fn read_v4(client: &mut TcpStream) -> Option<Ask> {
    let mut head = [0u8; 7];
    client.read_exact(&mut head).ok()?;
    if head[0] != 1 {
        return None;
    }
    let port = u16::from_be_bytes([head[1], head[2]]);
    let address = Ipv4Addr::new(head[3], head[4], head[5], head[6]);
    let mut user = Vec::new();
    read_nul(client, &mut user)?;
    let host = if address.octets()[..3] == [0, 0, 0] && address.octets()[3] != 0 {
        let mut name = Vec::new();
        read_nul(client, &mut name)?;
        String::from_utf8(name).ok()?
    } else {
        address.to_string()
    };
    Some(Ask::Connect(host, port))
}

fn read_v5(client: &mut TcpStream, inner: &Inner) -> Option<Ask> {
    let mut count = [0u8; 1];
    client.read_exact(&mut count).ok()?;
    let mut methods = vec![0u8; usize::from(count[0])];
    client.read_exact(&mut methods).ok()?;
    let auth = inner.settings.proxy_user.is_some();
    if auth {
        if !methods.contains(&2) {
            client.write_all(&[5, 0xff]).ok()?;
            return None;
        }
        client.write_all(&[5, 2]).ok()?;
        read_auth(client, inner)?;
    } else {
        if !methods.contains(&0) {
            client.write_all(&[5, 0xff]).ok()?;
            return None;
        }
        client.write_all(&[5, 0]).ok()?;
    }

    let mut request = [0u8; 4];
    client.read_exact(&mut request).ok()?;
    if request[0] != 5 {
        return None;
    }
    let host = match request[3] {
        1 => {
            let mut address = [0u8; 4];
            client.read_exact(&mut address).ok()?;
            Ipv4Addr::from(address).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            client.read_exact(&mut name).ok()?;
            String::from_utf8(name).ok()?
        }
        4 => {
            let mut address = [0u8; 16];
            client.read_exact(&mut address).ok()?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).ok()?;
    let port = u16::from_be_bytes(port);
    match request[1] {
        1 => Some(Ask::Connect(host, port)),
        3 => Some(Ask::Udp),
        _ => None,
    }
}

fn read_auth(client: &mut TcpStream, inner: &Inner) -> Option<()> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).ok()?;
    if head[0] != 1 {
        return None;
    }
    let mut user = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut user).ok()?;
    let mut plen = [0u8; 1];
    client.read_exact(&mut plen).ok()?;
    let mut pass = vec![0u8; usize::from(plen[0])];
    client.read_exact(&mut pass).ok()?;
    let expected_user = inner
        .settings
        .proxy_user
        .as_deref()
        .unwrap_or("")
        .as_bytes();
    let expected_pass = inner
        .settings
        .proxy_pass
        .as_deref()
        .unwrap_or("")
        .as_bytes();
    let user_ok = constant_time_eq(&user, expected_user);
    let pass_ok = constant_time_eq(&pass, expected_pass);
    if user_ok && pass_ok {
        client.write_all(&[1, 0]).ok()?;
        Some(())
    } else {
        client.write_all(&[1, 1]).ok()?;
        None
    }
}

fn read_nul(client: &mut TcpStream, out: &mut Vec<u8>) -> Option<()> {
    loop {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).ok()?;
        if byte[0] == 0 {
            return Some(());
        }
        if out.len() >= 255 {
            return None;
        }
        out.push(byte[0]);
    }
}

fn ask_reply(client: &mut TcpStream, version: Version, result: Result<(), u8>) -> bool {
    match version {
        Version::V4 => {
            let reply = if result.is_ok() {
                [0, 90, 0, 0, 0, 0, 0, 0]
            } else {
                [0, 91, 0, 0, 0, 0, 0, 0]
            };
            client.write_all(&reply).is_ok()
        }
        Version::V5 => {
            let reply = match result {
                Ok(()) => [5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                Err(code) => [5, code, 0, 1, 0, 0, 0, 0, 0, 0],
            };
            client.write_all(&reply).is_ok()
        }
    }
}

/// Relay one accepted flow through the tunnel, then close it when the tunnel ends.
fn relay_flow(
    client: TcpStream,
    flow: Flow,
    buffer: usize,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
) {
    match flow {
        Flow::Tunnel(channel) => relay(client, channel, buffer, rate),
        Flow::Direct(remote) => relay_direct(client, remote, buffer, rate),
    }
}

/// Account bytes against the tunnel's rate limits; false means `CloseAfterExhausted` fired.
fn throttle(
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
    is_read: bool,
    bytes: usize,
) -> bool {
    let Some(rate) = rate else {
        return true;
    };
    let account = {
        let Ok(mut rate) = rate.lock() else {
            return true;
        };
        if is_read {
            rate.read(bytes)
        } else {
            rate.write(bytes)
        }
    };
    crate::psiphon_rate::settle(account)
}

/// Relay a flow directly when split tunneling selects it.
#[allow(clippy::needless_pass_by_value)]
fn relay_direct(
    mut client: TcpStream,
    mut remote: TcpStream,
    buffer: usize,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
) {
    let Ok(mut client_read) = client.try_clone() else {
        return;
    };
    let Ok(mut remote_write) = remote.try_clone() else {
        return;
    };
    let forward_rate = rate.cloned();
    let forward = thread::Builder::new()
        .name("psiphon-direct-forward".to_owned())
        .stack_size(FLOW_STACK)
        .spawn(move || {
            let done = pump_copy(
                &mut client_read,
                &mut remote_write,
                buffer,
                forward_rate.as_ref(),
                false,
            );
            let _ = remote_write.shutdown(if done {
                Shutdown::Write
            } else {
                Shutdown::Both
            });
        })
        .ok();
    let done = pump_copy(&mut remote, &mut client, buffer, rate, true);
    let _ = client.shutdown(if done {
        Shutdown::Write
    } else {
        Shutdown::Both
    });
    if let Some(forward) = forward {
        let _ = forward.join();
    }
    let _ = remote.shutdown(Shutdown::Both);
}

/// Copy one direction until EOF or a terminal error.
fn pump_copy(
    source: &mut impl Read,
    sink: &mut impl Write,
    buffer: usize,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
    is_read: bool,
) -> bool {
    let mut bytes = vec![0u8; buffer];
    loop {
        match source.read(&mut bytes) {
            Ok(0) => return true,
            Ok(read) => {
                if !throttle(rate, is_read, read) {
                    return false;
                }
                if sink.write_all(&bytes[..read]).is_err() {
                    return true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return true,
        }
    }
}

/// Relay both directions of an established stream until either side closes.
#[allow(clippy::needless_pass_by_value)]
fn relay(
    mut client: TcpStream,
    channel: Channel,
    buffer: usize,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
) {
    let Ok(mut client_read) = client.try_clone() else {
        channel.close();
        return;
    };
    let mut channel_write = channel.clone();
    let forward_rate = rate.cloned();
    let forward = thread::Builder::new()
        .name("psiphon-flow-forward".to_owned())
        .stack_size(FLOW_STACK)
        .spawn(move || {
            let done = pump_out(
                &mut client_read,
                &mut channel_write,
                buffer,
                forward_rate.as_ref(),
            );
            if done {
                channel_write.shutdown();
            } else {
                channel_write.close();
            }
        })
        .ok();
    let mut channel_read = channel.clone();
    let done = pump_channel(&mut channel_read, &mut client, rate);
    if !done {
        channel_read.close();
    }
    let _ = client.shutdown(if done {
        Shutdown::Write
    } else {
        Shutdown::Both
    });
    if let Some(forward) = forward {
        let _ = forward.join();
    }
    channel.close();
}

fn trace_flow(flow: &Flow) {
    if std::env::var_os("AETHER_PSIPHON_TRACE_FLOWS").is_some() {
        match flow {
            Flow::Tunnel(channel) => eprintln!(
                "psiphon: flow via session {} {}",
                channel.session_id(),
                channel.server()
            ),
            Flow::Direct(_) => eprintln!("psiphon: flow split-tunneled directly"),
        }
    }
}

/// The download half writes each received packet straight from the SSH buffer,
/// coalescing the packets already queued into one vectored call.
fn pump_channel(
    channel: &mut Channel,
    sink: &mut impl Write,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
) -> bool {
    let mut batch: Vec<ChannelChunk> = Vec::with_capacity(RELAY_BATCH);
    loop {
        batch.clear();
        match channel.next_batch(&mut batch, RELAY_BATCH) {
            Ok(true) => {
                let bytes: usize = batch.iter().map(|chunk| chunk.data().len()).sum();
                if !throttle(rate, true, bytes) {
                    channel.recycle_chunks(batch.drain(..));
                    return false;
                }
                if !flush_chunks(channel, sink, &mut batch) {
                    return true;
                }
            }
            _ => return true,
        }
    }
}

fn flush_chunks(channel: &Channel, sink: &mut impl Write, batch: &mut Vec<ChannelChunk>) -> bool {
    let mut slices = [IoSlice::new(&[]); RELAY_BATCH];
    for (slot, chunk) in slices.iter_mut().zip(batch.iter()) {
        *slot = IoSlice::new(chunk.data());
    }
    let wrote = write_all_vectored(sink, &mut slices[..batch.len()]).is_ok();
    channel.recycle_chunks(batch.drain(..));
    wrote
}

fn write_all_vectored(sink: &mut impl Write, mut slices: &mut [IoSlice<'_>]) -> io::Result<()> {
    while !slices.is_empty() {
        let written = match sink.write_vectored(slices) {
            Ok(written) => written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "psiphon relay write wrote zero bytes",
            ));
        }
        IoSlice::advance_slices(&mut slices, written);
    }
    Ok(())
}

/// The client-to-tunnel side encrypts the read buffer in place, so the payload is not copied into a packet.
fn pump_out(
    source: &mut impl Read,
    sink: &mut Channel,
    buffer: usize,
    rate: Option<&Arc<Mutex<crate::psiphon_rate::Rate>>>,
) -> bool {
    let mut buffer = vec![0u8; buffer];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => return true,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return true,
        };
        if !throttle(rate, false, read) {
            return false;
        }
        // A window or a smaller remote packet can take less than the read, so the remainder leaves next packet.
        let mut at = 0;
        while at < read {
            match sink.write_in_place(&mut buffer[at..read]) {
                Ok(0) => return true,
                Ok(written) => at += written,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return true,
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn accept_http(listener: TcpListener, inner: Weak<Inner>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { break };
        let Some(inner) = inner.upgrade() else { break };
        if inner.stopping.load(Ordering::Acquire) {
            break;
        }
        let _ = thread::Builder::new()
            .name("psiphon-http-flow".to_owned())
            .stack_size(FLOW_STACK)
            .spawn(move || serve_http(stream, &inner));
    }
}

/// `LocalHttpProxyPort` serves CONNECT only: a plain-response request has no tunnel to carry it.
fn serve_http(mut client: TcpStream, inner: &Arc<Inner>) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));
    let mut head = [0u8; MAX_REQUEST];
    let mut filled = 0;
    let mut scanned = 0;
    let end = loop {
        if filled == head.len() {
            break None;
        }
        match client.read(&mut head[filled..]) {
            Ok(0) => return,
            Ok(read) => {
                filled += read;
                if let Some(at) = ferrox_core::foxy::head_end_grown(&head[..filled], &mut scanned) {
                    break Some(at);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    };
    let Some(end) = end else {
        let _ = client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n");
        return;
    };
    let text = String::from_utf8_lossy(&head[..end]);
    // Bytes a client pipelined behind its CONNECT headers are the stream's first bytes.
    let early = &head[end + 4..filled];
    let mut lines = text.split("\r\n");
    let mut request = lines.next().unwrap_or("").split_whitespace();
    let method = request.next().unwrap_or("");
    let authority = request.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = client.write_all(
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    // A shared edge names a credential, and the HTTP front answers it the way the SOCKS front does.
    if inner.settings.proxy_user.as_deref().is_some_and(|user| {
        let pass = inner.settings.proxy_pass.as_deref().unwrap_or("");
        !http_authorized(&text, user, pass)
    }) {
        let _ = client.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"psiphon\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|bare| bare.strip_suffix(']'))
        .unwrap_or(host);
    let Ok(port) = port.parse::<u16>() else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };
    match inner.dial(host, port) {
        Ok(mut flow) => {
            trace_flow(&flow);
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .is_err()
                || (!early.is_empty() && flow.write_all(early).is_err())
            {
                flow.close();
                return;
            }
            let _ = client.set_read_timeout(None);
            let _ = client.set_write_timeout(None);
            let rate = inner
                .settings
                .rate
                .as_ref()
                .map(|rate| Arc::new(Mutex::new(rate.clone())));
            relay_flow(client, flow, inner.settings.relay_buffer, rate.as_ref());
        }
        Err(why) => {
            eprintln!("psiphon: {why}");
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        }
    }
}

/// No early exit, so the compare's time follows the length and not the first differing byte.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

/// A `Proxy-Authorization: Basic` header carries the same `user:pass` the SOCKS front takes.
fn http_authorized(head: &str, user: &str, pass: &str) -> bool {
    let mut expected = Vec::with_capacity(user.len() + pass.len() + 1);
    expected.extend_from_slice(user.as_bytes());
    expected.push(b':');
    expected.extend_from_slice(pass.as_bytes());
    let expected = ferrox_core::b64::encode(&expected);
    head.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
                return false;
            }
            let Some((scheme, token)) = value.trim().split_once(' ') else {
                return false;
            };
            scheme.eq_ignore_ascii_case("basic")
                && constant_time_eq(token.trim().as_bytes(), expected.as_bytes())
        })
    })
}

impl Settings {
    #[allow(clippy::too_many_lines)]
    /// Read the lane settings, keeping the reference defaults for absent fields.
    fn from_json(settings: Option<&Json>) -> Result<Self, String> {
        let merged = merge_additional_parameters(settings)?;
        let settings = merged.as_ref().or(settings);
        let raw = settings.cloned();
        let listen = listen_address(settings)?;
        let region = match text(settings, "region")
            .or_else(|| text(settings, "egressRegion"))
            .or_else(|| text(settings, "EgressRegion"))
            .or_else(|| env("AETHER_PSIPHON_REGION"))
        {
            Some(code) => Some(ferrox_core::psiphon::region(&code).ok_or_else(|| {
                format!("psiphon: region {code:?} is not a two-letter country code")
            })?),
            None => None,
        };
        let dns_servers: Vec<SocketAddr> = string_list(settings, "DNSResolverAlternateServers")
            .iter()
            .filter_map(|server| {
                let parsed = dns_server(server);
                if parsed.is_none() {
                    eprintln!("psiphon: ignoring invalid DNSResolverAlternateServers {server:?}");
                }
                parsed
            })
            .collect();
        let dns = dns_config(settings, &dns_servers);
        if flag(settings, "disableTunnels", "AETHER_PSIPHON_DISABLE_TUNNELS")
            || flag(settings, "DisableTunnels", "AETHER_PSIPHON_DISABLE_TUNNELS")
        {
            return Err(
                "psiphon: disableTunnels opens no tunnel, so this lane would carry nothing"
                    .to_owned(),
            );
        }
        let ready = text(settings, "readySeconds")
            .or_else(|| {
                settings
                    .and_then(|settings| settings.get("readySeconds"))
                    .and_then(Json::as_u32)
                    .map(|value| value.to_string())
            })
            .or_else(|| env("AETHER_PSIPHON_READY_SECS"))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map_or(ferrox_core::psiphon::READY_SECS, |value| value.min(86_400));
        let mut server_lists = json_list(settings, "serverListURLs");
        for key in [
            "remoteServerListURLs",
            "RemoteServerListURLs",
            "RemoteServerListUrl",
            "remoteServerListUrl",
            "serverListUrls",
        ] {
            if server_lists.is_empty() {
                server_lists = json_list(settings, key);
            }
        }
        if server_lists.is_empty() {
            server_lists.extend(text(settings, "serverListURL"));
        }
        if server_lists.is_empty() {
            server_lists = env_list("AETHER_PSIPHON_SERVER_LIST");
        }
        let server_lists_explicit = !server_lists.is_empty();
        if server_lists.is_empty() {
            server_lists.push(ferrox_core::psiphon::SERVER_LIST_URL.to_owned());
        }
        let proxy_user = text(settings, "localProxyUsername")
            .or_else(|| text(settings, "LocalProxyUsername"))
            .or_else(|| text(settings, "shareProxyOnNetworkUsername"))
            .or_else(|| env("AETHER_PSIPHON_PROXY_USER"))
            .filter(|user| !user.is_empty());
        let proxy_pass = text(settings, "localProxyPassword")
            .or_else(|| text(settings, "LocalProxyPassword"))
            .or_else(|| text(settings, "shareProxyOnNetworkPassword"))
            .or_else(|| env("AETHER_PSIPHON_PROXY_PASS"))
            .filter(|pass| !pass.is_empty());
        if proxy_user.is_some() != proxy_pass.is_some() {
            return Err(
                "psiphon: localProxyUsername and localProxyPassword must be named together"
                    .to_owned(),
            );
        }
        if proxy_user.as_ref().is_some_and(|user| user.len() > 255)
            || proxy_pass.as_ref().is_some_and(|pass| pass.len() > 255)
        {
            return Err(
                "psiphon: localProxyUsername and localProxyPassword must each be at most 255 bytes"
                    .to_owned(),
            );
        }
        let cdn_profile = text(settings, "cdnProfile").map(|profile| profile.to_ascii_lowercase());
        let selection = text(settings, "protocolSelection")
            .map(|selection| selection.to_ascii_lowercase())
            .or_else(|| {
                text(settings, "protocol_selection").map(|value| value.to_ascii_lowercase())
            });
        let conduit = selection.as_deref() == Some("conduit");
        let fronted = match selection.as_deref() {
            None => matches!(cdn_profile.as_deref(), Some("fronted")),
            Some("cdn_fronting" | "fronted" | "fronted-meek" | "cdn") => true,
            Some("auto" | "direct" | "conduit") => false,
            Some(other) => {
                eprintln!("psiphon: protocolSelection {other:?} is not a known mode");
                false
            }
        };
        let fronted_fallback = !conduit && !fronted;
        let selection_cdn = selection_enables_cdn(selection.as_deref());
        let selection_tactics_disabled = selection_disables_tactics(selection.as_deref());
        // Explicit LimitTunnelProtocols wins; otherwise derive from protocolSelection.
        let mut protocols = protocol_list(settings);
        if protocols.is_empty() {
            protocols = selection_protocols(selection.as_deref());
        }
        let conduit_mode = match text(settings, "conduitMode")
            .or_else(|| text(settings, "conduit_mode"))
            .map(|mode| mode.to_ascii_lowercase())
            .as_deref()
        {
            Some("public") => ConduitMode::Public,
            Some("private" | "shirokhorshid") => ConduitMode::Shirokhorshid,
            Some("auto") | None => ConduitMode::Auto,
            Some(other) => {
                eprintln!("psiphon: conduitMode {other:?} is not a known mode");
                ConduitMode::Auto
            }
        };
        let conduit_timeout = Duration::from_secs(
            number(settings, "conduitTimeout")
                .or_else(|| number(settings, "conduit_timeout"))
                .unwrap_or(180)
                .clamp(10, 600),
        );
        let mut conduit_protocols = string_list(settings, "ConduitTunnelProtocols");
        if conduit_protocols.is_empty() {
            conduit_protocols = string_list(settings, "conduitTunnelProtocols");
        }
        if conduit_protocols.is_empty() {
            conduit_protocols = string_list(settings, "CONDUIT_TUNNEL_PROTOCOLS");
        }
        let reject_censored = flag(
            settings,
            "rejectCensoredCountryProxies",
            "AETHER_PSIPHON_REJECT_CENSORED_PROXIES",
        );
        let reject_countries = {
            let mut countries = string_list(settings, "InproxyRejectProxyCountryCodes");
            if countries.is_empty() {
                countries = string_list(settings, "rejectProxyCountryCodes");
            }
            if countries.is_empty() && reject_censored {
                countries = CENSORED_COUNTRY_CODES
                    .iter()
                    .map(|code| (*code).to_owned())
                    .collect();
            }
            countries
                .into_iter()
                .map(|code| code.to_ascii_uppercase())
                .collect()
        };
        let geoip_path = text(settings, "GeoIPDatabasePath");
        let reject_cidrs = string_list(settings, "InproxyRejectProxyCIDRs");
        let limit_quic_versions = string_list(settings, "LimitQUICVersions");
        let dial_ports = port_lists(settings);
        let dial_ports_probability = probability(settings, "LimitTunnelDialPortNumbersProbability");
        let prioritize_protocols = protocol_list_named(settings, "PrioritizeTunnelProtocols");
        let prioritize_count =
            number(settings, "PrioritizeTunnelProtocolsCandidateCount").unwrap_or(10) as usize;
        let prioritize_probability = probability(settings, "PrioritizeTunnelProtocolsProbability");
        let limit_protocols_probability = probability(settings, "LimitTunnelProtocolsProbability");
        let initial_limit_probability =
            probability(settings, "InitialLimitTunnelProtocolsProbability");
        let quic_noise = text(settings, "QUICNoiseProfile").filter(|profile| !profile.is_empty());
        let mut sni_names = string_list(settings, "TLSOSSHSNIServerNames");
        if sni_names.is_empty() {
            if let Some(name) = text(settings, "TLSOSSHSNIServerName") {
                sni_names.push(name);
            }
        }
        // Both reference coins must land, so one setting alone never turns a name into a random one.
        let transform_probability = decimal(settings, "TransformHostNameProbability")
            .unwrap_or(0.5)
            .clamp(0.0, 1.0)
            * decimal(settings, "CustomHostNameProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0);
        let meek_padding = (
            u16::try_from(
                number(settings, "MeekMinTLSPadding")
                    .unwrap_or(0)
                    .min(65_535),
            )
            .unwrap_or(0),
            u16::try_from(
                number(settings, "MeekMaxTLSPadding")
                    .unwrap_or(0)
                    .min(65_535),
            )
            .unwrap_or(0),
        );
        let obfuscated_min_padding = ssh_padding(
            settings,
            "ObfuscatedSSHMinPadding",
            MIN_PADDING,
            MIN_PADDING,
        );
        let obfuscated_max_padding = ssh_padding(
            settings,
            "ObfuscatedSSHMaxPadding",
            MAX_PADDING,
            obfuscated_min_padding,
        );
        let meek_limit = |key: &str| {
            let max = crate::psiphon_meek::MAX_REQUEST_PAYLOAD as u64;
            let raw = number(settings, key).unwrap_or(max);
            let value = raw.clamp(1, max) as usize;
            if raw != value as u64 {
                eprintln!("psiphon: {key} clamped to {value}");
            }
            value
        };
        let meek_min_limit_request = meek_limit("MeekMinLimitRequestPayloadLength");
        let meek_max_limit_request = meek_limit("MeekMaxLimitRequestPayloadLength");
        if meek_min_limit_request > meek_max_limit_request {
            eprintln!(
                "psiphon: MeekMinLimitRequestPayloadLength exceeds MeekMaxLimitRequestPayloadLength; using the minimum for both"
            );
        }
        let (tls_roots, disable_system_root_cas) = tls_trust_roots(settings);
        let tls_shape = TlsShape {
            min_padding: u16::try_from(
                number(settings, "TLSTunnelMinTLSPadding")
                    .unwrap_or(0)
                    .min(65_535),
            )
            .unwrap_or(0),
            max_padding: u16::try_from(
                number(settings, "TLSTunnelMaxTLSPadding")
                    .unwrap_or(0)
                    .min(65_535),
            )
            .unwrap_or(0),
            sni_names,
            transform_probability,
            hostname_patterns: string_list(settings, "CustomHostNameRegexes"),
            limit_protocols: protocol_list_named(settings, "CustomHostNameLimitProtocols"),
            profiles: tls_profiles(settings),
            custom_profiles: custom_tls_profiles(settings),
            use_only_custom_profiles: settings
                .and_then(|settings| settings.get("UseOnlyCustomTLSProfiles"))
                .and_then(Json::as_bool)
                .unwrap_or(false),
            disable_fronting_profiles: disable_fronting_profiles(settings),
            forced_profile: None,
            randomized_probability: decimal(settings, "SelectRandomizedTLSProfileProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            shadowsocks_prefix: shadowsocks_prefix(settings),
            ossh_prefix: ossh_prefix(settings),
            ossh_seed_transform: protocol_transforms(
                settings,
                "OSSHObfuscatorSeedTransformProbability",
                "OSSHObfuscatorSeedTransformSpecs",
                "OSSHObfuscatorSeedTransformScopedSpecNames",
            ),
            quic_nonce_transform: protocol_transforms(
                settings,
                "ObfuscatedQUICNonceTransformProbability",
                "ObfuscatedQUICNonceTransformSpecs",
                "ObfuscatedQUICNonceTransformScopedSpecNames",
            ),
            direct_http_transform: protocol_transforms(
                settings,
                "DirectHTTPProtocolTransformProbability",
                "DirectHTTPProtocolTransformSpecs",
                "DirectHTTPProtocolTransformScopedSpecNames",
            ),
            fronted_http_transform: protocol_transforms(
                settings,
                "FrontedHTTPProtocolTransformProbability",
                "FrontedHTTPProtocolTransformSpecs",
                "FrontedHTTPProtocolTransformScopedSpecNames",
            ),
            obfuscated_min_padding,
            obfuscated_max_padding,
            meek_alternate_cookie_name: decimal(settings, "MeekAlternateCookieNameProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0),
            meek_alternate_content_type: decimal(settings, "MeekAlternateContentTypeProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0),
            meek_traffic_shaping: decimal(settings, "MeekTrafficShapingProbability")
                .unwrap_or(1.0)
                .clamp(0.0, 1.0),
            meek_traffic_shaping_protocols: protocol_list_named(
                settings,
                "MeekTrafficShapingLimitProtocols",
            ),
            meek_min_limit_request,
            meek_max_limit_request,
            meek_redial_tls: decimal(settings, "MeekRedialTLSProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            meek_payload_padding: decimal(settings, "MeekPayloadPaddingProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            meek_payload_padding_omit: decimal(settings, "MeekPayloadPaddingOmitProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            meek_payload_padding_min: usize::try_from(
                number(settings, "MeekPayloadPaddingMinSize")
                    .unwrap_or(0)
                    .min(65_533),
            )
            .unwrap_or(0),
            meek_payload_padding_max: usize::try_from(
                number(settings, "MeekPayloadPaddingMaxSize")
                    .unwrap_or(65_533)
                    .min(65_533),
            )
            .unwrap_or(65_533),
            no_default_tls_session_id_probability: decimal(
                settings,
                "NoDefaultTLSSessionIDProbability",
            )
            .unwrap_or(0.5)
            .clamp(0.0, 1.0),
            obfuscated_ticket_probability: decimal(settings, "TLSTunnelObfuscatedPSKProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0),
            roots: tls_roots,
            disable_system_root_cas,
            tls_fragment_client_hello: decimal(settings, "TLSFragmentClientHelloProbability")
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            tls_fragment_client_hello_protocols: protocol_list_named(
                settings,
                "TLSFragmentClientHelloLimitProtocols",
            ),
            user_agent_probability: decimal(settings, "PickUserAgentProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0),
            quic_dial_early: decimal(settings, "QUICDialEarlyProbability")
                .unwrap_or(1.0)
                .clamp(0.0, 1.0),
            quic_disable_path_mtu: decimal(settings, "QUICDisablePathMTUDiscoveryProbability")
                .or_else(|| decimal(settings, "QUICDisableClientPathMTUDiscoveryProbability"))
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            quic_obfuscated_psk: decimal(settings, "QUICObfuscatedPSKProbability")
                .unwrap_or(0.5)
                .clamp(0.0, 1.0),
            fragmentor: crate::psiphon_fragment::Fragmentor::new(
                decimal(settings, "FragmentorProbability").unwrap_or(0.5),
                protocol_list_named(settings, "FragmentorLimitProtocols"),
                number(settings, "FragmentorMinTotalBytes").unwrap_or(0) as usize,
                number(settings, "FragmentorMaxTotalBytes").unwrap_or(0) as usize,
                number(settings, "FragmentorMinWriteBytes").unwrap_or(1) as usize,
                number(settings, "FragmentorMaxWriteBytes").unwrap_or(1500) as usize,
                Duration::from_micros(
                    number(settings, "FragmentorMinDelayMicroseconds").unwrap_or(0),
                ),
                Duration::from_micros(
                    number(settings, "FragmentorMaxDelayMicroseconds").unwrap_or(10_000),
                ),
                flag(
                    settings,
                    "OSSHPrefixEnableFragmentor",
                    "AETHER_PSIPHON_FRAGMENT_OSSHPREFIX",
                ),
            ),
        };
        let mut cdn_ips: Vec<String> = string_list(settings, "cdnIps")
            .into_iter()
            .flat_map(|raw| expand_cidr(&raw))
            .collect();
        let mut cdn_snis = string_list(settings, "cdnSni");
        let mut fronted_overrides = Vec::new();
        if let Some(items) = settings
            .and_then(|settings| settings.get("FrontedMeekDialOverrides"))
            .and_then(Json::as_arr)
        {
            for item in items {
                let dials = string_list_in(item, "DialAddresses");
                let snis = string_list_in(item, "SNIServerName");
                if dials.is_empty() && snis.is_empty() {
                    continue;
                }
                fronted_overrides.push(FrontedOverride {
                    override_id: text_in(item, "OverrideID"),
                    dials,
                    snis,
                    disable_sni: bool_in(item, "DisableSNI"),
                    alpn: string_list_in(item, "ALPNProtocols")
                        .into_iter()
                        .map(String::into_bytes)
                        .collect(),
                    match_providers: regex_list_in(item, "MatchFrontingProviderIDRegexes"),
                    match_dials: regex_list_in(item, "MatchDialAddressRegexes"),
                    match_hosts: regex_list_in(item, "MatchHostHeaderRegexes"),
                    verify_server_names: string_list_in(item, "VerifyServerNames"),
                    verify_pins: string_list_in(item, "VerifyPins"),
                    tls_profile: text_in(item, "TLSProfile"),
                    skip_cert_verify: bool_in(item, "SkipCertVerify"),
                });
            }
        }
        if let Some(spec) = settings
            .and_then(|settings| settings.get("FrontedMeekCDNScanSpec"))
            .or_else(|| settings.and_then(|settings| settings.get("frontedMeekCDNScanSpec")))
        {
            for ip in string_list_in(spec, "IPCandidates")
                .into_iter()
                .flat_map(|raw| expand_cidr(&raw))
            {
                push_unique(&mut cdn_ips, ip);
            }
            for sni in string_list_in(spec, "SNIServerNames") {
                push_unique(&mut cdn_snis, sni);
            }
        }
        let cdn_sets: Vec<String> = string_list(settings, "FrontedMeekCDNScanBuiltInSets")
            .into_iter()
            .chain(string_list(settings, "cdnSets"))
            .collect();
        let builtin_scan = selection_cdn
            || flag(
                settings,
                "FrontedMeekCDNScanUseBuiltInSpec",
                "AETHER_PSIPHON_CDN_BUILTIN",
            )
            || cdn_sets.iter().any(|set| {
                matches!(
                    set.to_ascii_lowercase().as_str(),
                    "builtin" | "legacy" | "fronted-meek" | "akamai"
                )
            });
        if builtin_scan {
            let room = FRONTED_VARIANTS
                .saturating_sub(cdn_ips.len())
                .min(FRONTED_VARIANTS / 2);
            for edge in builtin_cdn_ips(room) {
                push_unique(&mut cdn_ips, edge);
            }
            for sni in BUILTIN_CDN_SNIS {
                push_unique(&mut cdn_snis, (*sni).to_owned());
            }
        }
        if selection_cdn
            || cdn_sets
                .iter()
                .any(|set| set.eq_ignore_ascii_case("fastly"))
        {
            fronted_overrides.push(FrontedOverride {
                dials: vec!["pypi.org".to_owned()],
                snis: vec!["pypi.org".to_owned()],
                disable_sni: false,
                alpn: vec![b"http/1.1".to_vec()],
                match_providers: Vec::new(),
                match_dials: Vec::new(),
                match_hosts: Vec::new(),
                override_id: None,
                verify_server_names: Vec::new(),
                verify_pins: Vec::new(),
                tls_profile: None,
                skip_cert_verify: false,
            });
        }
        if decimal(settings, "FrontedMeekDialOverridesProbability")
            .is_some_and(|probability| probability <= 0.0)
        {
            fronted_overrides.clear();
        }
        if cdn_ips.len() > FRONTED_VARIANTS {
            eprintln!(
                "psiphon: {} cdn IP candidates exceed {FRONTED_VARIANTS}; dropping the rest",
                cdn_ips.len()
            );
            cdn_ips.truncate(FRONTED_VARIANTS);
        }
        if cdn_snis.len() > FRONTED_VARIANTS {
            eprintln!(
                "psiphon: {} cdn SNI candidates exceed {FRONTED_VARIANTS}; dropping the rest",
                cdn_snis.len()
            );
            cdn_snis.truncate(FRONTED_VARIANTS);
        }
        let proxy = text(settings, "upstreamProxy")
            .or_else(|| text(settings, "upstream"))
            .or_else(|| text(settings, "UpstreamProxyURL"))
            .or_else(|| text(settings, "UpstreamProxyUrl"))
            .or_else(|| env("AETHER_PSIPHON_UPSTREAM"))
            .map(|url| Proxy::parse(&url, &dns))
            .transpose()?;
        let http_listen = if flag(
            settings,
            "DisableLocalHTTPProxy",
            "AETHER_PSIPHON_DISABLE_HTTP_PROXY",
        ) {
            None
        } else {
            port_number(settings, "LocalHttpProxyPort")
                .or_else(|| port_number(settings, "shareProxyOnNetworkHttpPort"))
                .or_else(|| {
                    env("AETHER_PSIPHON_HTTP_PROXY_PORT")
                        .and_then(|value| value.parse::<u16>().ok())
                })
        };
        let target =
            text(settings, "TargetServerEntry").or_else(|| env("AETHER_PSIPHON_TARGET_ENTRY"));
        // The reference pins a targeted entry to one tunnel, and so does this lane.
        let pool = if target.is_some() {
            1
        } else {
            number(settings, "TunnelPoolSize")
                .or_else(|| number(settings, "tunnelPoolSize"))
                .or_else(|| env("AETHER_PSIPHON_TUNNEL_POOL").and_then(|value| value.parse().ok()))
                .unwrap_or(1)
                .clamp(1, 32) as usize
        };
        let disable_timeouts = flag(
            settings,
            "DisableTimeouts",
            "AETHER_PSIPHON_DISABLE_TIMEOUTS",
        );
        let latency = Latency::from_settings(settings, disable_timeouts);
        let establish = number(settings, "TunnelConnectTimeoutSeconds")
            .or_else(|| number(settings, "EstablishTunnelTimeoutSeconds"))
            .map(|seconds| Duration::from_secs(seconds.clamp(1, 600)));
        let initial_protocols = protocol_list_named(settings, "InitialLimitTunnelProtocols");
        let initial_count = number(settings, "InitialLimitTunnelProtocolsCandidateCount")
            .or_else(|| {
                env("AETHER_PSIPHON_INITIAL_PROTOCOL_COUNT").and_then(|value| value.parse().ok())
            })
            .unwrap_or(0) as usize;
        let beast = settings
            .and_then(|settings| settings.get("beastMode"))
            .and_then(Json::as_bool);
        let aggressive_setting = settings
            .and_then(|settings| settings.get("AggressiveEstablishment"))
            .and_then(Json::as_bool)
            .or_else(|| {
                settings
                    .and_then(|settings| settings.get("aggressiveEstablishment"))
                    .and_then(Json::as_bool)
            })
            .or(beast);
        // Shirokhorshid's Beast Mode defaults on for every selection mode; a plain reference config keeps it off.
        let aggressive = aggressive_setting.unwrap_or(selection.is_some())
            || env_flag("AETHER_PSIPHON_BEAST")
            || env_flag("AETHER_PSIPHON_AGGRESSIVE");
        let limit_cpu = flag(
            settings,
            "LimitCPUThreads",
            "AETHER_PSIPHON_LIMIT_CPU_THREADS",
        );
        let workers = number(settings, "ConnectionWorkerPoolSize")
            .or_else(|| env("AETHER_PSIPHON_WORKERS").and_then(|value| value.parse().ok()))
            .unwrap_or(DIAL_WORKERS as u64)
            .clamp(1, 32) as usize;
        let worker_cap = number(settings, "ConnectionWorkerPoolMaxSize")
            .unwrap_or(32)
            .clamp(1, 32) as usize;
        let workers = if target.is_some() {
            1
        } else if aggressive {
            workers.max(30).min(worker_cap)
        } else {
            workers.min(worker_cap)
        };
        let workers = if flag(
            settings,
            "DisableConnectionWorkerPool",
            "AETHER_PSIPHON_DISABLE_WORKERS",
        ) {
            1
        } else {
            workers
        };
        let workers = if limit_cpu { 1 } else { workers };
        let intensive_workers = number(settings, "LimitIntensiveConnectionWorkers")
            .unwrap_or(0)
            .min(u64::try_from(workers).unwrap_or(u64::MAX));
        let intensive_workers = if limit_cpu {
            1
        } else {
            intensive_workers as usize
        };
        let stagger = Duration::from_millis(
            number(settings, "StaggerConnectionWorkersMilliseconds")
                .or_else(|| env("AETHER_PSIPHON_STAGGER_MS").and_then(|value| value.parse().ok()))
                .unwrap_or(0)
                .min(60_000),
        );
        let pause = Duration::from_secs(
            number(settings, "EstablishTunnelPausePeriodSeconds")
                .unwrap_or(2)
                .clamp(1, 3600),
        );
        let affinity_grace = Duration::from_millis(
            number(
                settings,
                "EstablishTunnelServerAffinityGracePeriodMilliseconds",
            )
            .unwrap_or(0)
            .min(60_000),
        );
        let propagation = text(settings, "PropagationChannelId")
            .or_else(|| env("AETHER_PSIPHON_PROPAGATION"))
            .unwrap_or_else(|| PROPAGATION_CHANNEL_ID.to_owned());
        let platform = text(settings, "ClientPlatform")
            .or_else(|| env("AETHER_PSIPHON_PLATFORM"))
            .unwrap_or_else(|| "Android".to_owned());
        let client_version = text(settings, "ClientVersion")
            .or_else(|| env("AETHER_PSIPHON_CLIENT_VERSION"))
            .unwrap_or_else(|| CLIENT_VERSION.to_owned());
        let device_region = text(settings, "DeviceRegion")
            .or_else(|| text(settings, "deviceRegion"))
            .or_else(|| env("AETHER_PSIPHON_DEVICE_REGION"))
            .filter(|region| !region.is_empty());
        let device_location = text(settings, "DeviceLocation")
            .or_else(|| text(settings, "deviceLocation"))
            .or_else(|| env("AETHER_PSIPHON_DEVICE_LOCATION"))
            .filter(|location| !location.is_empty());
        let client_features = string_list(settings, "ClientFeatures");
        let split_tunnel_own_region = flag(
            settings,
            "SplitTunnelOwnRegion",
            "AETHER_PSIPHON_SPLIT_TUNNEL_OWN_REGION",
        );
        let split_tunnel_regions = split_tunnel_regions(settings);
        let compartment = text(settings, "InproxyClientPersonalCompartmentID")
            .or_else(|| text(settings, "inproxyClientPersonalCompartmentID"))
            .or_else(|| text(settings, "inproxyCompartment"))
            .or_else(|| env("AETHER_PSIPHON_COMPARTMENT"))
            .unwrap_or_else(|| PRIVATE_COMPARTMENT_ID.to_owned());
        let limit_meek_buffers = flag(
            settings,
            "LimitMeekBufferSizes",
            "AETHER_PSIPHON_SMALL_MEEK",
        );
        let relay_buffer = if flag(
            settings,
            "LimitRelayBufferSizes",
            "AETHER_PSIPHON_SMALL_RELAY",
        ) {
            4 * 1024
        } else {
            RELAY_BUFFER
        };
        let keepalive = if flag(
            settings,
            "DisablePeriodicSshKeepAlive",
            "AETHER_PSIPHON_DISABLE_KEEPALIVE",
        ) || flag(
            settings,
            "DisableKeepAlive",
            "AETHER_PSIPHON_DISABLE_KEEPALIVE",
        ) {
            None
        } else {
            Some(keepalive(settings))
        };
        let sponsor = text(settings, "sponsorId")
            .or_else(|| text(settings, "SponsorId"))
            .or_else(|| text(settings, "SponsorID"))
            .or_else(|| env("AETHER_PSIPHON_SPONSOR_ID"))
            .unwrap_or_else(|| SPONSOR_ID.to_owned());
        let session_id = client_session_id(settings);
        let burst = crate::psiphon_burst::Config::new(
            number(settings, "ClientBurstUpstreamTargetBytes").unwrap_or(0),
            Duration::from_millis(
                number(settings, "ClientBurstUpstreamDeadlineMilliseconds").unwrap_or(0),
            ),
            number(settings, "ClientBurstDownstreamTargetBytes").unwrap_or(0),
            Duration::from_millis(
                number(settings, "ClientBurstDownstreamDeadlineMilliseconds").unwrap_or(0),
            ),
        );
        let api_encoding = match text(settings, "TargetAPIEncoding").as_deref() {
            None | Some("cbor") => ApiEncoding::Cbor,
            Some("json") => ApiEncoding::Json,
            Some(other) => {
                return Err(format!("psiphon: invalid TargetAPIEncoding {other:?}"));
            }
        };
        let remote_list_retry = Duration::from_millis(
            number(settings, "FetchRemoteServerListRetryPeriodMilliseconds")
                .unwrap_or(0)
                .min(3_600_000),
        );
        let disable_api = flag(settings, "DisableApi", "AETHER_PSIPHON_DISABLE_API");
        let ssh_algorithms = ssh_algorithms(settings);
        match text(settings, "TargetAPIProtocol").as_deref() {
            None | Some("ssh") => {}
            Some("web") => {
                eprintln!("psiphon: TargetAPIProtocol web is not carried; using the ssh API");
            }
            Some(other) => {
                return Err(format!("psiphon: invalid TargetAPIProtocol {other:?}"));
            }
        }
        let light = light_settings(
            settings,
            &tls_shape,
            &sponsor,
            &platform,
            device_region.as_deref(),
            session_id.as_deref(),
        );
        Ok(Self {
            state: text(settings, "state")
                .or_else(|| text(settings, "dataRootDirectory"))
                .or_else(|| text(settings, "DataRootDirectory"))
                .or_else(|| text(settings, "dataDirectory"))
                .or_else(|| env("AETHER_PSIPHON_DIR"))
                .or_else(|| env("AETHER_PSIPHON_STATE"))
                .map_or_else(default_state, PathBuf::from),
            listen,
            http_listen,
            region,
            ready: Duration::from_secs(ready),
            entries: server_entries(settings),
            target,
            protocols,
            initial_protocols,
            fronted,
            fronted_fallback,
            cdn_ips,
            cdn_snis,
            fronted_overrides,
            initial_count,
            pool,
            latency,
            establish,
            workers,
            intensive_workers,
            stagger,
            pause,
            affinity_grace,
            propagation,
            platform,
            client_version,
            api_encoding,
            device_region,
            device_location,
            client_features,
            split_tunnel_own_region,
            split_tunnel_regions,
            compartment,
            conduit,
            conduit_mode,
            conduit_timeout,
            conduit_protocols,
            reject_countries,
            reject_cidrs,
            geoip_path,
            dns_servers,
            dns,
            limit_quic_versions,
            quic_noise,
            tls_shape,
            meek_padding,
            limit_meek_buffers,
            relay_buffer,
            rate: rate_limits(settings),
            holdoff: holdoff(settings),
            holdoff_direct: holdoff_class(settings, "Direct"),
            holdoff_fronting: holdoff_class(settings, "Fronting"),
            holdoff_inproxy: holdoff_class(settings, "Inproxy"),
            compress_tactics: settings
                .and_then(|settings| settings.get("CompressTactics"))
                .and_then(Json::as_bool)
                .unwrap_or(true),
            server_entry_max_move_to_front: decimal(settings, "ServerEntryIteratorMaxMoveToFront")
                .map_or(-1, |value| value as i64),
            server_entry_reset_probability: decimal(
                settings,
                "ServerEntryIteratorResetProbability",
            )
            .unwrap_or(1.0)
            .clamp(0.0, 1.0),
            restrict_direct_regions: key_strings(settings, "RestrictDirectProviderRegions"),
            restrict_direct_probability: decimal(
                settings,
                "RestrictDirectProviderIDsClientProbability",
            )
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
            restrict_inproxy_regions: key_strings(settings, "RestrictInproxyProviderRegions"),
            restrict_inproxy_probability: decimal(
                settings,
                "RestrictInproxyProviderIDsClientProbability",
            )
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
            restrict_fronting_ids: string_list(settings, "RestrictFrontingProviderIDs"),
            restrict_fronting_probability: decimal(
                settings,
                "RestrictFrontingProviderIDsClientProbability",
            )
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
            liveness: liveness(settings),
            dial_ports,
            dial_ports_probability,
            prioritize_protocols,
            prioritize_count,
            prioritize_probability,
            limit_protocols_probability,
            initial_limit_probability,
            replay: replay_settings(settings),
            keepalive,
            disable_tactics: selection_tactics_disabled
                || flag(settings, "DisableTactics", "AETHER_PSIPHON_DISABLE_TACTICS"),
            meek_headers: dial_headers(settings),
            ssh_channel_window: number(settings, "SSHChannelWindowSize")
                .map_or(crate::psiphon_ssh::DEFAULT_CHANNEL_WINDOW, |window| {
                    window.clamp(64 * 1024, u64::from(u32::MAX)) as u32
                }),
            server_lists,
            server_lists_explicit,
            remote_fetch_disabled: flag(
                settings,
                "DisableRemoteServerListFetcher",
                "AETHER_PSIPHON_DISABLE_REMOTE_LIST",
            ),
            server_list_key: text(settings, "serverListSignaturePublicKey")
                .or_else(|| text(settings, "RemoteServerListSignaturePublicKey"))
                .or_else(|| text(settings, "remoteServerListSignaturePublicKey"))
                .or_else(|| env("AETHER_PSIPHON_SERVER_LIST_KEY"))
                .unwrap_or_else(|| ferrox_core::psiphon::SERVER_LIST_SIGNATURE_KEY.to_owned()),
            osl_roots: osl_roots(settings),
            remote_list_key: text(settings, "RemoteServerListSignaturePublicKey")
                .or_else(|| text(settings, "remoteServerListSignaturePublicKey"))
                .or_else(|| env("AETHER_PSIPHON_REMOTE_LIST_KEY"))
                .unwrap_or_else(|| ferrox_core::psiphon::SERVER_LIST_SIGNATURE_KEY.to_owned()),
            remote_list_retry,
            limit_cpu,
            disable_api,
            ssh_algorithms,
            emit_sloks: flag(settings, "EmitSLOKs", "AETHER_PSIPHON_EMIT_SLOKS"),
            emit_server_alerts: flag(
                settings,
                "EmitServerAlerts",
                "AETHER_PSIPHON_EMIT_SERVER_ALERTS",
            ),
            headers: custom_headers(settings),
            proxy,
            sponsor,
            session_id,
            authorizations: string_list(settings, "Authorizations"),
            proxy_user,
            proxy_pass,
            burst,
            light,
            raw,
        })
    }
}

#[derive(Clone, Copy)]
struct Latency {
    direct: f64,
    min: f64,
    max: f64,
    lambda: f64,
}

impl Latency {
    fn from_settings(settings: Option<&Json>, disable_timeouts: bool) -> Self {
        let direct = decimal(settings, "NetworkLatencyMultiplier")
            .or_else(|| env("AETHER_PSIPHON_LATENCY").and_then(|value| value.parse().ok()))
            .filter(|multiplier| *multiplier > 0.0)
            .map(|multiplier| multiplier.min(60.0));
        if let Some(direct) = direct {
            return Self {
                direct,
                min: direct,
                max: direct,
                lambda: 2.0,
            };
        }
        let min = decimal(settings, "NetworkLatencyMultiplierMin")
            .filter(|value| !value.is_nan())
            .map(|value| value.clamp(1.0, 60.0));
        let max = decimal(settings, "NetworkLatencyMultiplierMax")
            .filter(|value| !value.is_nan())
            .map(|value| value.clamp(1.0, 60.0));
        let lambda = decimal(settings, "NetworkLatencyMultiplierLambda")
            .or_else(|| env("AETHER_PSIPHON_LATENCY_LAMBDA").and_then(|value| value.parse().ok()))
            .filter(|value| !value.is_nan())
            .or_else(|| disable_timeouts.then_some(0.1))
            .map(|value| value.clamp(0.001, 1e6));
        if min.is_none() && max.is_none() && lambda.is_none() {
            return Self {
                direct: 1.0,
                min: 1.0,
                max: 1.0,
                lambda: 2.0,
            };
        }
        Self {
            direct: 0.0,
            min: min.unwrap_or(1.0),
            max: max.unwrap_or(3.0),
            lambda: lambda.unwrap_or(2.0),
        }
    }

    fn multiplier(self) -> f64 {
        if self.direct > 0.0 {
            return self.direct;
        }
        if self.max <= self.min || self.lambda <= 0.0 {
            return self.min;
        }
        let span = self.max - self.min;
        for _ in 0..16 {
            let mut bytes = [0u8; 4];
            let _ = getrandom::fill(&mut bytes);
            let uniform = f64::from(u32::from_le_bytes(bytes)) / 4_294_967_296.0;
            let value = self.min - (1.0 - uniform).ln() / self.lambda * span;
            if value <= self.max {
                return value;
            }
        }
        self.max
    }
}

impl Settings {
    /// The reference scales every network budget by `NetworkLatencyMultiplier`.
    fn dial_timeout(&self) -> Duration {
        self.establish
            .unwrap_or(DIAL_TIMEOUT)
            .mul_f64(self.latency.multiplier())
            .min(Duration::from_secs(600))
    }

    /// The longest provider-scoped hold-off that names this tunnel's class.
    fn holdoff_for(
        &self,
        protocol: &str,
        provider: Option<&str>,
        region: Option<&str>,
        fronting: Option<&str>,
    ) -> Duration {
        if protocol.starts_with("FRONTED-MEEK") {
            self.holdoff_fronting.delay(fronting, region)
        } else if protocol.starts_with("INPROXY-") {
            self.holdoff_inproxy.delay(provider, region)
        } else {
            self.holdoff_direct.delay(provider, region)
        }
    }

    /// A hash of the fields that change a dial's selected parameters.
    fn config_state(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.protocols.hash(&mut hasher);
        self.initial_protocols.hash(&mut hasher);
        self.fronted.hash(&mut hasher);
        self.fronted_fallback.hash(&mut hasher);
        self.cdn_ips.hash(&mut hasher);
        self.cdn_snis.hash(&mut hasher);
        format!("{:?}", self.fronted_overrides).hash(&mut hasher);
        self.region.hash(&mut hasher);
        self.conduit.hash(&mut hasher);
        self.conduit_protocols.hash(&mut hasher);
        self.limit_quic_versions.hash(&mut hasher);
        self.quic_noise.hash(&mut hasher);
        self.meek_headers.hash(&mut hasher);
        self.headers.hash(&mut hasher);
        self.authorizations.hash(&mut hasher);
        self.proxy_user.hash(&mut hasher);
        self.proxy_pass.hash(&mut hasher);
        self.device_region.hash(&mut hasher);
        self.client_features.hash(&mut hasher);
        self.prioritize_protocols.hash(&mut hasher);
        self.prioritize_count.hash(&mut hasher);
        self.restrict_direct_regions.hash(&mut hasher);
        self.restrict_inproxy_regions.hash(&mut hasher);
        self.restrict_fronting_ids.hash(&mut hasher);
        format!("{:?}", self.tls_shape).hash(&mut hasher);
        format!("{:?}", self.proxy).hash(&mut hasher);
        format!("{:?}", self.light).hash(&mut hasher);
        format!("{:?}", self.dial_ports).hash(&mut hasher);
        self.dial_ports_probability.to_bits().hash(&mut hasher);
        self.limit_protocols_probability.to_bits().hash(&mut hasher);
        self.initial_limit_probability.to_bits().hash(&mut hasher);
        self.prioritize_probability.to_bits().hash(&mut hasher);
        self.restrict_direct_probability.to_bits().hash(&mut hasher);
        self.restrict_inproxy_probability
            .to_bits()
            .hash(&mut hasher);
        self.restrict_fronting_probability
            .to_bits()
            .hash(&mut hasher);
        hasher.finish()
    }

    /// Whether a client restriction skips this candidate; the reference coins per candidate.
    fn restricted(&self, server: &Server, conduit: bool) -> bool {
        if conduit && server.inproxy.is_some() {
            return coin(self.restrict_inproxy_probability)
                && region_restricted(
                    &self.restrict_inproxy_regions,
                    server.provider_id.as_deref(),
                    server.region.as_deref(),
                );
        }
        if server.meek.is_some() {
            return coin(self.restrict_fronting_probability)
                && server
                    .fronting_provider_id
                    .as_deref()
                    .is_some_and(|id| self.restrict_fronting_ids.iter().any(|known| known == id));
        }
        coin(self.restrict_direct_probability)
            && region_restricted(
                &self.restrict_direct_regions,
                server.provider_id.as_deref(),
                server.region.as_deref(),
            )
    }
}

/// Read the named DNS protocol transforms from settings.
fn protocol_transform_specs(
    raw: Option<&Json>,
    field: &str,
) -> Vec<(String, Vec<(String, String)>)> {
    let Some(Json::Obj(specs)) = raw.and_then(|settings| settings.get(field)) else {
        return Vec::new();
    };
    specs
        .iter()
        .filter_map(|(name, value)| {
            let Json::Arr(transforms) = value else {
                return None;
            };
            let pairs: Vec<(String, String)> = transforms
                .iter()
                .filter_map(|transform| {
                    let Json::Arr(parts) = transform else {
                        return None;
                    };
                    if parts.len() != 2 {
                        return None;
                    }
                    Some((parts[0].as_str()?.to_owned(), parts[1].as_str()?.to_owned()))
                })
                .collect();
            (!pairs.is_empty()).then(|| (name.clone(), pairs))
        })
        .collect()
}

/// Read a transform scope-to-spec-name mapping from settings.
fn protocol_transform_scopes(raw: Option<&Json>, field: &str) -> Vec<(String, Vec<String>)> {
    let Some(Json::Obj(scopes)) = raw.and_then(|settings| settings.get(field)) else {
        return Vec::new();
    };
    scopes
        .iter()
        .map(|(scope, value)| {
            let names = match value {
                Json::Arr(items) => items
                    .iter()
                    .filter_map(Json::as_str)
                    .map(str::to_owned)
                    .collect(),
                _ => Vec::new(),
            };
            (scope.clone(), names)
        })
        .collect()
}

/// One transform family: its probability, compiled specs and scope map.
fn protocol_transforms(
    settings: Option<&Json>,
    probability: &str,
    specs: &str,
    scopes: &str,
) -> crate::psiphon_dns::ProtocolTransforms {
    crate::psiphon_dns::ProtocolTransforms {
        probability: decimal(settings, probability)
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        transforms: std::sync::Arc::new(crate::psiphon_dns::Transforms::new(
            protocol_transform_specs(settings, specs),
            protocol_transform_scopes(settings, scopes),
        )),
    }
}

/// Build the DNS fallback config from the reference's `DNSResolver*` fields.
fn dns_config(raw: Option<&Json>, dns_servers: &[SocketAddr]) -> crate::psiphon_dns::Config {
    let list = |key: &str| -> Vec<String> { string_list(raw, key) };
    let clock = |key: &str, default: u64| {
        Duration::from_millis(number(raw, key).unwrap_or(default).clamp(1, 600_000))
    };
    let mut config = crate::psiphon_dns::Config::from_servers(dns_servers);
    config.preferred = list("DNSResolverPreferredAlternateServers")
        .iter()
        .filter_map(|server| dns_server(server))
        .collect();
    config.attempts_per_server = usize::try_from(
        number(raw, "DNSResolverAttemptsPerServer")
            .unwrap_or(2)
            .clamp(1, 16),
    )
    .unwrap_or(1);
    config.attempts_per_preferred = usize::try_from(
        number(raw, "DNSResolverAttemptsPerPreferredServer")
            .unwrap_or(1)
            .clamp(1, 16),
    )
    .unwrap_or(1);
    config.request_timeout = clock("DNSResolverRequestTimeoutMilliseconds", 5_000);
    config.await_timeout = clock("DNSResolverAwaitTimeoutMilliseconds", 10);
    config.prefer_alternate_probability =
        decimal(raw, "DNSResolverPreferAlternateServerProbability")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
    config.edns0_probability = decimal(raw, "DNSResolverIncludeEDNS0Probability")
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    config.qname_casing_probability = decimal(raw, "DNSResolverQNameRandomizeCasingProbability")
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    config.cache_extension = Duration::from_millis(
        number(raw, "DNSResolverCacheExtensionInitialTTLMilliseconds").unwrap_or(0),
    );
    config.cache_extension_verified = Duration::from_millis(
        number(raw, "DNSResolverCacheExtensionVerifiedTTLMilliseconds").unwrap_or(0),
    );
    config.transform_probability = decimal(raw, "DNSResolverProtocolTransformProbability")
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    config.qname_must_match_probability = decimal(raw, "DNSResolverQNameMustMatchProbability")
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    config.transforms = Arc::new(crate::psiphon_dns::Transforms::new(
        protocol_transform_specs(raw, "DNSResolverProtocolTransformSpecs"),
        protocol_transform_scopes(raw, "DNSResolverProtocolTransformScopedSpecNames"),
    ));
    config.preresolved_labels = if let Some(Json::Obj(labels)) =
        raw.and_then(|settings| settings.get("DNSResolverPreresolvedIPAddressCIDRs"))
    {
        labels
            .iter()
            .filter_map(|(label, value)| {
                let texts: Vec<String> = match value {
                    Json::Arr(items) => items
                        .iter()
                        .filter_map(Json::as_str)
                        .map(str::to_owned)
                        .collect(),
                    Json::Str(text) => vec![text.clone()],
                    _ => return None,
                };
                let networks = crate::psiphon_dns::Config::cidrs(&texts);
                (!networks.is_empty()).then(|| (label.to_ascii_lowercase(), networks))
            })
            .collect()
    } else {
        let networks =
            crate::psiphon_dns::Config::cidrs(&list("DNSResolverPreresolvedIPAddressCIDRs"));
        if networks.is_empty() {
            HashMap::new()
        } else {
            HashMap::from([(String::new(), networks)])
        }
    };
    config.preresolved_probability = decimal(raw, "DNSResolverPreresolvedIPAddressProbability")
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    config.steering_ttl =
        Duration::from_secs(number(raw, "SteeringIPCacheTTLSeconds").unwrap_or(3600));
    config.steering_probability = decimal(raw, "SteeringIPProbability")
        .unwrap_or(1.0)
        .clamp(0.0, 1.0);
    config.steering_max =
        usize::try_from(number(raw, "SteeringIPCacheMaxEntries").unwrap_or(65_536))
            .unwrap_or(65_536);
    config
}

/// The reference's `RateLimits`: a shared token bucket for both directions.
fn rate_limits(settings: Option<&Json>) -> Option<crate::psiphon_rate::Rate> {
    let limits = settings.and_then(|settings| settings.get("RateLimits"))?;
    let amount = |key: &str| {
        limits
            .get(key)
            .and_then(Json::as_u32)
            .map(u64::from)
            .or_else(|| {
                limits
                    .get(key)
                    .and_then(Json::as_i64)
                    .and_then(|value| u64::try_from(value).ok())
            })
            .unwrap_or(0)
    };
    let close = matches!(limits.get("CloseAfterExhausted"), Some(Json::Bool(true)));
    let rate = crate::psiphon_rate::Rate::new(
        amount("ReadBytesPerSecond"),
        amount("ReadUnthrottledBytes"),
        amount("WriteBytesPerSecond"),
        amount("WriteUnthrottledBytes"),
        close,
    );
    rate.active().then_some(rate)
}

/// The reference's tactics timing: how long establishment waits, how it retries, and one dial's deadline.
#[derive(Clone, Copy, Debug, Default)]
struct TacticsTiming {
    wait: Duration,
    retry: Duration,
    jitter: f64,
    timeout: Option<Duration>,
}

/// The reference tactics timing: establishment wait, retry period, jitter, and one dial's deadline.
fn tactics_timing(settings: Option<&Json>) -> TacticsTiming {
    let millis = |key: &str, minimum: u64| {
        number(settings, key)
            .filter(|millis| *millis >= minimum)
            .map(|millis| Duration::from_millis(millis.min(3_600_000)))
    };
    TacticsTiming {
        wait: millis("TacticsWaitPeriodMilliseconds", 0).unwrap_or(Duration::ZERO),
        retry: millis("TacticsRetryPeriodMilliseconds", 1).unwrap_or(Duration::from_secs(2)),
        jitter: decimal(settings, "TacticsRetryPeriodJitter")
            .unwrap_or(0.3)
            .clamp(0.0, 1.0),
        timeout: number(settings, "TacticsTimeoutMilliseconds").and_then(|millis| {
            if millis < 1_000 {
                eprintln!(
                    "psiphon: TacticsTimeoutMilliseconds {millis} is below the 1000 ms floor; using the default"
                );
                None
            } else {
                Some(Duration::from_millis(millis.min(3_600_000)))
            }
        }),
    }
}

/// The reference protocol hold-off, empty when no protocol is named.
fn holdoff(settings: Option<&Json>) -> HoldOff {
    let names = string_list(settings, "HoldOffTunnelProtocolNames");
    if names.is_empty() {
        return HoldOff::default();
    }
    let clock = |key: &str| Duration::from_millis(number(settings, key).unwrap_or(0));
    let min = clock("HoldOffTunnelProtocolMinDurationMilliseconds").min(HOLD_OFF_LIMIT);
    let max = clock("HoldOffTunnelProtocolMaxDurationMilliseconds")
        .min(HOLD_OFF_LIMIT)
        .max(min);
    HoldOff {
        names,
        probability: decimal(settings, "HoldOffTunnelProtocolProbability")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        min,
        max,
    }
}

/// One provider-scoped hold-off class from `HoldOff{Direct,Fronting,Inproxy}Tunnel*`.
fn holdoff_class(settings: Option<&Json>, kind: &str) -> HoldOffClass {
    let clock = |suffix: &str| {
        Duration::from_millis(
            number(settings, &format!("HoldOff{kind}Tunnel{suffix}")).unwrap_or(0),
        )
        .min(HOLD_OFF_LIMIT)
    };
    let min = clock("MinDurationMilliseconds");
    let max = clock("MaxDurationMilliseconds").max(min);
    let region_scoped = kind != "Fronting";
    let providers = if region_scoped {
        key_strings(settings, &format!("HoldOff{kind}TunnelProviderRegions"))
    } else {
        string_list(settings, "HoldOffFrontingTunnelProviderIDs")
            .into_iter()
            .map(|id| (id, Vec::new()))
            .collect()
    };
    HoldOffClass {
        providers,
        region_scoped,
        probability: decimal(settings, &format!("HoldOff{kind}TunnelProbability"))
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        min,
        max,
    }
}

/// A JSON object of provider ID to region list, as the reference's `KeyStrings` fields carry.
fn key_strings(settings: Option<&Json>, key: &str) -> Vec<(String, Vec<String>)> {
    let Some(Json::Obj(pairs)) = settings.and_then(|settings| settings.get(key)) else {
        return Vec::new();
    };
    pairs
        .iter()
        .map(|(provider, value)| {
            let regions = match value {
                Json::Arr(items) => items
                    .iter()
                    .filter_map(Json::as_str)
                    .map(str::to_owned)
                    .collect(),
                Json::Str(region) => vec![region.clone()],
                _ => Vec::new(),
            };
            (provider.clone(), regions)
        })
        .collect()
}

/// Whether a provider/region map names this provider with `""` or the entry's own region.
fn region_restricted(
    map: &[(String, Vec<String>)],
    provider: Option<&str>,
    region: Option<&str>,
) -> bool {
    let Some(provider) = provider else {
        return false;
    };
    map.iter().any(|(id, regions)| {
        id == provider
            && regions
                .iter()
                .any(|allowed| allowed.is_empty() || Some(allowed.as_str()) == region)
    })
}

/// The reference initial and periodic liveness probes.
fn liveness(settings: Option<&Json>) -> Liveness {
    let flat = LivenessSpec {
        pattern: String::new(),
        min_upstream: usize::try_from(
            number(settings, "LivenessTestMinUpstreamBytes").unwrap_or(0),
        )
        .unwrap_or(0),
        max_upstream: usize::try_from(
            number(settings, "LivenessTestMaxUpstreamBytes").unwrap_or(0),
        )
        .unwrap_or(0),
        min_downstream: usize::try_from(
            number(settings, "LivenessTestMinDownstreamBytes").unwrap_or(0),
        )
        .unwrap_or(0),
        max_downstream: usize::try_from(
            number(settings, "LivenessTestMaxDownstreamBytes").unwrap_or(0),
        )
        .unwrap_or(0),
    };
    let active = flat.max_upstream > 0 || flat.max_downstream > 0;
    let mut initial = liveness_specs(settings, "InitialLivenessTest");
    let mut periodic = liveness_specs(settings, "LivenessTest");
    if active {
        if initial.is_empty() {
            initial.push(flat.clone());
        }
        if periodic.is_empty() {
            periodic.push(flat);
        }
    }
    Liveness { initial, periodic }
}

/// Read one probe list, keeping only entries with a usable pattern.
fn liveness_specs(settings: Option<&Json>, key: &str) -> Vec<LivenessSpec> {
    let Some(Json::Obj(probes)) = settings.and_then(|settings| settings.get(key)) else {
        return Vec::new();
    };
    probes
        .iter()
        .map(|(pattern, probe)| {
            let amount = |field: &str| {
                usize::try_from(probe.get(field).and_then(Json::as_u32).unwrap_or(0)).unwrap_or(0)
            };
            LivenessSpec {
                pattern: pattern.clone(),
                min_upstream: amount("MinUpstreamBytes"),
                max_upstream: amount("MaxUpstreamBytes"),
                min_downstream: amount("MinDownstreamBytes"),
                max_downstream: amount("MaxDownstreamBytes"),
            }
        })
        .collect()
}

fn port_number(settings: Option<&Json>, key: &str) -> Option<u16> {
    let value = settings.and_then(|settings| settings.get(key))?;
    value
        .as_port()
        .or_else(|| value.as_u32().and_then(|port| u16::try_from(port).ok()))
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        .filter(|port| *port > 0)
}

fn number(settings: Option<&Json>, key: &str) -> Option<u64> {
    let value = settings.and_then(|settings| settings.get(key))?;
    value
        .as_u32()
        .map(u64::from)
        .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

/// Read an integer field from settings.
fn integer(settings: Option<&Json>, key: &str) -> Option<i64> {
    let value = settings.and_then(|settings| settings.get(key))?;
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

fn decimal(settings: Option<&Json>, key: &str) -> Option<f64> {
    let value = settings.and_then(|settings| settings.get(key))?;
    match value {
        Json::Num(number) => Some(*number),
        Json::Str(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// A probability field, clamped to the reference's `[0, 1]`; absent means its default coin lands.
fn probability(settings: Option<&Json>, key: &str) -> f64 {
    decimal(settings, key).unwrap_or(1.0).clamp(0.0, 1.0)
}

/// One weighted coin, with the reference's inclusive endpoints.
fn coin(probability: f64) -> bool {
    if probability >= 1.0 {
        return true;
    }
    if probability <= 0.0 {
        return false;
    }
    f64::from(u16::from_be_bytes(random::<2>())) / 65_536.0 < probability
}

/// The reference's periodic keep-alive window, clamped so a hostile config cannot stall a session.
fn keepalive(settings: Option<&Json>) -> KeepAlive {
    let millis = |key, default: u64| {
        Duration::from_millis(
            number(settings, key)
                .unwrap_or(default)
                .clamp(1_000, 300_000),
        )
    };
    let period_min = millis("SSHKeepAlivePeriodMinMilliseconds", 60_000);
    let period_max = millis("SSHKeepAlivePeriodMaxMilliseconds", 120_000).max(period_min);
    let padding = |key, default: u64| {
        usize::try_from(number(settings, key).unwrap_or(default).min(8_192)).unwrap_or(8_192)
    };
    let padding_min = padding("SSHKeepAlivePaddingMinBytes", 0);
    let padding_max = padding("SSHKeepAlivePaddingMaxBytes", 256).max(padding_min);
    KeepAlive {
        period_min,
        period_max,
        padding_min,
        padding_max,
        inactive: millis("SSHKeepAlivePeriodicInactivePeriodMilliseconds", 10_000),
        timeout: millis("SSHKeepAlivePeriodicTimeoutMilliseconds", 30_000),
    }
}

/// The reference's `Replay*` settings, with its defaults and clamps.
fn replay_settings(settings: Option<&Json>) -> crate::psiphon_replay::Settings {
    let seconds = |key, default| Duration::from_secs(number(settings, key).unwrap_or(default));
    let probability = |key, default| decimal(settings, key).unwrap_or(default).clamp(0.0, 1.0);
    crate::psiphon_replay::Settings {
        disable: flag(settings, "DisableReplay", "AETHER_PSIPHON_DISABLE_REPLAY"),
        candidate_count: integer(settings, "ReplayCandidateCount").unwrap_or(10),
        ttl: seconds("ReplayDialParametersTTLSeconds", 86_400),
        target_upstream: number(settings, "ReplayTargetUpstreamBytes").unwrap_or(0),
        target_downstream: number(settings, "ReplayTargetDownstreamBytes").unwrap_or(0),
        target_duration: seconds("ReplayTargetTunnelDurationSeconds", 1),
        later_round_move_to_front: probability("ReplayLaterRoundMoveToFrontProbability", 0.0),
        retain_failed: probability("ReplayRetainFailedProbability", 0.5),
        ignore_changed_config_state: probability("ReplayIgnoreChangedConfigStateProbability", 0.0),
        fronted_ttl: seconds("FrontedHTTPClientReplayDialParametersTTLSeconds", 86_400),
        fronted_update_frequency: seconds("FrontedHTTPClientReplayUpdateFrequencySeconds", 300),
        fronted_probability: probability("FrontedHTTPClientReplayDialParametersProbability", 1.0),
        fronted_retain_failed: probability("FrontedHTTPClientReplayRetainFailedProbability", 0.5),
        inproxy_broker_ttl: seconds("InproxyReplayBrokerDialParametersTTLSeconds", 86_400),
        inproxy_broker_update_frequency: seconds("InproxyReplayBrokerUpdateFrequencySeconds", 300),
        inproxy_broker_probability: probability(
            "InproxyReplayBrokerDialParametersProbability",
            1.0,
        ),
        inproxy_broker_retain_failed: probability(
            "InproxyReplayBrokerRetainFailedProbability",
            0.5,
        ),
        inproxy_retain_failed: probability("InproxyReplayRetainFailedProbability", 1.0),
    }
}

/// The reference's `LimitTunnelDialPortNumbers`: protocol names (or `All`) to port ranges.
fn port_lists(settings: Option<&Json>) -> Vec<(String, PortList)> {
    let Some(Json::Obj(fields)) = settings.and_then(|settings| {
        settings
            .get("LimitTunnelDialPortNumbers")
            .or_else(|| settings.get("limitTunnelDialPortNumbers"))
    }) else {
        return Vec::new();
    };
    fields
        .iter()
        .filter_map(|(name, value)| {
            let ranges = port_ranges(value)?;
            Some((name.to_ascii_uppercase(), PortList { ranges }))
        })
        .collect()
}

/// A `PortList` value: scalars, closed ranges, or a mix of both, exactly as the reference unmarshals.
fn port_ranges(value: &Json) -> Option<Vec<(u16, u16)>> {
    if let Some(port) = value.as_port() {
        return Some(vec![(port, port)]);
    }
    if let Some(text) = value.as_str() {
        let (low, high) = text.split_once('-').unwrap_or((text, text));
        let low = low.trim().parse::<u16>().ok()?;
        let high = high.trim().parse::<u16>().ok()?;
        return Some(vec![(low.min(high), low.max(high))]);
    }
    let items = value.as_arr()?;
    let mut ranges = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Json::Arr(pair) => {
                let low = pair.first()?.as_port()?;
                let high = pair.get(1)?.as_port()?;
                ranges.push((low.min(high), low.max(high)));
            }
            Json::Num(_) => {
                let port = item.as_port()?;
                ranges.push((port, port));
            }
            Json::Str(text) => {
                let (low, high) = text
                    .split_once('-')
                    .unwrap_or((text.as_str(), text.as_str()));
                let low = low.trim().parse::<u16>().ok()?;
                let high = high.trim().parse::<u16>().ok()?;
                ranges.push((low.min(high), low.max(high)));
            }
            _ => return None,
        }
    }
    Some(ranges)
}

/// The `ShadowsocksPrefixSpecs` transform, its scope map and its probability.
fn shadowsocks_prefix(settings: Option<&Json>) -> crate::psiphon_ssh::ShadowsocksPrefix {
    crate::psiphon_ssh::ShadowsocksPrefix {
        probability: decimal(settings, "ShadowsocksPrefixProbability")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        specs: transform_specs(settings, "ShadowsocksPrefixSpecs"),
        scoped: transform_scopes(settings, "ShadowsocksPrefixScopedSpecNames"),
    }
}

/// The `OSSHPrefixSpecs` transform, its scope map, probability and split window.
fn ossh_prefix(settings: Option<&Json>) -> crate::psiphon_ssh::OsshPrefix {
    crate::psiphon_ssh::OsshPrefix {
        probability: decimal(settings, "OSSHPrefixProbability")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        specs: transform_specs(settings, "OSSHPrefixSpecs"),
        scoped: transform_scopes(settings, "OSSHPrefixScopedSpecNames"),
        split_min: Duration::from_nanos(duration_nanos(
            settings,
            "OSSHPrefixSplitMinDelayMilliseconds",
            "OSSHPrefixSplitMinDelay",
        )),
        split_max: Duration::from_nanos(duration_nanos(
            settings,
            "OSSHPrefixSplitMaxDelayMilliseconds",
            "OSSHPrefixSplitMaxDelay",
        )),
    }
}

/// One obfuscated-SSH padding bound: the reference only accepts a value in
/// `[prng.SEED_LENGTH, OBFUSCATE_MAX_PADDING]`; anything else leaves the default.
fn ssh_padding(settings: Option<&Json>, key: &str, default: usize, floor: usize) -> usize {
    number(settings, key)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (MIN_PADDING..=MAX_PADDING).contains(value) && *value >= floor)
        .unwrap_or(default)
}

/// A duration in nanoseconds: the `...Milliseconds` spelling is milliseconds, while the
/// reference's `time.Duration` spelling is already nanoseconds.
fn duration_nanos(settings: Option<&Json>, millis: &str, duration: &str) -> u64 {
    if let Some(value) = number(settings, millis) {
        return value.saturating_mul(1_000_000).min(60_000_000_000);
    }
    number(settings, duration).map_or(0, |nanos| nanos.min(60_000_000_000))
}

/// The named byte generators of one prefix transform.
fn transform_specs(settings: Option<&Json>, field: &str) -> Vec<(String, String)> {
    let Some(Json::Obj(fields)) = settings.and_then(|settings| settings.get(field)) else {
        return Vec::new();
    };
    fields
        .iter()
        .filter_map(|(name, spec)| {
            let generator = spec
                .as_arr()
                .and_then(|transforms| transforms.first())
                .and_then(Json::as_arr)
                .and_then(|transform| transform.get(1))
                .and_then(Json::as_str)?;
            Some((name.clone(), generator.to_owned()))
        })
        .collect()
}

/// The scope map of one prefix transform.
fn transform_scopes(settings: Option<&Json>, field: &str) -> Vec<(String, Vec<String>)> {
    let Some(Json::Obj(scopes)) = settings.and_then(|settings| settings.get(field)) else {
        return Vec::new();
    };
    scopes
        .iter()
        .map(|(scope, names)| {
            (
                scope.clone(),
                names
                    .as_arr()
                    .map(|names| {
                        names
                            .iter()
                            .filter_map(Json::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        })
        .collect()
}

/// The anchors a verified Psiphon TLS dial uses, and whether the reference skips verification.
/// A named file is read at dial time so a config with no verified dial keeps working without it.
fn tls_trust_roots(settings: Option<&Json>) -> (crate::psiphon_ssh::TlsRoots, bool) {
    let disabled = flag(
        settings,
        "DisableSystemRootCAs",
        "AETHER_PSIPHON_DISABLE_SYSTEM_ROOT_CAS",
    );
    if disabled {
        return (crate::psiphon_ssh::TlsRoots::Empty, true);
    }
    if let Some(path) = text(settings, "TrustedCACertificatesFilename") {
        return (crate::psiphon_ssh::TlsRoots::File(path), false);
    }
    (crate::psiphon_ssh::TlsRoots::System, false)
}

/// The configured `LimitTLSProfiles` parrots, or the scalar `TLSProfile` when one is named.
fn tls_profiles(settings: Option<&Json>) -> Vec<Fingerprint> {
    let names = if settings
        .and_then(|settings| settings.get("LimitTLSProfiles"))
        .is_some()
    {
        string_list(settings, "LimitTLSProfiles")
    } else {
        text(settings, "TLSProfile").into_iter().collect()
    };
    names
        .iter()
        .filter_map(|name| Fingerprint::resolve(name))
        .collect()
}

/// `CustomTLSProfiles`: an array of named uTLS specs, each accepted profile immutable for the process.
fn custom_tls_profiles(settings: Option<&Json>) -> Vec<Fingerprint> {
    let Some(items) = settings
        .and_then(|settings| settings.get("CustomTLSProfiles"))
        .and_then(Json::as_arr)
    else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut profiles = Vec::new();
    for item in items {
        let Some(name) = text_in(item, "Name") else {
            eprintln!("psiphon: CustomTLSProfiles entry missing Name; ignoring it");
            continue;
        };
        if Fingerprint::resolve(&name).is_some() || !seen.insert(name.clone()) {
            eprintln!("psiphon: invalid or duplicate CustomTLSProfiles name {name:?}; ignoring it");
            continue;
        }
        let Some(spec) = item.get("UTLSSpec") else {
            eprintln!("psiphon: CustomTLSProfiles entry {name:?} missing UTLSSpec; ignoring it");
            continue;
        };
        let ciphers = u16_list(spec.get("CipherSuites"));
        if ciphers.is_empty() {
            eprintln!(
                "psiphon: CustomTLSProfiles entry {name:?} has no cipher suites; ignoring it"
            );
            continue;
        }
        let mut extensions = Vec::new();
        let mut valid = true;
        if let Some(items) = spec.get("Extensions").and_then(Json::as_arr) {
            for item in items {
                if let Some(extension) = custom_extension(item) {
                    extensions.push(extension);
                } else {
                    eprintln!(
                        "psiphon: CustomTLSProfiles entry {name:?} has an unknown extension; ignoring the profile"
                    );
                    valid = false;
                    break;
                }
            }
        }
        if !valid {
            continue;
        }
        let name: &'static str = Box::leak(name.into_boxed_str());
        let ciphers: &'static [u16] = Box::leak(ciphers.into_boxed_slice());
        let extensions: Vec<Ext> = extensions
            .into_iter()
            .map(|extension| Ext {
                kind: extension.kind,
                body: extension.body.leak(),
            })
            .collect();
        let extensions: &'static [Ext] = Box::leak(extensions.into_boxed_slice());
        let profile: &'static Profile = Box::leak(Box::new(Profile {
            name,
            ciphers,
            shuffle: false,
            exts: extensions,
        }));
        profiles.push(Fingerprint::custom(profile));
    }
    profiles
}

#[derive(Debug)]
struct CustomExtension {
    kind: u16,
    body: CustomBody,
}

#[derive(Debug)]
enum CustomBody {
    Grease,
    Sni,
    Pad,
    Groups(Vec<u16>),
    Sigalgs(Vec<u16>),
    Alpn(Vec<u8>),
    Versions(Vec<u16>),
    KeyShare(Vec<u16>),
    Raw(Vec<u8>),
}

impl CustomBody {
    fn leak(self) -> Body {
        match self {
            Self::Grease => Body::Grease,
            Self::Sni => Body::Sni,
            Self::Pad => Body::Pad,
            Self::Groups(groups) => Body::Groups(Box::leak(groups.into_boxed_slice())),
            Self::Sigalgs(sigalgs) => Body::Sigalgs(Box::leak(sigalgs.into_boxed_slice())),
            Self::Alpn(alpn) => Body::Alpn(Box::leak(alpn.into_boxed_slice())),
            Self::Versions(versions) => Body::Versions(Box::leak(versions.into_boxed_slice())),
            Self::KeyShare(groups) => Body::KeyShare {
                groups: Box::leak(groups.into_boxed_slice()),
                reuse: false,
            },
            Self::Raw(bytes) => Body::Raw(Box::leak(bytes.into_boxed_slice())),
        }
    }
}

fn custom_extension(item: &Json) -> Option<CustomExtension> {
    let name = item.get("Name")?.as_str()?;
    let data = item.get("Data");
    let (kind, body) = match name {
        "NPN" => (0x3374, CustomBody::Raw(Vec::new())),
        "SNI" => (0x0000, CustomBody::Sni),
        "StatusRequest" => (0x0005, CustomBody::Raw(vec![1, 0, 0, 0, 0])),
        "SupportedCurves" => (0x000a, CustomBody::Groups(u16_list(data?.get("Curves")))),
        "SupportedPoints" => {
            let points = u8_list(data?.get("SupportedPoints"));
            let mut body = Vec::with_capacity(1 + points.len());
            body.push(u8::try_from(points.len()).ok()?);
            body.extend_from_slice(&points);
            (0x000b, CustomBody::Raw(body))
        }
        "SignatureAlgorithms" => (
            0x000d,
            CustomBody::Sigalgs(u16_list(data?.get("SupportedSignatureAlgorithms"))),
        ),
        "RenegotiationInfo" => (0xff01, CustomBody::Raw(vec![0])),
        "ALPN" => (0x0010, CustomBody::Alpn(alpn_body(data?, "AlpnProtocols"))),
        "SCT" => (0x0012, CustomBody::Raw(Vec::new())),
        "SessionTicket" => (0x0023, CustomBody::Raw(Vec::new())),
        "Generic" => (
            u16::try_from(data?.get("Id")?.as_u32()?).ok()?,
            CustomBody::Raw(u8_list(data?.get("Data"))),
        ),
        "ExtendedMasterSecret" => (0x0017, CustomBody::Raw(Vec::new())),
        "GREASE" => (0x0a0a, CustomBody::Grease),
        "BoringPadding" => (0x0015, CustomBody::Pad),
        "KeyShare" => {
            let groups = data?
                .get("KeyShares")?
                .as_arr()?
                .iter()
                .filter_map(|share| share.get("Group").and_then(Json::as_u32))
                .filter_map(|group| u16::try_from(group).ok())
                .collect();
            (0x0033, CustomBody::KeyShare(groups))
        }
        "PSKKeyExchangeModes" => {
            let modes = u8_list(data?.get("Modes"));
            let mut body = Vec::with_capacity(1 + modes.len());
            body.push(u8::try_from(modes.len()).ok()?);
            body.extend_from_slice(&modes);
            (0x002d, CustomBody::Raw(body))
        }
        "SupportedVersions" => (
            0x002b,
            CustomBody::Versions(u16_list(data?.get("Versions"))),
        ),
        "ChannelID" => (
            if data
                .and_then(|data| data.get("OldExtensionID"))
                .and_then(Json::as_bool)
                .unwrap_or(false)
            {
                0x754f
            } else {
                0x7550
            },
            CustomBody::Raw(Vec::new()),
        ),
        "CertCompressionAlgs" => {
            let algorithms = u16_list(data?.get("Algorithms"));
            let mut body = Vec::with_capacity(1 + 2 * algorithms.len());
            body.push(u8::try_from(2 * algorithms.len()).ok()?);
            for algorithm in algorithms {
                body.extend_from_slice(&algorithm.to_be_bytes());
            }
            (0x001b, CustomBody::Raw(body))
        }
        "RecordSizeLimit" => {
            let limit = u16::try_from(data?.get("Limit")?.as_u32()?).ok()?;
            (0x001c, CustomBody::Raw(limit.to_be_bytes().to_vec()))
        }
        "ALPS" => (
            0x4469,
            CustomBody::Alpn(alpn_body_either(
                data?,
                "supported_protocols",
                "SupportedProtocols",
            )),
        ),
        "DelegatedCredentials" => {
            let algorithms = u16_list_either(
                data?,
                "supported_signature_algorithms",
                "SupportedSignatureAlgorithms",
            );
            let mut body = Vec::with_capacity(2 + 2 * algorithms.len());
            body.extend_from_slice(&u16::try_from(2 * algorithms.len()).ok()?.to_be_bytes());
            for algorithm in algorithms {
                body.extend_from_slice(&algorithm.to_be_bytes());
            }
            (0x0022, CustomBody::Raw(body))
        }
        _ => return None,
    };
    Some(CustomExtension { kind, body })
}

fn alpn_body(item: &Json, key: &str) -> Vec<u8> {
    let mut list = Vec::new();
    for protocol in string_list_in(item, key) {
        if let Ok(length) = u8::try_from(protocol.len()) {
            list.push(length);
            list.extend_from_slice(protocol.as_bytes());
        }
    }
    let mut body = Vec::with_capacity(2 + list.len());
    body.extend_from_slice(&u16::try_from(list.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(&list);
    body
}

fn alpn_body_either(item: &Json, first: &str, second: &str) -> Vec<u8> {
    if item.get(first).is_some() {
        alpn_body(item, first)
    } else {
        alpn_body(item, second)
    }
}

fn u16_list_either(item: &Json, first: &str, second: &str) -> Vec<u16> {
    u16_list(item.get(first).or_else(|| item.get(second)))
}

fn u16_list(value: Option<&Json>) -> Vec<u16> {
    value
        .and_then(Json::as_arr)
        .unwrap_or_default()
        .iter()
        .filter_map(Json::as_u32)
        .filter_map(|value| u16::try_from(value).ok())
        .collect()
}

fn u8_list(value: Option<&Json>) -> Vec<u8> {
    value
        .and_then(Json::as_arr)
        .unwrap_or_default()
        .iter()
        .filter_map(Json::as_u32)
        .filter_map(|value| u8::try_from(value).ok())
        .collect()
}

fn disable_fronting_profiles(settings: Option<&Json>) -> Vec<(String, Vec<String>)> {
    let Some(block) =
        settings.and_then(|settings| settings.get("DisableFrontingProviderTLSProfiles"))
    else {
        return Vec::new();
    };
    let Json::Obj(pairs) = block else {
        return Vec::new();
    };
    pairs
        .iter()
        .filter_map(|(provider, profiles)| {
            let profiles = profiles
                .as_arr()?
                .iter()
                .filter_map(Json::as_str)
                .map(str::trim)
                .filter(|profile| !profile.is_empty())
                .map(|profile| {
                    Fingerprint::resolve(profile)
                        .and_then(Fingerprint::name)
                        .map_or_else(|| profile.to_owned(), str::to_owned)
                })
                .collect::<Vec<_>>();
            (!profiles.is_empty()).then(|| (provider.clone(), profiles))
        })
        .collect()
}

fn protocol_list_named(settings: Option<&Json>, key: &str) -> Vec<String> {
    string_list(settings, key)
        .into_iter()
        .map(|protocol| protocol.to_ascii_uppercase())
        .collect()
}

/// The protocol limit the Android client derives from its connection mode.
fn selection_protocols(selection: Option<&str>) -> Vec<String> {
    let named = match selection {
        Some("cdn_fronting" | "fronted" | "fronted-meek" | "cdn") => CDN_FRONTING_PROTOCOLS,
        Some("direct") => DIRECT_PROTOCOLS,
        _ => return Vec::new(),
    };
    named
        .iter()
        .map(|protocol| (*protocol).to_owned())
        .collect()
}

/// Whether the Android client enables its CDN fronting overrides for this mode.
fn selection_enables_cdn(selection: Option<&str>) -> bool {
    matches!(
        selection,
        Some("auto" | "direct" | "cdn_fronting" | "fronted" | "fronted-meek" | "cdn")
    )
}

/// Whether the Android client disables tactics for this mode.
fn selection_disables_tactics(selection: Option<&str>) -> bool {
    matches!(
        selection,
        Some("direct" | "cdn_fronting" | "fronted" | "fronted-meek" | "cdn")
    )
}

fn protocol_list(settings: Option<&Json>) -> Vec<String> {
    let mut protocols = string_list(settings, "LimitTunnelProtocols");
    if protocols.is_empty() {
        protocols = string_list(settings, "limitTunnelProtocols");
    }
    if protocols.is_empty() {
        if let Some(single) = text(settings, "TunnelProtocol")
            .or_else(|| text(settings, "tunnelProtocol"))
            .or_else(|| text(settings, "tunnelProtocols"))
        {
            protocols = split_list(&single);
        }
    }
    protocols
        .into_iter()
        .map(|protocol| protocol.to_ascii_uppercase())
        .collect()
}

fn string_list(settings: Option<&Json>, key: &str) -> Vec<String> {
    let listed = settings.and_then(|settings| settings.get(key));
    if let Some(items) = listed.and_then(Json::as_arr) {
        return items
            .iter()
            .filter_map(Json::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(text) = listed.and_then(Json::as_str) {
        return split_list(text);
    }
    Vec::new()
}

/// The OSL roots, preferring the plural list and falling back to the legacy single URL.
fn osl_roots(settings: Option<&Json>) -> Vec<TransferRoot> {
    let global = custom_headers(settings);
    let mut roots = Vec::new();
    if let Some(Json::Arr(items)) = settings.and_then(|settings| {
        settings
            .get("ObfuscatedServerListRootURLs")
            .or_else(|| settings.get("obfuscatedServerListRootURLs"))
    }) {
        for item in items {
            match item {
                Json::Str(value) => {
                    if let Some(url) = transfer_url(value) {
                        roots.push(TransferRoot {
                            url,
                            skip_verify: false,
                            headers: global.clone(),
                        });
                    }
                }
                Json::Obj(fields) => {
                    let url = fields
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("URL"))
                        .and_then(|(_, value)| value.as_str())
                        .and_then(transfer_url);
                    let Some(url) = url else {
                        eprintln!("psiphon: ObfuscatedServerListRootURLs entry names no URL");
                        continue;
                    };
                    let skip_verify = fields
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("SkipVerify"))
                        .and_then(|(_, value)| value.as_bool())
                        .unwrap_or(false);
                    let local = fields
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("RequestHeaders"))
                        .map(|(_, value)| header_fields(value))
                        .unwrap_or_default();
                    let mut headers = global.clone();
                    headers.retain(|(name, _)| {
                        !local
                            .iter()
                            .any(|(added, _)| added.eq_ignore_ascii_case(name))
                    });
                    headers.extend(local);
                    roots.push(TransferRoot {
                        url,
                        skip_verify,
                        headers,
                    });
                }
                _ => eprintln!("psiphon: ObfuscatedServerListRootURLs entry is not an object"),
            }
        }
    }
    if roots.is_empty() {
        if let Some(root) = text(settings, "ObfuscatedServerListRootURL") {
            if let Some(url) = transfer_url(root.trim()) {
                roots.push(TransferRoot {
                    url,
                    skip_verify: false,
                    headers: global,
                });
            }
        }
    }
    roots
}

/// A TransferURL's URL is base64 encoded; plain HTTPS URLs are accepted for existing configs.
fn transfer_url(value: &str) -> Option<String> {
    let value = value.trim();
    if value.starts_with("https://") || value.starts_with("http://") {
        return Some(list_url(value));
    }
    let decoded = ferrox_core::b64::decode(value.as_bytes())?;
    let decoded = String::from_utf8(decoded).ok()?;
    (decoded.starts_with("https://") || decoded.starts_with("http://")).then(|| list_url(&decoded))
}

/// `ObfuscatedSSHAlgorithms` is [kex, cipher, mac, host key]; names this engine cannot carry keep the defaults.
fn ssh_algorithms(settings: Option<&Json>) -> Option<[String; 4]> {
    let names = string_list(settings, "ObfuscatedSSHAlgorithms");
    if names.is_empty() {
        return None;
    }
    let Ok([kex, cipher, mac, host]): Result<[String; 4], _> = names.try_into() else {
        eprintln!("psiphon: ObfuscatedSSHAlgorithms needs four names; using the defaults");
        return None;
    };
    let supported: [&[&str]; 4] = [
        &["curve25519-sha256", "curve25519-sha256@libssh.org"],
        &["aes128-ctr"],
        &["hmac-sha2-256"],
        &["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa", "ssh-ed25519"],
    ];
    for (name, allowed) in [&kex, &cipher, &mac, &host].into_iter().zip(supported) {
        if !allowed.contains(&name.as_str()) {
            eprintln!("psiphon: ObfuscatedSSHAlgorithms {name} is not carried; using the defaults");
            return None;
        }
    }
    Some([kex, cipher, mac, host])
}

fn header_fields(value: &Json) -> Vec<(String, String)> {
    let Json::Obj(fields) = value else {
        return Vec::new();
    };
    fields
        .iter()
        .flat_map(|(name, value)| match value {
            Json::Str(text) => vec![(name.clone(), text.clone())],
            Json::Arr(items) => items
                .iter()
                .filter_map(Json::as_str)
                .map(|text| (name.clone(), text.to_owned()))
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// Split-tunnel regions are ISO 3166-1 alpha-2 codes; accept either case and drop duplicates.
fn split_tunnel_regions(settings: Option<&Json>) -> Vec<String> {
    let mut regions = Vec::new();
    for region in string_list(settings, "SplitTunnelRegions") {
        let region = region.trim().to_ascii_uppercase();
        if region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase()) {
            push_unique(&mut regions, region);
        } else {
            eprintln!("psiphon: SplitTunnelRegions ignores {region:?}, not an ISO alpha-2 code");
        }
    }
    regions
}

fn custom_headers(settings: Option<&Json>) -> Vec<(String, String)> {
    let mut headers = header_map(settings, "CustomHeaders");
    if headers.is_empty() {
        headers = header_map(settings, "customHeaders");
    }
    if headers.is_empty() {
        headers = header_map(settings, "UpstreamProxyCustomHeaders");
    }
    merge_headers(headers, header_map(settings, "AdditionalCustomHeaders"))
}

/// The dial headers: `MeekAdditionalHeaders` with `AdditionalCustomHeaders` replacing a same name.
fn dial_headers(settings: Option<&Json>) -> Vec<(String, String)> {
    merge_headers(
        header_map(settings, "MeekAdditionalHeaders"),
        header_map(settings, "AdditionalCustomHeaders"),
    )
}

fn merge_headers(
    mut headers: Vec<(String, String)>,
    additional: Vec<(String, String)>,
) -> Vec<(String, String)> {
    if additional.is_empty() {
        return headers;
    }
    headers.retain(|(name, _)| {
        !additional
            .iter()
            .any(|(added, _)| added.eq_ignore_ascii_case(name))
    });
    headers.extend(additional);
    headers
}

fn header_map(settings: Option<&Json>, key: &str) -> Vec<(String, String)> {
    let Some(Json::Obj(fields)) = settings.and_then(|settings| settings.get(key)) else {
        return Vec::new();
    };
    fields
        .iter()
        .flat_map(|(name, value)| match value {
            Json::Str(text) => vec![(name.clone(), text.clone())],
            Json::Arr(items) => items
                .iter()
                .filter_map(Json::as_str)
                .map(|text| (name.clone(), text.to_owned()))
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// The reference's testing hook: base64 JSON laid over the caller's config.
fn merge_additional_parameters(settings: Option<&Json>) -> Result<Option<Json>, String> {
    let Some(raw) = settings.and_then(|settings| {
        settings
            .get("AdditionalParameters")
            .or_else(|| settings.get("additionalParameters"))
    }) else {
        return Ok(None);
    };
    let over = match raw {
        Json::Obj(_) => raw.clone(),
        Json::Str(text) => {
            let decoded = ferrox_core::b64::decode(text.as_bytes())
                .ok_or_else(|| "psiphon: AdditionalParameters is not base64".to_owned())?;
            let text = String::from_utf8(decoded)
                .map_err(|_| "psiphon: AdditionalParameters is not UTF-8".to_owned())?;
            crate::json::parse(&text)
                .map_err(|error| format!("psiphon: AdditionalParameters: {error}"))?
        }
        _ => return Err("psiphon: AdditionalParameters is not a string or object".to_owned()),
    };
    let Json::Obj(overrides) = over else {
        return Err("psiphon: AdditionalParameters is not a JSON object".to_owned());
    };
    let mut fields = match settings.cloned() {
        Some(Json::Obj(fields)) => fields,
        Some(_) => return Ok(Some(Json::Obj(overrides))),
        None => Vec::new(),
    };
    for (key, value) in overrides {
        if let Some((_, slot)) = fields.iter_mut().find(|(have, _)| *have == key) {
            *slot = value;
        } else {
            fields.push((key, value));
        }
    }
    Ok(Some(Json::Obj(fields)))
}

const KNOWN_SETTINGS: &[&str] = &[
    "listen",
    "shareProxyOnNetwork",
    "shareProxyOnNetworkSocksPort",
    "region",
    "egressRegion",
    "readySeconds",
    "serverList",
    "serverEntries",
    "state",
    "dataRootDirectory",
    "dataDirectory",
    "serverListURL",
    "serverListURLs",
    "serverListUrls",
    "remoteServerListURLs",
    "RemoteServerListURLs",
    "RemoteServerListUrl",
    "remoteServerListUrl",
    "serverListSignaturePublicKey",
    "remoteServerListSignaturePublicKey",
    "RemoteServerListSignaturePublicKey",
    "ServerEntrySignaturePublicKey",
    "FetchRemoteServerListRetryPeriodMilliseconds",
    "ObfuscatedServerListRootURLs",
    "obfuscatedServerListRootURLs",
    "ObfuscatedServerListRootURL",
    "EmitSLOKs",
    "EmitServerAlerts",
    "DisableRemoteServerListFetcher",
    "DisablePeriodicSshKeepAlive",
    "DisableKeepAlive",
    "SSHKeepAliveSpeedTestSampleProbability",
    "SSHKeepAlivePaddingMinBytes",
    "SSHKeepAlivePaddingMaxBytes",
    "SSHKeepAlivePeriodMinMilliseconds",
    "SSHKeepAlivePeriodMaxMilliseconds",
    "SSHKeepAlivePeriodicTimeoutMilliseconds",
    "SSHKeepAlivePeriodicInactivePeriodMilliseconds",
    "SSHKeepAliveProbeTimeoutMilliseconds",
    "SSHKeepAliveProbeInactivePeriodMilliseconds",
    "SSHKeepAliveNetworkConnectivityPollingPeriodMilliseconds",
    "SSHKeepAliveResetOnFailureProbability",
    "SSHKeepAliveResumeProbeTimeoutMilliseconds",
    "SSHKeepAliveResumeProbeInactivePeriodMilliseconds",
    "SSHKeepAliveResumeReconnectInactivePeriodMilliseconds",
    "LocalSocksProxyPort",
    "ListenInterface",
    "LocalHttpProxyPort",
    "shareProxyOnNetworkHttpPort",
    "DisableLocalSocksProxy",
    "DisableLocalHTTPProxy",
    "EgressRegion",
    "DataRootDirectory",
    "SponsorId",
    "SponsorID",
    "SessionID",
    "Authorizations",
    "sponsorId",
    "localProxyUsername",
    "LocalProxyUsername",
    "shareProxyOnNetworkUsername",
    "localProxyPassword",
    "LocalProxyPassword",
    "shareProxyOnNetworkPassword",
    "DisableTimeouts",
    "disableTunnels",
    "DisableTunnels",
    "upstreamProxy",
    "upstream",
    "UpstreamProxyURL",
    "UpstreamProxyUrl",
    "UpstreamProxyCustomHeaders",
    "UpstreamProxyAllowAllServerEntrySources",
    "protocolSelection",
    "beastMode",
    "AggressiveEstablishment",
    "aggressiveEstablishment",
    "TunnelPoolSize",
    "tunnelPoolSize",
    "ConnectionWorkerPoolSize",
    "ConnectionWorkerPoolMaxSize",
    "LimitIntensiveConnectionWorkers",
    "LimitCPUThreads",
    "DisableConnectionWorkerPool",
    "EstablishTunnelTimeoutSeconds",
    "TunnelConnectTimeoutSeconds",
    "CompressTactics",
    "ServerEntryIteratorMaxMoveToFront",
    "ServerEntryIteratorResetProbability",
    "RestrictDirectProviderIDsClientProbability",
    "RestrictDirectProviderRegions",
    "RestrictFrontingProviderIDs",
    "RestrictFrontingProviderIDsClientProbability",
    "RestrictInproxyProviderIDsClientProbability",
    "RestrictInproxyProviderRegions",
    "HoldOffDirectTunnelMinDurationMilliseconds",
    "HoldOffDirectTunnelMaxDurationMilliseconds",
    "HoldOffDirectTunnelProbability",
    "HoldOffDirectTunnelProviderRegions",
    "HoldOffFrontingTunnelMinDurationMilliseconds",
    "HoldOffFrontingTunnelMaxDurationMilliseconds",
    "HoldOffFrontingTunnelProbability",
    "HoldOffFrontingTunnelProviderIDs",
    "HoldOffInproxyTunnelMinDurationMilliseconds",
    "HoldOffInproxyTunnelMaxDurationMilliseconds",
    "HoldOffInproxyTunnelProbability",
    "HoldOffInproxyTunnelProviderRegions",
    "EstablishTunnelPausePeriodSeconds",
    "EstablishTunnelServerAffinityGracePeriodMilliseconds",
    "StaggerConnectionWorkersMilliseconds",
    "PropagationChannelId",
    "ClientPlatform",
    "ClientVersion",
    "DeviceRegion",
    "deviceRegion",
    "DeviceLocation",
    "deviceLocation",
    "ClientFeatures",
    "InproxyClientPersonalCompartmentID",
    "inproxyClientPersonalCompartmentID",
    "inproxyCompartment",
    "protocol_selection",
    "conduitMode",
    "conduit_mode",
    "conduitTimeout",
    "conduit_timeout",
    "ConduitTunnelProtocols",
    "conduitTunnelProtocols",
    "CONDUIT_TUNNEL_PROTOCOLS",
    "rejectCensoredCountryProxies",
    "InproxyRejectProxyCountryCodes",
    "rejectProxyCountryCodes",
    "GeoIPDatabasePath",
    "DNSResolverAlternateServers",
    "SteeringIPCacheTTLSeconds",
    "SteeringIPCacheMaxEntries",
    "SteeringIPProbability",
    "cdnProfile",
    "cdnIps",
    "cdnSni",
    "cdnSets",
    "FrontedMeekDialOverrides",
    "FrontedMeekDialOverridesProbability",
    "FrontedMeekCDNScanSpec",
    "frontedMeekCDNScanSpec",
    "FrontedMeekCDNScanUseBuiltInSpec",
    "FrontedMeekCDNScanBuiltInSets",
    "LimitMeekBufferSizes",
    "LimitRelayBufferSizes",
    "NetworkLatencyMultiplier",
    "NetworkLatencyMultiplierMin",
    "NetworkLatencyMultiplierMax",
    "NetworkLatencyMultiplierLambda",
    "InitialLimitTunnelProtocols",
    "InitialLimitTunnelProtocolsCandidateCount",
    "InitialLimitTunnelProtocolsProbability",
    "LimitTunnelProtocols",
    "LimitTunnelProtocolsProbability",
    "LimitTunnelDialPortNumbers",
    "limitTunnelDialPortNumbers",
    "LimitTunnelDialPortNumbersProbability",
    "PrioritizeTunnelProtocols",
    "PrioritizeTunnelProtocolsCandidateCount",
    "PrioritizeTunnelProtocolsProbability",
    "limitTunnelProtocols",
    "TunnelProtocol",
    "tunnelProtocol",
    "tunnelProtocols",
    "TargetServerEntry",
    "CustomHeaders",
    "customHeaders",
    "AdditionalCustomHeaders",
    "AdditionalParameters",
    "additionalParameters",
    "DisableTactics",
    "DisableReplay",
    "FrontedHTTPClientReplayDialParametersProbability",
    "FrontedHTTPClientReplayDialParametersTTLSeconds",
    "FrontedHTTPClientReplayRetainFailedProbability",
    "FrontedHTTPClientReplayUpdateFrequencySeconds",
    "InproxyReplayBrokerDialParametersProbability",
    "InproxyReplayBrokerDialParametersTTLSeconds",
    "InproxyReplayBrokerRetainFailedProbability",
    "InproxyReplayBrokerUpdateFrequencySeconds",
    "InproxyReplayRetainFailedProbability",
    "ReplayCandidateCount",
    "ReplayDialParametersTTLSeconds",
    "ReplayIgnoreChangedConfigStateProbability",
    "ReplayLaterRoundMoveToFrontProbability",
    "ReplayRetainFailedProbability",
    "ReplayTargetDownstreamBytes",
    "ReplayTargetTunnelDurationSeconds",
    "ReplayTargetUpstreamBytes",
    "MeekAdditionalHeaders",
    "SSHChannelWindowSize",
    "ClientBuildRev",
    "NetworkType",
    "ClientBurstUpstreamTargetBytes",
    "ClientBurstUpstreamDeadlineMilliseconds",
    "ClientBurstDownstreamTargetBytes",
    "ClientBurstDownstreamDeadlineMilliseconds",
    "EnableLightProxy",
    "LightProxyEntry",
    "LightProxyEntryTracker",
    "LightProxyDisable",
    "LightProxyTestFetchAddress",
    "LightProxyUseRecommendedSNIProbability",
    "LightProxyCustomHostNameProbability",
    "LightProxyCustomHostNameRegexes",
    "LightProxyTunnelInactiveThresholdMilliseconds",
    "LightProxyTunnelInactiveThreshold",
    "LightProxyDialTimeoutMilliseconds",
    "LightProxyDialTimeout",
    "LimitQUICVersions",
    "LimitTLSProfiles",
    "TLSProfile",
    "CustomTLSProfiles",
    "UseOnlyCustomTLSProfiles",
    "DisableFrontingProviderTLSProfiles",
    "QUICNoiseProfile",
    "InproxyRejectProxyCIDRs",
    "TLSTunnelMinTLSPadding",
    "TLSTunnelMaxTLSPadding",
    "MeekMinTLSPadding",
    "MeekMaxTLSPadding",
    "MeekTrafficShapingProbability",
    "MeekTrafficShapingLimitProtocols",
    "MeekMinLimitRequestPayloadLength",
    "MeekMaxLimitRequestPayloadLength",
    "MeekRedialTLSProbability",
    "MeekAlternateCookieNameProbability",
    "MeekAlternateContentTypeProbability",
    "MeekPayloadPaddingProbability",
    "MeekPayloadPaddingMinSize",
    "MeekPayloadPaddingMaxSize",
    "MeekPayloadPaddingOmitProbability",
    "TLSTunnelTrafficShapingProbability",
    "NoDefaultTLSSessionIDProbability",
    "TLSTunnelObfuscatedPSKProbability",
    "DisableSystemRootCAs",
    "TrustedCACertificatesFilename",
    "TLSFragmentClientHelloProbability",
    "TargetAPIEncoding",
    "TargetAPIProtocol",
    "ClientAPILevel",
    "DisableApi",
    "TLSFragmentClientHelloLimitProtocols",
    "PickUserAgentProbability",
    "QUICDialEarlyProbability",
    "QUICDisablePathMTUDiscoveryProbability",
    "QUICDisableClientPathMTUDiscoveryProbability",
    "QUICObfuscatedPSKProbability",
    "SelectRandomizedTLSProfileProbability",
    "TLSOSSHSNIServerName",
    "TLSOSSHSNIServerNames",
    "TransformHostNameProbability",
    "CustomHostNameRegexes",
    "CustomHostNameProbability",
    "CustomHostNameLimitProtocols",
    "SplitTunnelOwnRegion",
    "SplitTunnelRegions",
    "ShadowsocksPrefixSpecs",
    "ShadowsocksPrefixScopedSpecNames",
    "ShadowsocksPrefixProbability",
    "OSSHPrefixSpecs",
    "OSSHPrefixScopedSpecNames",
    "OSSHPrefixProbability",
    "OSSHPrefixSplitMinDelayMilliseconds",
    "OSSHPrefixSplitMaxDelayMilliseconds",
    "OSSHPrefixSplitMinDelay",
    "OSSHPrefixSplitMaxDelay",
    "OSSHObfuscatorSeedTransformProbability",
    "OSSHObfuscatorSeedTransformScopedSpecNames",
    "OSSHObfuscatorSeedTransformSpecs",
    "ObfuscatedQUICNonceTransformProbability",
    "ObfuscatedQUICNonceTransformScopedSpecNames",
    "ObfuscatedQUICNonceTransformSpecs",
    "DirectHTTPProtocolTransformProbability",
    "DirectHTTPProtocolTransformScopedSpecNames",
    "DirectHTTPProtocolTransformSpecs",
    "FrontedHTTPProtocolTransformProbability",
    "FrontedHTTPProtocolTransformScopedSpecNames",
    "FrontedHTTPProtocolTransformSpecs",
    "ObfuscatedSSHAlgorithms",
    "ObfuscatedSSHMinPadding",
    "ObfuscatedSSHMaxPadding",
    "RateLimits",
    "HoldOffTunnelProtocolMinDurationMilliseconds",
    "HoldOffTunnelProtocolMaxDurationMilliseconds",
    "HoldOffTunnelProtocolNames",
    "HoldOffTunnelProtocolProbability",
    "TacticsWaitPeriodMilliseconds",
    "TacticsRetryPeriodMilliseconds",
    "TacticsRetryPeriodJitter",
    "TacticsTimeoutMilliseconds",
    "InitialLivenessTest",
    "LivenessTest",
    "LivenessTestMinUpstreamBytes",
    "LivenessTestMaxUpstreamBytes",
    "LivenessTestMinDownstreamBytes",
    "LivenessTestMaxDownstreamBytes",
    "FragmentorProbability",
    "FragmentorLimitProtocols",
    "FragmentorMinTotalBytes",
    "FragmentorMaxTotalBytes",
    "FragmentorMinWriteBytes",
    "FragmentorMaxWriteBytes",
    "FragmentorMinDelayMicroseconds",
    "FragmentorMaxDelayMicroseconds",
    "OSSHPrefixEnableFragmentor",
    "DNSResolverAttemptsPerPreferredServer",
    "DNSResolverAttemptsPerServer",
    "DNSResolverAwaitTimeoutMilliseconds",
    "DNSResolverCacheExtensionInitialTTLMilliseconds",
    "DNSResolverCacheExtensionVerifiedTTLMilliseconds",
    "DNSResolverProtocolTransformProbability",
    "DNSResolverProtocolTransformScopedSpecNames",
    "DNSResolverProtocolTransformSpecs",
    "DNSResolverQNameMustMatchProbability",
    "DNSResolverIncludeEDNS0Probability",
    "DNSResolverPreferAlternateServerProbability",
    "DNSResolverPreferredAlternateServers",
    "DNSResolverPreresolvedIPAddressCIDRs",
    "DNSResolverPreresolvedIPAddressProbability",
    "DNSResolverQNameRandomizeCasingProbability",
    "DNSResolverRequestTimeoutMilliseconds",
];

/// Report settings fields this lane does not consume.
fn warn_ignored(settings: Option<&Json>) {
    let Some(Json::Obj(fields)) = settings else {
        return;
    };

    let ignored: Vec<&str> = fields
        .iter()
        .filter(|(key, _)| !KNOWN_SETTINGS.contains(&key.as_str()))
        .map(|(key, _)| key.as_str())
        .collect();
    if !ignored.is_empty() {
        eprintln!("psiphon: native engine ignores {}", ignored.join(", "));
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var_os(name)
        .and_then(|value| value.into_string().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn dns_server(text: &str) -> Option<SocketAddr> {
    let text = text.trim();
    text.parse::<SocketAddr>().ok().or_else(|| {
        text.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

/// The reference's `SessionID`: 32 lowercase hex digits, or one generated per client session.
fn client_session_id(settings: Option<&Json>) -> Option<String> {
    let session = text(settings, "SessionID")?;
    let valid = session.len() == 32
        && session
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        eprintln!("psiphon: SessionID must be 32 lowercase hex digits; generating one");
    }
    valid.then_some(session)
}

/// The `LightProxy` client settings, or `None` when the lane is not enabled.
fn light_settings(
    settings: Option<&Json>,
    tls_shape: &TlsShape,
    sponsor: &str,
    platform: &str,
    device_region: Option<&str>,
    session_id: Option<&str>,
) -> Option<crate::psiphon_light::Config> {
    if !flag(settings, "EnableLightProxy", "AETHER_PSIPHON_LIGHT_PROXY") {
        return None;
    }
    if flag(
        settings,
        "LightProxyDisable",
        "AETHER_PSIPHON_LIGHT_PROXY_DISABLE",
    ) {
        return None;
    }
    let Some(entry) =
        text(settings, "LightProxyEntry").or_else(|| env("AETHER_PSIPHON_LIGHT_PROXY_ENTRY"))
    else {
        eprintln!("psiphon: EnableLightProxy is set but LightProxyEntry is missing");
        return None;
    };
    let build_rev = text(settings, "ClientBuildRev")
        .or_else(|| env("AETHER_PSIPHON_BUILD_REV"))
        .unwrap_or_default();
    let network_type = text(settings, "NetworkType")
        .or_else(|| env("AETHER_PSIPHON_NETWORK_TYPE"))
        .unwrap_or_default();
    let test_fetch_address =
        text(settings, "LightProxyTestFetchAddress").filter(|address| address.contains(':'));
    Some(crate::psiphon_light::Config {
        entry,
        tracker: integer(settings, "LightProxyEntryTracker").unwrap_or(0),
        sponsor: sponsor.to_owned(),
        platform: platform.to_owned(),
        build_rev,
        device_region: device_region.map(str::to_owned),
        session_id: session_id.unwrap_or_default().to_owned(),
        network_type,
        recommended_probability: decimal(settings, "LightProxyUseRecommendedSNIProbability")
            .unwrap_or(0.5)
            .clamp(0.0, 1.0),
        custom_probability: decimal(settings, "LightProxyCustomHostNameProbability")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0),
        custom_hostnames: string_list(settings, "LightProxyCustomHostNameRegexes"),
        inactive: light_duration(
            settings,
            "LightProxyTunnelInactiveThresholdMilliseconds",
            "LightProxyTunnelInactiveThreshold",
            Duration::from_secs(30),
        ),
        dial_timeout: light_duration(
            settings,
            "LightProxyDialTimeoutMilliseconds",
            "LightProxyDialTimeout",
            Duration::from_secs(20),
        )
        .max(Duration::from_secs(1)),
        test_fetch_address,
        tls_shape: tls_shape.clone(),
    })
}

/// Read a millisecond setting, or the older duration spelling.
fn light_duration(
    settings: Option<&Json>,
    millis_key: &str,
    duration_key: &str,
    default: Duration,
) -> Duration {
    if let Some(millis) = number(settings, millis_key) {
        return Duration::from_millis(millis.min(600_000));
    }
    let Some(value) = settings.and_then(|settings| settings.get(duration_key)) else {
        return default;
    };
    if let Some(text) = value.as_str() {
        if let Some(duration) = go_duration(text) {
            return duration.min(Duration::from_secs(600));
        }
    }
    number(settings, duration_key).map_or(default, |nanos| {
        Duration::from_nanos(nanos).min(Duration::from_secs(600))
    })
}

/// The reference's `time.Duration` spellings that tactics use for these two knobs.
fn go_duration(text: &str) -> Option<Duration> {
    let text = text.trim();
    for (suffix, scale) in [
        ("ms", 1u64),
        ("ns", 0),
        ("s", 1_000),
        ("m", 60_000),
        ("h", 3_600_000),
    ] {
        if let Some(value) = text.strip_suffix(suffix) {
            let value = value.trim().parse::<u64>().ok()?;
            let millis = value.checked_mul(scale)?;
            return Some(if suffix == "ns" {
                Duration::from_nanos(value)
            } else {
                Duration::from_millis(millis)
            });
        }
    }
    None
}

fn text(settings: Option<&Json>, key: &str) -> Option<String> {
    settings
        .and_then(|settings| settings.get(key))
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn json_list(settings: Option<&Json>, key: &str) -> Vec<String> {
    let listed = settings.and_then(|settings| settings.get(key));
    if let Some(items) = listed.and_then(Json::as_arr) {
        return items
            .iter()
            .filter_map(|item| {
                item.as_str()
                    .or_else(|| item.get("URL").and_then(Json::as_str))
                    .or_else(|| item.get("url").and_then(Json::as_str))
            })
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(list_url)
            .collect();
    }
    if let Some(text) = listed.and_then(Json::as_str) {
        return split_list(text)
            .into_iter()
            .map(|url| list_url(&url))
            .collect();
    }
    Vec::new()
}

/// A list entry is a plain URL or, as the reference writes it, the base64 of one.
fn list_url(item: &str) -> String {
    if item.starts_with("http://") || item.starts_with("https://") {
        return item.to_owned();
    }
    ferrox_core::b64::decode(item.as_bytes())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .map_or_else(|| item.to_owned(), |url| url.trim().to_owned())
}

fn env_list(environment: &str) -> Vec<String> {
    env(environment)
        .map(|text| split_list(&text))
        .unwrap_or_default()
}

fn split_list(text: &str) -> Vec<String> {
    text.split([',', ' ', '\t', '\n', '\r', ';'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn flag(settings: Option<&Json>, key: &str, environment: &str) -> bool {
    settings
        .and_then(|settings| settings.get(key))
        .and_then(Json::as_bool)
        .unwrap_or_else(|| env_flag(environment))
}

fn env_flag(environment: &str) -> bool {
    env(environment).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn server_entries(settings: Option<&Json>) -> Option<PathBuf> {
    let path = text(settings, "serverList")
        .or_else(|| text(settings, "serverEntries"))
        .or_else(|| env("AETHER_PSIPHON_SERVER_ENTRIES"))
        .map(PathBuf::from)?;
    if path.is_file() {
        Some(path)
    } else {
        eprintln!("psiphon: server entries {} are not a file", path.display());
        None
    }
}

fn default_state() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(dir).join("ferrox/psiphon");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/state/ferrox/psiphon");
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        std::env::temp_dir().join(format!("ferrox-psiphon-{uid}"))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("ferrox-psiphon")
    }
}

fn listen_address(settings: Option<&Json>) -> Result<SocketAddr, String> {
    let share = flag(settings, "shareProxyOnNetwork", "AETHER_PSIPHON_SHARE");
    let private = flag(
        settings,
        "DisableLocalSocksProxy",
        "AETHER_PSIPHON_DISABLE_SOCKS_PROXY",
    );
    let explicit = text(settings, "listen").is_some() || env("AETHER_PSIPHON_BIND").is_some();
    let interface = text(settings, "ListenInterface");
    let text = text(settings, "listen")
        .or_else(|| env("AETHER_PSIPHON_BIND"))
        .or_else(|| {
            text(settings, "shareProxyOnNetworkSocksPort")
                .or_else(|| {
                    settings
                        .and_then(|settings| settings.get("shareProxyOnNetworkSocksPort"))
                        .and_then(Json::as_u32)
                        .map(|port| port.to_string())
                })
                .or_else(|| {
                    settings
                        .and_then(|settings| settings.get("LocalSocksProxyPort"))
                        .and_then(Json::as_u32)
                        .map(|port| port.to_string())
                })
                .map(|port| {
                    let ip = if share { "0.0.0.0" } else { "127.0.0.1" };
                    format!("{ip}:{port}")
                })
        })
        .unwrap_or_else(|| {
            if share {
                format!(
                    "0.0.0.0:{}",
                    ferrox_core::psiphon::DEFAULT_BIND
                        .rsplit_once(':')
                        .map_or("1821", |(_, port)| port)
                )
            } else {
                ferrox_core::psiphon::DEFAULT_BIND.to_owned()
            }
        });
    let address = if private {
        // The flag removes the reference's local SOCKS listener, but the embedded lane keeps an ephemeral loopback edge for its own outbound.
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    } else {
        let address = text
            .parse::<SocketAddr>()
            .map_err(|_| format!("psiphon: listen {text:?} is not an address and a port"))?;
        if explicit {
            address
        } else if let Some(interface) = interface {
            SocketAddr::new(interface_ip(&interface, address.ip()), address.port())
        } else {
            address
        }
    };
    Ok(if address.port() == 0 {
        SocketAddr::new(address.ip(), free_port(address.ip())?)
    } else {
        address
    })
}

fn interface_ip(interface: &str, fallback: IpAddr) -> IpAddr {
    if interface.eq_ignore_ascii_case("any") {
        return match fallback {
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
    }
    if let Ok(ip) = interface.parse() {
        return ip;
    }
    eprintln!("psiphon: ListenInterface {interface:?} is not an address; using {fallback}");
    fallback
}

fn free_port(ip: IpAddr) -> Result<u16, String> {
    let socket = TcpListener::bind(SocketAddr::new(ip, 0))
        .map_err(|error| format!("psiphon: no local port on {ip}: {error}"))?;
    socket
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("psiphon: the local port did not read back: {error}"))
}

/// The region codes the signed list publishes and how many entries each carries.
pub(crate) fn regions(settings: Option<&Json>) -> Result<Vec<(String, usize)>, String> {
    let settings = Settings::from_json(settings)?;
    let mut counts: BTreeMap<String, HashSet<IpAddr>> = BTreeMap::new();
    for server in load_all_entries(&settings)? {
        if let Some(region) = server.region {
            counts.entry(region).or_default().insert(server.address);
        }
    }
    Ok(counts
        .into_iter()
        .map(|(region, addresses)| (region, addresses.len()))
        .collect())
}

/// Fetch tactics from the first entry that advertises the untunneled capability.
pub(crate) fn tactics(settings: Option<&Json>) -> Result<crate::psiphon_tactics::Tactics, String> {
    let settings = Settings::from_json(settings)?;
    fetch_tactics(&settings)
}

fn compartment32(text: &str, what: &str) -> Result<[u8; 32], String> {
    ferrox_core::b64::decode(text.as_bytes())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("psiphon broker: {what} is not 32 base64 bytes"))
}

/// Create the local offer unless the caller supplied SDP.
fn webrtc_offer(
    address: IpAddr,
    stun_servers: &[String],
    sdp: Option<&str>,
    timeout: std::time::Duration,
    dns_config: &crate::psiphon_dns::Config,
    unreliable: bool,
) -> Result<(Option<crate::psiphon_webrtc::WebRtc>, String), String> {
    if let Some(sdp) = sdp {
        return Ok((None, sdp.to_owned()));
    }
    let (webrtc, sdp) = crate::psiphon_webrtc::WebRtc::offer(
        address,
        stun_servers,
        timeout,
        dns_config,
        unreliable,
    )?;
    Ok((Some(webrtc), sdp))
}

/// Apply the broker's answer and open the channel.
fn webrtc_conduit(
    webrtc: &mut crate::psiphon_webrtc::WebRtc,
    offer: &crate::psiphon_broker::Offer,
    timeout: std::time::Duration,
) -> Result<(), String> {
    if offer.answer_sdp.is_empty() {
        return Ok(());
    }
    webrtc.answer(&offer.answer_sdp)?;
    webrtc.await_channel(timeout)
}

/// Send a client offer to the first broker the tactics payload names.
pub(crate) fn broker_offer(
    settings: Option<&Json>,
    sdp: Option<&str>,
) -> Result<crate::psiphon_broker::Offer, String> {
    let settings = Settings::from_json(settings)?;
    if settings.disable_tactics {
        return Err(
            "psiphon: DisableTactics is set and no embedded tactics are bundled".to_owned(),
        );
    }
    if settings.proxy.is_some() && sdp.is_none() {
        eprintln!("psiphon broker: generated WebRTC uses direct UDP; the proxy carries only broker requests");
    }
    let servers = load_tactics_entries(&settings)?;
    let session_id = hex(&random::<16>());
    let tactics = fetch_tactics_from(&settings, &servers, &session_id)?;
    let broker = tactics
        .brokers
        .first()
        .ok_or_else(|| "psiphon broker: tactics names no broker".to_owned())?;
    let server = servers
        .iter()
        .find(|server| server.inproxy.is_some())
        .ok_or_else(|| "psiphon broker: no in-proxy destination".to_owned())?;
    let destination = server
        .inproxy
        .as_ref()
        .ok_or_else(|| "psiphon broker: no in-proxy destination".to_owned())?;
    let compartments: Vec<[u8; 32]> = tactics
        .compartments
        .iter()
        .map(|compartment| compartment32(compartment, "tactics compartment"))
        .collect::<Result<_, _>>()?;
    let personal: [u8; 32] = compartment32(&settings.compartment, "personal compartment")?;
    let identity = Identity {
        session_id: &session_id,
        authorizations: &settings.authorizations,
        sponsor: &settings.sponsor,
        propagation: &settings.propagation,
        platform: &settings.platform,
        version: &settings.client_version,
        egress_region: settings.region.as_deref(),
        device_region: settings.device_region.as_deref(),
        device_location: settings.device_location.as_deref(),
        client_features: &settings.client_features,
        split_tunnel: settings.split_tunnel_own_region,
        split_tunnel_regions: &settings.split_tunnel_regions,
        api_encoding: settings.api_encoding,
        compress_tactics: settings.compress_tactics,
        disable_api: settings.disable_api,
        ssh_algorithms: settings.ssh_algorithms.as_ref(),
    };
    let fronts = broker_fronts(broker);
    if fronts.is_empty() {
        return Err("psiphon broker: no fronting host".to_owned());
    }
    let mut why = String::new();
    for front in &fronts {
        let timeout = settings.ready.max(std::time::Duration::from_secs(20));
        let (mut webrtc, generated) = webrtc_offer(
            server.address,
            &tactics.stun_servers,
            sdp,
            timeout,
            &settings.dns,
            server.inproxy.as_ref().is_some_and(inproxy_uses_quic),
        )?;
        let mut client = match crate::psiphon_broker::Client::connect(
            crate::psiphon_broker::Broker {
                public_key: broker.public_key.clone(),
                root_secret: broker.root_secret.clone(),
            },
            front,
            settings.ready,
            settings.proxy.as_ref(),
            &settings.meek_headers,
            &settings.dns,
        ) {
            Ok(client) => client,
            Err(error) => {
                why = error;
                continue;
            }
        };
        match client.client_offer(
            destination,
            &compartments,
            &[personal],
            &generated,
            &crate::psiphon_broker::Metrics::from_identity(&identity),
        ) {
            Ok(offer) => {
                if let Some(webrtc) = webrtc.as_mut() {
                    if let Err(error) = webrtc_conduit(webrtc, &offer, timeout) {
                        why = error;
                        continue;
                    }
                }
                return Ok(offer);
            }
            Err(error) => why = error,
        }
    }
    Err(why)
}

fn fetch_tactics(settings: &Settings) -> Result<crate::psiphon_tactics::Tactics, String> {
    if settings.disable_tactics {
        return Err(
            "psiphon: DisableTactics is set and no embedded tactics are bundled".to_owned(),
        );
    }
    let servers = load_tactics_entries(settings)?;
    let session_id = hex(&random::<16>());
    fetch_tactics_from(settings, &servers, &session_id)
}

fn fetch_tactics_from(
    settings: &Settings,
    servers: &[Server],
    session_id: &str,
) -> Result<crate::psiphon_tactics::Tactics, String> {
    if settings.disable_tactics {
        return Err(
            "psiphon: DisableTactics is set and no embedded tactics are bundled".to_owned(),
        );
    }
    let server = servers
        .iter()
        .find(|server| server.tactics.is_some())
        .ok_or_else(|| "psiphon: the server list holds no tactics entry".to_owned())?;
    let identity = Identity {
        session_id,
        authorizations: &settings.authorizations,
        sponsor: &settings.sponsor,
        propagation: &settings.propagation,
        platform: &settings.platform,
        version: &settings.client_version,
        egress_region: settings.region.as_deref(),
        device_region: settings.device_region.as_deref(),
        device_location: settings.device_location.as_deref(),
        client_features: &settings.client_features,
        split_tunnel: settings.split_tunnel_own_region,
        split_tunnel_regions: &settings.split_tunnel_regions,
        api_encoding: settings.api_encoding,
        compress_tactics: settings.compress_tactics,
        disable_api: settings.disable_api,
        ssh_algorithms: settings.ssh_algorithms.as_ref(),
    };
    let timing = tactics_timing(settings.raw.as_ref());
    let timeout = timing.timeout.unwrap_or(settings.ready);
    let deadline = (!timing.wait.is_zero()).then(|| Instant::now() + timing.wait);
    loop {
        match crate::psiphon_tactics::Tactics::fetch(
            server,
            &identity,
            timeout,
            settings.proxy.as_ref(),
            &settings.dns,
            settings.compress_tactics,
        ) {
            Ok(tactics) => return Ok(tactics),
            Err(why) => {
                let Some(deadline) = deadline else {
                    return Err(why);
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(why);
                }
                let base = timing.retry.min(remaining);
                let span = f64::from(u16::from_be_bytes(random::<2>())) / 65_536.0;
                let delay = base.mul_f64(1.0 + timing.jitter * span).min(remaining);
                thread::sleep(delay);
            }
        }
    }
}

/// Decode every tactics compartment without echoing a value.
fn decode_compartments(compartments: &[String]) -> Result<Vec<[u8; 32]>, String> {
    compartments
        .iter()
        .map(|compartment| decode_compartment(compartment))
        .collect()
}

/// Decode one compartment without echoing a value.
fn decode_compartment(compartment: &str) -> Result<[u8; 32], String> {
    ferrox_core::b64::decode(compartment.as_bytes())
        .and_then(|compartment| compartment.try_into().ok())
        .ok_or_else(|| "psiphon: compartment is not 32 base64 bytes".to_owned())
}

fn broker_fronts(broker: &crate::psiphon_tactics::Broker) -> Vec<crate::psiphon_broker::Front> {
    let mut fronts = Vec::new();
    for front in &broker.fronts {
        let addresses = if front.addresses.is_empty() {
            vec![front.host.clone()]
        } else {
            front.addresses.clone()
        };
        for address in addresses {
            let Some((dial, port)) = split_dial(&address) else {
                eprintln!("psiphon broker: cannot dial {address}");
                continue;
            };
            let candidate = crate::psiphon_broker::Front {
                host: front.host.clone(),
                dial,
                port,
                disable_sni: front.disable_sni,
            };
            if !fronts
                .iter()
                .any(|existing: &crate::psiphon_broker::Front| {
                    existing.host == candidate.host
                        && existing.dial == candidate.dial
                        && existing.port == candidate.port
                })
            {
                fronts.push(candidate);
            }
        }
    }
    fronts
}

fn split_dial(address: &str) -> Option<(String, u16)> {
    let address = address.trim_matches(|ch| ch == '^' || ch == '$');
    if let Some(rest) = address.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':').and_then(|port| port.parse().ok());
        return Some((host.to_owned(), port.unwrap_or(443)));
    }
    if address.contains(['\\', '(', ')', '|', '+', '*', '?', '{', '}']) {
        return None;
    }
    if address.matches(':').count() > 1 {
        return Some((address.to_owned(), 443));
    }
    match address.rsplit_once(':') {
        Some((host, port)) => Some((host.to_owned(), port.parse().ok()?)),
        None => Some((address.to_owned(), 443)),
    }
}

fn load_entries(settings: &Settings) -> Result<Vec<Server>, String> {
    let servers = load_all_entries(settings)?;
    Ok(filter_region(servers, settings))
}

fn load_tactics_entries(settings: &Settings) -> Result<Vec<Server>, String> {
    let servers = load_source_entries(settings, false, true)?;
    let mut servers = filter_region(servers, settings);
    apply_session_settings(&mut servers, settings);
    apply_tactics_overrides(&mut servers, settings);
    if servers.is_empty() {
        return Err("psiphon: no usable server entries".to_owned());
    }
    Ok(servers)
}

/// Apply the settings that belong to every session rather than to one entry.
fn apply_session_settings(servers: &mut [Server], settings: &Settings) {
    for server in servers {
        server.channel_window = settings.ssh_channel_window;
        server.quic_noise.clone_from(&settings.quic_noise);
        for meek in [
            server.meek.as_mut(),
            server.unfronted_meek.as_mut(),
            server.inproxy_meek.as_mut(),
        ]
        .into_iter()
        .flatten()
        .chain(server.tactics.as_mut().map(|tactics| &mut tactics.meek))
        {
            meek.headers.clone_from(&settings.meek_headers);
            meek.dns.clone_from(&settings.dns_servers);
            meek.shape = settings.tls_shape.clone();
            (meek.shape.min_padding, meek.shape.max_padding) = settings.meek_padding;
        }
    }
}

fn filter_region(mut servers: Vec<Server>, settings: &Settings) -> Vec<Server> {
    if let Some(region) = settings.region.as_deref() {
        let regional: Vec<Server> = servers
            .iter()
            .filter(|server| server.region.as_deref() == Some(region))
            .cloned()
            .collect();
        if regional.is_empty() {
            eprintln!("psiphon: no server is in region {region}, using the whole list");
        } else {
            servers = regional;
        }
    }
    servers
}

fn load_all_entries(settings: &Settings) -> Result<Vec<Server>, String> {
    let servers = load_source_entries(settings, true, settings.conduit)?;
    let servers: Vec<Server> = servers
        .into_iter()
        .filter(|server| {
            server.direct
                || server.meek.is_some()
                || server.unfronted_meek.is_some()
                || (settings.conduit && server.inproxy.is_some())
        })
        .collect();
    let mut servers = if settings.target.is_some() {
        servers
    } else {
        let protocols: &[String] = if coin(settings.limit_protocols_probability) {
            &settings.protocols
        } else {
            &[]
        };
        let initial: &[String] = if coin(settings.initial_limit_probability) {
            &settings.initial_protocols
        } else {
            &[]
        };
        let initial_count = if initial.is_empty() {
            0
        } else {
            settings.initial_count
        };
        let dial_ports = if coin(settings.dial_ports_probability) {
            Some(settings.dial_ports.as_slice())
        } else {
            None
        };
        let mut selected = select_protocols_with(
            servers,
            protocols,
            initial,
            initial_count,
            settings.fronted,
            settings.fronted_fallback,
            dial_ports,
        );
        if coin(settings.prioritize_probability) {
            prioritize_servers(
                &mut selected,
                &settings.prioritize_protocols,
                settings.prioritize_count,
            );
        }
        selected
    };
    apply_session_settings(&mut servers, settings);
    apply_fronting_overrides_selected(&mut servers, settings);
    if servers.is_empty() {
        return Err("psiphon: no usable server entries".to_owned());
    }
    Ok(servers)
}

fn load_target_entry(
    settings: &Settings,
    target: &str,
    target_limits: bool,
    include_inproxy: bool,
) -> Result<Server, String> {
    let Some(server) =
        decode_entry_with(target.trim(), include_inproxy, &settings.conduit_protocols)
    else {
        return Err("psiphon: TargetServerEntry is not a valid server entry".to_owned());
    };
    let mut server = limit_quic_versions(vec![server], settings)
        .pop()
        .ok_or_else(|| {
            "psiphon: TargetServerEntry has no QUIC version allowed by LimitQUICVersions".to_owned()
        })?;
    if target_limits {
        let (limits, label, filter) = target_protocol_filter(settings);
        let named_meek = limits.iter().any(|protocol| is_meek_protocol(protocol));
        if let Some(shape) = filter {
            let shadowsocks_takes_over = shape.shadowsocks && server.shadowsocks.is_some();
            if shape.tls
                && !shape.plain
                && !shape.obfuscated
                && !shadowsocks_takes_over
                && server.tls_port.is_some()
                && (server.obfuscation_key.is_some() || server.tls_obfuscation_key.is_some())
            {
                if !server.tls {
                    server.inproxy = server.tls_inproxy.take();
                }
                server.tls = true;
                server.port = server.tls_port.unwrap_or(server.port);
                if server.obfuscation_key.is_none() {
                    server.obfuscation_key = server.tls_obfuscation_key.take();
                }
            }
            if !named_meek && server.direct {
                server.meek = None;
                server.unfronted_meek = None;
            }
            if shape.shadowsocks && !matches_limit(&server, shape, named_meek, limits) {
                if let Some(variant) = server.shadowsocks_variant() {
                    server = variant;
                }
            }
            if shape.quic && !matches_limit(&server, shape, named_meek, limits) {
                if let Some(variant) = server.quic_variant() {
                    server = variant;
                }
            }
            if !matches_limit(&server, shape, named_meek, limits) {
                let protocol = server.meek.as_ref().map_or_else(
                    || {
                        if server.ss {
                            "SHADOWSOCKS-OSSH"
                        } else if server.obfuscated() {
                            "OSSH"
                        } else {
                            "SSH"
                        }
                    },
                    |meek| meek.protocol,
                );
                return Err(format!(
                    "psiphon: TargetServerEntry is {protocol} but {label} ({}) leaves it out",
                    limits.join(",")
                ));
            }
        }
        if coin(settings.dial_ports_probability) {
            server = allowed_dial_variant(server, &settings.dial_ports, filter, named_meek, limits)
                .ok_or_else(|| {
                    "psiphon: TargetServerEntry has no dial port allowed by LimitTunnelDialPortNumbers"
                        .to_owned()
                })?;
        }
        server.scan_cdn = scan_allows(&server, limits);
    }
    Ok(server)
}

fn load_source_entries(
    settings: &Settings,
    target_limits: bool,
    include_inproxy: bool,
) -> Result<Vec<Server>, String> {
    if let Some(target) = settings.target.as_deref() {
        return Ok(vec![load_target_entry(
            settings,
            target,
            target_limits,
            include_inproxy,
        )?]);
    }
    let mut servers = Vec::new();
    let mut seen = HashSet::new();
    if let Some(path) = settings.entries.as_deref() {
        match std::fs::read_to_string(path) {
            Ok(text) => absorb(
                &text,
                &mut servers,
                &mut seen,
                include_inproxy,
                &settings.conduit_protocols,
            ),
            Err(error) => eprintln!("psiphon: server entries {}: {error}", path.display()),
        }
    }
    let fetch_remote =
        !settings.remote_fetch_disabled && (settings.server_lists_explicit || servers.is_empty());
    for url in settings.server_lists.iter().filter(|_| fetch_remote) {
        match fetch_list(
            url,
            &settings.server_list_key,
            &settings.headers,
            &settings.tls_shape.roots,
            settings.tls_shape.disable_system_root_cas,
        ) {
            Ok(text) => {
                absorb(
                    &text,
                    &mut servers,
                    &mut seen,
                    include_inproxy,
                    &settings.conduit_protocols,
                );
                save_cache(settings, &text);
            }
            Err(why) => eprintln!("psiphon: {why}"),
        }
    }
    if servers.is_empty() && state_is_ours(&settings.state) {
        if let Ok(text) = std::fs::read_to_string(cache_path(settings)) {
            absorb(
                &text,
                &mut servers,
                &mut seen,
                include_inproxy,
                &settings.conduit_protocols,
            );
        }
    }
    Ok(limit_quic_versions(servers, settings))
}

fn limit_quic_versions(mut servers: Vec<Server>, settings: &Settings) -> Vec<Server> {
    if settings.limit_quic_versions.is_empty() {
        return servers;
    }
    servers.retain_mut(|server| {
        let explicit = !server.quic_versions.is_empty();
        if explicit {
            server.quic_versions.retain(|version| {
                settings
                    .limit_quic_versions
                    .iter()
                    .any(|limit| limit == version)
            });
            if server.quic_versions.is_empty() {
                server.quic_port = None;
                if server.inproxy.as_ref().is_some_and(inproxy_uses_quic) {
                    server.inproxy = None;
                }
                if server.quic {
                    return false;
                }
            }
        } else {
            server
                .quic_versions
                .clone_from(&settings.limit_quic_versions);
        }
        let plain = server
            .quic_versions
            .iter()
            .any(|version| matches!(version.as_str(), "QUICv1" | "RANDOMIZED-QUICv1"));
        if !plain {
            if let Some(meek) = server.meek.as_mut().filter(|meek| meek.quic) {
                meek.quic = false;
                meek.protocol = match meek.protocol {
                    "FRONTED-MEEK-QUIC-OSSH" => "FRONTED-MEEK-OSSH",
                    "FRONTED-MEEK-CDN-QUIC-OSSH" => "FRONTED-MEEK-CDN-OSSH",
                    other => other,
                };
            }
            if server
                .inproxy
                .as_ref()
                .is_some_and(|destination| destination.base_protocol() == "FRONTED-MEEK-QUIC-OSSH")
            {
                server.inproxy = None;
            }
        }
        server.direct
            || server.ss
            || server.meek.is_some()
            || server.unfronted_meek.is_some()
            || server.tactics.is_some()
            || server.inproxy.is_some()
            || server.tls_inproxy.is_some()
    });
    servers
}

/// Whether a destination's tunnel runs over QUIC.
fn inproxy_uses_quic(destination: &crate::psiphon_broker::Destination) -> bool {
    matches!(
        destination.base_protocol(),
        "QUIC-OSSH" | "FRONTED-MEEK-QUIC-OSSH"
    )
}

#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct Shape {
    plain: bool,
    obfuscated: bool,
    tls: bool,
    shadowsocks: bool,
    quic: bool,
}

/// The shapes a protocol list names; `None` means the list asks for no restriction.
fn shape_filter(protocols: &[String], label: &str) -> Option<Shape> {
    if protocols.is_empty() {
        return None;
    }
    let mut shape = Shape {
        plain: false,
        obfuscated: false,
        tls: false,
        shadowsocks: false,
        quic: false,
    };
    let mut unsupported = Vec::new();
    for protocol in protocols {
        match protocol.as_str() {
            "SSH" | "UNFRONTED-SSH" => shape.plain = true,
            "TLS-OSSH" => shape.tls = true,
            "SHADOWSOCKS-OSSH" => shape.shadowsocks = true,
            "QUIC-OSSH" | "QUIC-OSSHV1" => shape.quic = true,
            "TAPDANCE-OSSH" | "CONJURE-OSSH" => shape.obfuscated = true,
            "OSSH"
            | "UNFRONTED-OSSH"
            | "UNFRONTED-MEEK-OSSH"
            | "UNFRONTED-MEEK-HTTPS-OSSH"
            | "UNFRONTED-MEEK-HTTP-OSSH"
            | "INPROXY-WEBRTC-OSSH"
            | "INPROXY-WEBRTC-QUIC-OSSH"
            | "INPROXY-WEBRTC-UNFRONTED-MEEK-OSSH"
            | "INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH"
            | "INPROXY-WEBRTC-UNFRONTED-MEEK-SESSION-TICKET-OSSH"
            | "INPROXY-WEBRTC-FRONTED-MEEK-OSSH"
            | "INPROXY-WEBRTC-FRONTED-MEEK-HTTP-OSSH"
            | "INPROXY-WEBRTC-FRONTED-MEEK-QUIC-OSSH"
            | "INPROXY-QUIC-OSSH"
            | "FRONTED-MEEK-OSSH"
            | "FRONTED-MEEK-CDN-OSSH"
            | "FRONTED-MEEK-HTTP-OSSH"
            | "FRONTED-MEEK-CDN-HTTP-OSSH"
            | "FRONTED-MEEK-QUIC-OSSH"
            | "FRONTED-MEEK-CDN-QUIC-OSSH" => {
                shape.obfuscated = true;
            }
            "INPROXY-WEBRTC-SHADOWSOCKS-OSSH" => {
                shape.obfuscated = true;
                shape.shadowsocks = true;
            }
            other => unsupported.push(other),
        }
    }
    if !unsupported.is_empty() {
        eprintln!("psiphon: {label} ignores {}", unsupported.join(","));
    }
    if !shape.plain && !shape.obfuscated && !shape.tls && !shape.shadowsocks && !shape.quic {
        eprintln!("psiphon: {label} names no SSH or OSSH shape; using the whole list");
        return None;
    }
    Some(shape)
}

fn matches_shape(server: &Server, shape: Shape) -> bool {
    if server.quic {
        shape.quic
    } else if server.ss {
        shape.shadowsocks
    } else if server.tls && server.meek.is_none() {
        shape.tls
    } else if server.obfuscated() {
        shape.obfuscated
    } else {
        shape.plain
    }
}

/// The protocol name without its CDN marker or OSSH suffix.
fn protocol_base(protocol: &str) -> String {
    let base = protocol.replace("-CDN", "");
    base.strip_suffix("-OSSH").unwrap_or(&base).to_owned()
}

/// Whether a protocol names a meek transport.
fn is_meek_protocol(protocol: &str) -> bool {
    protocol.starts_with("FRONTED-MEEK") || protocol.starts_with("UNFRONTED-MEEK")
}

/// The protocol shape an in-proxy name asks for, without its WebRTC and OSSH markers.
fn inproxy_base(protocol: &str) -> &str {
    let base = protocol
        .strip_prefix("INPROXY-WEBRTC-")
        .or_else(|| protocol.strip_prefix("INPROXY-"))
        .unwrap_or(protocol);
    base.strip_suffix("-OSSH").unwrap_or(base)
}

/// Whether a server is allowed by a limit that names no meek transport.
fn matches_direct_limit(server: &Server, shape: Shape, protocols: &[String]) -> bool {
    if !(server.direct || server.inproxy.is_some()) {
        return false;
    }
    let named_inproxy = protocols
        .iter()
        .any(|protocol| protocol.starts_with("INPROXY-"));
    if named_inproxy {
        if let Some(destination) = &server.inproxy {
            if protocols.iter().any(|protocol| {
                protocol.starts_with("INPROXY-")
                    && inproxy_base(protocol) == inproxy_base(destination.base_protocol())
            }) {
                return true;
            }
        }
        if !protocols
            .iter()
            .any(|protocol| !protocol.starts_with("INPROXY-"))
        {
            return false;
        }
    }
    if server.meek.is_some() {
        return false;
    }
    matches_shape(server, shape)
}

/// Whether a server is allowed by a limit, with a direct-only limit dropping every meek entry.
/// Whether a server the reference hands back at runtime still belongs to the selected lane.
fn entry_allowed(server: &Server, protocols: &[String], fronted: bool) -> bool {
    let normal = shape_filter(protocols, "LimitTunnelProtocols");
    if fronted {
        let shadowsocks_named = normal.is_some_and(|shape| shape.shadowsocks);
        let quic_named = normal.is_some_and(|shape| shape.quic);
        if !(server.meek.as_ref().is_some_and(|meek| meek.fronted)
            || (shadowsocks_named && server.ss)
            || (quic_named && server.quic_port.is_some()))
        {
            return false;
        }
    }
    normal.is_none_or(|filter| {
        matches_limit(
            server,
            filter,
            protocols.iter().any(|protocol| is_meek_protocol(protocol)),
            protocols,
        )
    })
}

fn matches_limit(server: &Server, filter: Shape, meek_named: bool, protocols: &[String]) -> bool {
    if meek_named {
        matches_shape(server, filter) && matches_meek_protocol(server, protocols)
    } else {
        matches_direct_limit(server, filter, protocols)
    }
}

/// Whether a server's meek protocol is named by the limit.
fn matches_meek_protocol(server: &Server, protocols: &[String]) -> bool {
    if server.quic {
        return protocols
            .iter()
            .any(|protocol| matches!(protocol.as_str(), "QUIC-OSSH" | "QUIC-OSSHV1"));
    }
    let Some(meek) = &server.meek else {
        if server.ss {
            return protocols
                .iter()
                .any(|protocol| protocol.as_str() == "SHADOWSOCKS-OSSH");
        }
        if server.tls {
            return protocols
                .iter()
                .any(|protocol| protocol.as_str() == "TLS-OSSH");
        }
        return protocols.iter().any(|protocol| {
            matches!(
                protocol.as_str(),
                "SSH" | "UNFRONTED-SSH" | "OSSH" | "UNFRONTED-OSSH"
            )
        });
    };
    let base = protocol_base(meek.protocol);
    let plain = base.strip_suffix("-QUIC").map(str::to_owned);
    protocols.iter().any(|protocol| {
        if !is_meek_protocol(protocol) {
            return false;
        }
        let named = protocol_base(protocol);
        named == base || plain.as_deref() == Some(named.as_str())
    })
}

fn target_protocol_filter(settings: &Settings) -> (&[String], &'static str, Option<Shape>) {
    if settings.initial_count > 0 && !settings.initial_protocols.is_empty() {
        let shape = shape_filter(&settings.initial_protocols, "InitialLimitTunnelProtocols");
        if shape.is_some() {
            return (
                &settings.initial_protocols,
                "InitialLimitTunnelProtocols",
                shape,
            );
        }
    }
    (
        &settings.protocols,
        "LimitTunnelProtocols",
        shape_filter(&settings.protocols, "LimitTunnelProtocols"),
    )
}

/// Apply configured fronting addresses and SNI names to matching servers.
#[derive(Clone, Copy)]
enum Front {
    Tunnel,
    Tactics,
}

impl Front {
    fn of(self, server: &Server) -> Option<&crate::psiphon_meek::Meek> {
        match self {
            Front::Tunnel => server.meek.as_ref(),
            Front::Tactics => server.tactics.as_ref().map(|tactics| &tactics.meek),
        }
    }

    fn present(self, server: &Server) -> bool {
        match self {
            Front::Tunnel => server.meek.is_some(),
            Front::Tactics => server.tactics.is_some(),
        }
    }
}

fn apply_fronting_overrides(servers: &mut Vec<Server>, settings: &Settings) {
    for server in servers.iter_mut() {
        server.scan_cdn = scan_allows(server, &settings.protocols);
    }
    apply_fronting_overrides_selected(servers, settings);
}

/// Apply the overrides with each candidate's own selection limit, so an
/// initial candidate and an unrestricted one keep separate scan eligibility.
fn apply_fronting_overrides_selected(servers: &mut Vec<Server>, settings: &Settings) {
    if !settings.fronted_overrides.is_empty() {
        servers.sort_by_key(|server| {
            let pinned = server.meek.as_ref().is_some_and(|meek| {
                let names = std::iter::once(&meek.host)
                    .chain(std::iter::once(&meek.dial))
                    .chain(meek.fronts.iter().map(|(front, _)| front));
                settings.fronted_overrides.iter().any(|fronted| {
                    fronted
                        .dials
                        .iter()
                        .chain(fronted.snis.iter())
                        .any(|wanted| names.clone().any(|name| name == wanted))
                })
            });
            !pinned
        });
    }
    expand_fronted(servers, settings, Front::Tunnel);
}

fn apply_tactics_overrides(servers: &mut Vec<Server>, settings: &Settings) {
    // Tactics fronts take their overrides without the tunnel protocol gate.
    expand_fronted(servers, settings, Front::Tactics);
}

/// Upstream's `TunnelProtocolUsesFrontedMeekCDN`: only CDN-suffixed fronted
/// meek tunnel protocols may take scan IPs and SNIs.
fn uses_fronted_meek_cdn(protocol: &str) -> bool {
    protocol.starts_with("FRONTED-MEEK") && protocol.contains("-CDN")
}

/// Whether the limit that selected this entry lets it take CDN scan candidates.
/// An empty limit (no restriction) does; a bare `FRONTED-MEEK-QUIC-OSSH`
/// limit keeps the fronting host its entry advertised.
fn scan_allows(server: &Server, protocols: &[String]) -> bool {
    if protocols.is_empty() {
        return true;
    }
    let Some(meek) = server.meek.as_ref() else {
        return true;
    };
    let base = protocol_base(meek.protocol);
    protocols
        .iter()
        .any(|protocol| uses_fronted_meek_cdn(protocol) && protocol_base(protocol) == base)
}

#[allow(clippy::too_many_lines)]
fn expand_fronted(servers: &mut Vec<Server>, settings: &Settings, front: Front) {
    if settings.cdn_ips.is_empty()
        && settings.cdn_snis.is_empty()
        && settings.fronted_overrides.is_empty()
    {
        return;
    }
    let mut groups: Vec<Vec<Server>> = Vec::with_capacity(servers.len());
    for server in servers.drain(..) {
        let Some(meek) = front.of(&server) else {
            groups.push(vec![server]);
            continue;
        };
        // CDN fronting includes the HTTP carrier, so HTTP fronts expand too.
        if !meek.fronted {
            groups.push(vec![server]);
            continue;
        }
        // Only entries the selected limit allows to scan take scan candidates.
        if matches!(front, Front::Tunnel) && !server.scan_cdn {
            groups.push(vec![server]);
            continue;
        }
        let mut group = Vec::with_capacity(FRONTED_VARIANTS.min(16));
        let mut variants = 0;
        if settings.cdn_ips.is_empty() && settings.cdn_snis.is_empty() {
            group.push(server.clone());
            variants += 1;
        }
        for fronted in &settings.fronted_overrides {
            if !fronted.matches(meek) {
                continue;
            }
            if let Some(id) = fronted.override_id.as_deref() {
                eprintln!("psiphon: applying fronted override {id}");
            }
            let dials: Vec<(String, u16)> = if fronted.dials.is_empty() {
                vec![(meek.dial.clone(), meek.port)]
            } else {
                fronted
                    .dials
                    .iter()
                    .map(|raw| split_fronting_address_with(raw, meek.port))
                    .collect()
            };
            add_fronted_variants(
                &server,
                &dials,
                &fronted.snis,
                fronted.disable_sni,
                &fronted.alpn,
                fronted.dials.is_empty(),
                &fronted.verify_server_names,
                &fronted.verify_pins,
                fronted.tls_profile.as_deref(),
                fronted.skip_cert_verify,
                front,
                true,
                &mut group,
                &mut variants,
            );
        }
        if !settings.cdn_ips.is_empty() || !settings.cdn_snis.is_empty() {
            let dials: Vec<(String, u16)> = if settings.cdn_ips.is_empty() {
                vec![(meek.dial.clone(), meek.port)]
            } else {
                settings
                    .cdn_ips
                    .iter()
                    .map(|raw| split_fronting_address_with(raw, meek.port))
                    .collect()
            };
            add_fronted_variants(
                &server,
                &dials,
                &settings.cdn_snis,
                meek.disable_sni,
                &[],
                settings.cdn_ips.is_empty(),
                &[],
                &[],
                None,
                false,
                front,
                false,
                &mut group,
                &mut variants,
            );
            if !settings.cdn_snis.is_empty() && !meek.disable_sni {
                add_fronted_variants(
                    &server,
                    &dials,
                    &[],
                    true,
                    &[],
                    settings.cdn_ips.is_empty(),
                    &[],
                    &[],
                    None,
                    false,
                    front,
                    false,
                    &mut group,
                    &mut variants,
                );
            }
        }
        if group.is_empty() {
            group.push(server);
        }
        groups.push(group);
    }
    let mut expanded = Vec::new();
    let mut fronted = 0;
    let depth = groups.iter().map(Vec::len).max().unwrap_or(0);
    for index in 0..depth {
        for group in &groups {
            let Some(server) = group.get(index) else {
                continue;
            };
            if front.present(server) {
                if fronted >= FRONTED_SERVERS {
                    continue;
                }
                fronted += 1;
            }
            expanded.push(server.clone());
        }
    }
    *servers = expanded;
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn add_fronted_variants(
    server: &Server,
    dials: &[(String, u16)],
    snis: &[String],
    disable_sni: bool,
    alpn: &[Vec<u8>],
    keep_candidates: bool,
    verify_server_names: &[String],
    verify_pins: &[String],
    tls_profile: Option<&str>,
    skip_cert_verify: bool,
    front: Front,
    override_rules: bool,
    expanded: &mut Vec<Server>,
    variants: &mut usize,
) {
    if snis.is_empty() || disable_sni {
        for (dial, port) in dials {
            if !push_fronted_variant(
                server,
                dial,
                *port,
                dial,
                disable_sni,
                alpn,
                keep_candidates,
                verify_server_names,
                verify_pins,
                tls_profile,
                skip_cert_verify,
                front,
                override_rules,
                expanded,
                variants,
            ) {
                return;
            }
        }
        return;
    }
    let pairs = dials.len().saturating_mul(snis.len());
    if pairs <= FRONTED_VARIANTS.saturating_sub(*variants) {
        for (dial, port) in dials {
            for sni in snis {
                if !push_fronted_variant(
                    server,
                    dial,
                    *port,
                    sni,
                    disable_sni,
                    alpn,
                    keep_candidates,
                    verify_server_names,
                    verify_pins,
                    tls_profile,
                    skip_cert_verify,
                    front,
                    override_rules,
                    expanded,
                    variants,
                ) {
                    return;
                }
            }
        }
        return;
    }
    // A candidate list wider than the cap still names every dial once.
    for (index, (dial, port)) in dials.iter().enumerate() {
        let sni = &snis[index % snis.len()];
        if !push_fronted_variant(
            server,
            dial,
            *port,
            sni,
            disable_sni,
            alpn,
            keep_candidates,
            verify_server_names,
            verify_pins,
            tls_profile,
            skip_cert_verify,
            front,
            override_rules,
            expanded,
            variants,
        ) {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn push_fronted_variant(
    server: &Server,
    dial: &str,
    port: u16,
    sni: &str,
    disable_sni: bool,
    alpn: &[Vec<u8>],
    keep_candidates: bool,
    verify_server_names: &[String],
    verify_pins: &[String],
    tls_profile: Option<&str>,
    skip_cert_verify: bool,
    front: Front,
    override_rules: bool,
    expanded: &mut Vec<Server>,
    variants: &mut usize,
) -> bool {
    if *variants >= FRONTED_VARIANTS {
        return false;
    }
    let mut variant = server.clone();
    let meek = match front {
        Front::Tunnel => variant
            .meek
            .as_mut()
            .expect("a fronted server carries a meek front"),
        Front::Tactics => {
            &mut variant
                .tactics
                .as_mut()
                .expect("a tactics server carries a tactics front")
                .meek
        }
    };
    let original_dial = meek.dial.clone();
    let original_sni = meek.sni.clone();
    dial.clone_into(&mut meek.dial);
    meek.port = port;
    if disable_sni {
        meek.sni.clear();
    } else {
        sni.clone_into(&mut meek.sni);
    }
    meek.disable_sni = disable_sni;
    if override_rules && !meek.https {
        // The plain-HTTP front consumes only the dial address and Host header.
        meek.sni.clear();
        meek.disable_sni = true;
    } else if override_rules && meek.quic && !meek.disable_sni && is_ip_literal(sni) {
        // A QUIC CDN edge reached by IP keeps a routable fronting name in SNI.
        let fallback = if is_ip_literal(&original_dial) {
            original_sni.as_str()
        } else {
            original_dial.as_str()
        };
        if !fallback.is_empty() && !is_ip_literal(fallback) {
            fallback.clone_into(&mut meek.sni);
        }
    }
    if !keep_candidates {
        meek.fronts = vec![(dial.to_owned(), port)];
        let host = meek.host.clone();
        meek.hosts = vec![host];
    }
    // The reference applies an override's ALPN to a TLS front; QUIC keeps its own h3 ALPN.
    if !alpn.is_empty() && meek.https && !meek.quic {
        meek.alpn = alpn.to_vec();
    }
    meek.verify_server_names = if skip_cert_verify || meek.quic || !meek.https {
        Vec::new()
    } else {
        verify_server_names.to_vec()
    };
    meek.verify_pins = if skip_cert_verify || meek.quic || !meek.https {
        Vec::new()
    } else {
        verify_pins.to_vec()
    };
    if let Some(profile) = tls_profile.filter(|_| meek.https && !meek.quic) {
        if let Some(fingerprint) = meek.shape.named_profile(profile) {
            meek.shape.forced_profile = Some(fingerprint);
            meek.shape.profiles = vec![fingerprint];
            meek.shape.randomized_probability = 0.0;
        } else {
            eprintln!("psiphon: unknown FrontedMeekDialOverrides TLSProfile {profile:?}");
        }
    }
    expanded.push(variant);
    *variants += 1;
    true
}

fn is_ip_literal(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn expand_cidr(raw: &str) -> Vec<String> {
    let Some((address, prefix)) = raw.split_once('/') else {
        return vec![raw.to_owned()];
    };
    let (Ok(address), Ok(prefix)) = (address.parse::<Ipv4Addr>(), prefix.parse::<u8>()) else {
        return vec![raw.to_owned()];
    };
    if prefix > 32 {
        return vec![raw.to_owned()];
    }
    let host_bits = u32::from(32 - prefix);
    let count = 1u64 << host_bits;
    let mask = if host_bits == 32 {
        0
    } else {
        u32::MAX << host_bits
    };
    let base = u32::from(address) & mask;
    let take = count.min(FRONTED_VARIANTS as u64);
    if count > take {
        eprintln!("psiphon: CIDR {raw} expands to {count} addresses; keeping {take}");
    }
    (0..take)
        .map(|offset| {
            Ipv4Addr::from(base.wrapping_add(u32::try_from(offset).unwrap_or(0))).to_string()
        })
        .collect()
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.iter().any(|existing| existing == &item) {
        list.push(item);
    }
}

fn bool_in(item: &Json, key: &str) -> bool {
    item.get(key).and_then(Json::as_bool).unwrap_or(false)
}

fn string_list_in(item: &Json, key: &str) -> Vec<String> {
    match item.get(key) {
        Some(Json::Arr(items)) => items
            .iter()
            .filter_map(Json::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Json::Str(text)) => split_list(text),
        _ => Vec::new(),
    }
}

fn text_in(item: &Json, key: &str) -> Option<String> {
    item.get(key)
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn regex_list_in(item: &Json, key: &str) -> Vec<regex::Regex> {
    string_list_in(item, key)
        .into_iter()
        .filter_map(|pattern| match regex::Regex::new(&pattern) {
            Ok(regex) => Some(regex),
            Err(error) => {
                eprintln!("psiphon: {key} {pattern:?}: {error}");
                None
            }
        })
        .collect()
}

/// Plain SSH and unfronted OSSH are the shapes this transport dials; a limit naming neither keeps the full list.
#[cfg(test)]
fn select_protocols(
    servers: Vec<Server>,
    protocols: &[String],
    initial_protocols: &[String],
    initial_count: usize,
    fronted: bool,
) -> Vec<Server> {
    select_protocols_with(
        servers,
        protocols,
        initial_protocols,
        initial_count,
        fronted,
        false,
        None,
    )
}

#[allow(clippy::too_many_lines)]
fn select_protocols_with(
    servers: Vec<Server>,
    protocols: &[String],
    initial_protocols: &[String],
    initial_count: usize,
    fronted: bool,
    fronted_fallback: bool,
    dial_ports: Option<&[(String, PortList)]>,
) -> Vec<Server> {
    let mut servers = servers;
    let normal = shape_filter(protocols, "LimitTunnelProtocols");
    let initial_active = initial_count > 0 && !initial_protocols.is_empty();
    let initial = shape_filter(initial_protocols, "InitialLimitTunnelProtocols");
    let shadowsocks_named = normal.is_some_and(|shape| shape.shadowsocks)
        || (initial_active && initial.is_some_and(|shape| shape.shadowsocks));
    let quic_named = normal.is_some_and(|shape| shape.quic)
        || (initial_active && initial.is_some_and(|shape| shape.quic));
    if fronted {
        let all = servers;
        let mut only: Vec<Server> = all
            .iter()
            .filter(|server| {
                server.meek.as_ref().is_some_and(|meek| meek.fronted)
                    || (shadowsocks_named && server.ss)
                    || (quic_named && server.quic_port.is_some())
            })
            .cloned()
            .collect();
        if only.is_empty() {
            eprintln!("psiphon: no server names a CDN front; using SSH/OSSH");
            servers = all;
        } else {
            servers = std::mem::take(&mut only);
        }
    } else {
        servers.retain_mut(|server| {
            if server.direct {
                server.meek = None;
                server.unfronted_meek = None;
                return true;
            }
            if server.inproxy.is_some() {
                server.meek = None;
                server.unfronted_meek = None;
                return true;
            }
            if server.meek.as_ref().is_some_and(|meek| !meek.fronted) {
                return true;
            }
            if let Some(unfronted) = server.unfronted_meek.take() {
                server.meek = Some(unfronted);
                return true;
            }
            fronted_fallback && server.meek.as_ref().is_some_and(|meek| meek.fronted)
        });
    }
    if quic_named {
        let variants: Vec<Server> = servers.iter().filter_map(Server::quic_variant).collect();
        servers.extend(variants);
    }
    if normal.is_none() && !initial_active && dial_ports.is_none() {
        return servers;
    }
    let tls_named = normal.is_some_and(|shape| shape.tls)
        || (initial_active && initial.is_some_and(|shape| shape.tls));
    if tls_named {
        add_tls_variants(&mut servers);
    }
    let normal_meek =
        normal.is_some() && protocols.iter().any(|protocol| is_meek_protocol(protocol));
    let initial_meek = initial_active
        && initial_protocols
            .iter()
            .any(|protocol| is_meek_protocol(protocol));
    let mut selected = Vec::new();
    let mut rest = Vec::new();
    for (index, server) in servers.iter().enumerate() {
        if initial_active
            && selected.len() < initial_count
            && initial.is_some_and(|filter| {
                matches_limit(server, filter, initial_meek, initial_protocols)
            })
        {
            selected.push(index);
        } else {
            rest.push(index);
        }
    }
    let initial_selected = selected.len();
    selected.extend(rest.into_iter().filter(|index| {
        let server = &servers[*index];
        normal.is_none_or(|filter| matches_limit(server, filter, normal_meek, protocols))
    }));
    if selected.is_empty() {
        if normal.is_some() {
            eprintln!(
                "psiphon: no server matches LimitTunnelProtocols ({}); refusing",
                protocols.join(",")
            );
            return Vec::new();
        }
        eprintln!("psiphon: initial protocol limit matched nothing; using the whole list");
        selected = (0..servers.len()).collect();
    }
    let selected: Vec<Server> = selected
        .into_iter()
        .enumerate()
        .map(|(position, index)| {
            let mut server = servers[index].clone();
            let limit = if position < initial_selected {
                initial_protocols
            } else {
                protocols
            };
            server.scan_cdn = scan_allows(&server, limit);
            server
        })
        .collect();
    match dial_ports {
        Some(limits) => apply_dial_port_limits(selected, limits, normal, normal_meek, protocols),
        None => selected,
    }
}

fn fronted_meek_dial_port(protocol: &str) -> Option<u16> {
    match protocol {
        "FRONTED-MEEK-HTTP-OSSH" | "FRONTED-MEEK-CDN-HTTP-OSSH" => Some(80),
        "FRONTED-MEEK-OSSH"
        | "FRONTED-MEEK-CDN-OSSH"
        | "FRONTED-MEEK-QUIC-OSSH"
        | "FRONTED-MEEK-CDN-QUIC-OSSH" => Some(443),
        _ => None,
    }
}

/// The protocol name and dial port a server currently presents.
fn server_dial_port(server: &Server) -> Option<(&str, u16)> {
    if let Some(meek) = server.meek.as_ref() {
        let port = fronted_meek_dial_port(meek.protocol)
            .filter(|_| meek.fronted)
            .unwrap_or(meek.port);
        return Some((meek.protocol, port));
    }
    if let Some(meek) = server.unfronted_meek.as_ref() {
        return Some((meek.protocol, meek.port));
    }
    if server.inproxy.is_some() || server.tls_inproxy.is_some() {
        return None;
    }
    if server.quic {
        return Some(("QUIC-OSSH", server.port));
    }
    if server.ss {
        return Some(("SHADOWSOCKS-OSSH", server.port));
    }
    if server.tls {
        return Some(("TLS-OSSH", server.port));
    }
    if server.obfuscated() {
        return Some(("OSSH", server.port));
    }
    Some(("SSH", server.port))
}

fn allowed_dial_port(limits: &[(String, PortList)], protocol: &str, port: u16) -> bool {
    limits
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(protocol))
        .or_else(|| {
            limits
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("ALL"))
        })
        .is_none_or(|(_, list)| list.contains(port))
}

/// The `LimitTunnelDialPortNumbers` filter: the current protocol or a sibling whose own port is allowed.
fn allowed_dial_variant(
    server: Server,
    limits: &[(String, PortList)],
    filter: Option<Shape>,
    meek_named: bool,
    protocols: &[String],
) -> Option<Server> {
    if let Some((protocol, port)) = server_dial_port(&server) {
        if allowed_dial_port(limits, protocol, port) {
            return Some(server);
        }
    } else {
        return Some(server);
    }
    let allowed = |variant: &Server, protocol: &str, port: u16| {
        allowed_dial_port(limits, protocol, port)
            && filter.is_none_or(|shape| matches_limit(variant, shape, meek_named, protocols))
    };
    if let Some(variant) = server.shadowsocks_variant() {
        if allowed(&variant, "SHADOWSOCKS-OSSH", variant.port) {
            return Some(variant);
        }
    }
    if let Some(variant) = server.quic_variant() {
        if allowed(&variant, "QUIC-OSSH", variant.port) {
            return Some(variant);
        }
    }
    if let Some(variant) = tls_variant(&server) {
        if allowed(&variant, "TLS-OSSH", variant.port) {
            return Some(variant);
        }
    }
    if let Some(variant) = ssh_variant(&server) {
        if allowed(&variant, "SSH", variant.port) {
            return Some(variant);
        }
    }
    if let Some(unfronted) = server.unfronted_meek.clone() {
        let mut variant = server.clone();
        variant.meek = Some(unfronted.clone());
        variant.unfronted_meek = None;
        if allowed(&variant, unfronted.protocol, unfronted.port) {
            return Some(variant);
        }
    }
    None
}

fn apply_dial_port_limits(
    servers: Vec<Server>,
    limits: &[(String, PortList)],
    filter: Option<Shape>,
    meek_named: bool,
    protocols: &[String],
) -> Vec<Server> {
    if limits.is_empty() {
        return servers;
    }
    let kept: Vec<Server> = servers
        .iter()
        .cloned()
        .filter_map(|server| allowed_dial_variant(server, limits, filter, meek_named, protocols))
        .collect();
    if kept.is_empty() {
        eprintln!("psiphon: LimitTunnelDialPortNumbers matched no server");
    }
    kept
}

/// The `PrioritizeTunnelProtocols` order: matching servers with an allowed port lead the list.
fn prioritize_servers(servers: &mut Vec<Server>, protocols: &[String], count: usize) {
    if protocols.is_empty() || count == 0 {
        return;
    }
    let mut priority = Vec::with_capacity(count.min(servers.len()));
    let mut rest = Vec::with_capacity(servers.len());
    for server in servers.drain(..) {
        let matches = server_dial_port(&server).is_some_and(|(protocol, _)| {
            protocols
                .iter()
                .any(|name| name.eq_ignore_ascii_case(protocol))
        });
        if matches && priority.len() < count {
            priority.push(server);
        } else {
            rest.push(server);
        }
    }
    priority.extend(rest);
    *servers = priority;
}

fn ssh_variant(server: &Server) -> Option<Server> {
    let port = server.ssh_port?;
    if !server.obfuscated() && !server.ss && !server.quic && !server.tls && server.port == port {
        return None;
    }
    let mut variant = server.clone();
    variant.port = port;
    variant.ssh_port = Some(port);
    variant.direct = true;
    variant.obfuscation_key = None;
    variant.tls_obfuscation_key = None;
    variant.meek_obfuscated_key = None;
    variant.tls = false;
    variant.tls_port = None;
    variant.quic = false;
    variant.quic_port = None;
    variant.ss = false;
    variant.shadowsocks = None;
    variant.meek = None;
    variant.unfronted_meek = None;
    variant.inproxy = None;
    variant.tls_inproxy = None;
    variant.inproxy_meek = None;
    variant.inproxy_shadowsocks_key = None;
    variant.tactics = None;
    Some(variant)
}

fn tls_variant(server: &Server) -> Option<Server> {
    if server.tls
        || server.quic
        || !server.direct
        || server.tls_port.is_none()
        || (server.obfuscation_key.is_none() && server.tls_obfuscation_key.is_none())
    {
        return None;
    }
    let mut variant = server.clone();
    if variant.obfuscation_key.is_none() {
        variant.obfuscation_key = variant.tls_obfuscation_key.clone();
    }
    variant.tls_obfuscation_key = None;
    variant.tls = true;
    variant.port = variant.tls_port.unwrap_or(variant.port);
    variant.meek = None;
    variant.unfronted_meek = None;
    variant.inproxy = variant.tls_inproxy.take();
    variant.tactics = None;
    Some(variant)
}

/// Add a TLS variant for each direct entry that names a TLS port.
fn add_tls_variants(servers: &mut Vec<Server>) {
    let variants: Vec<Server> = servers.iter().filter_map(tls_variant).collect();
    servers.extend(variants);
}

fn cache_path(settings: &Settings) -> PathBuf {
    settings.state.join("server_entries.txt")
}

#[cfg(unix)]
fn state_is_ours(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).is_ok_and(|meta| {
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0
    })
}

#[cfg(not(unix))]
fn state_is_ours(_: &Path) -> bool {
    true
}

fn save_cache(settings: &Settings, text: &str) {
    let path = cache_path(settings);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if state_is_ours(&settings.state) {
        let _ = std::fs::write(path, text);
    }
}

fn absorb(
    text: &str,
    servers: &mut Vec<Server>,
    seen: &mut HashSet<(IpAddr, u16)>,
    include_inproxy: bool,
    conduit_protocols: &[String],
) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(server) = decode_entry_with(line, include_inproxy, conduit_protocols) {
            let variant = server.shadowsocks_variant();
            if seen.insert((server.address, server.port)) {
                servers.push(server);
            }
            if let Some(variant) = variant {
                if seen.insert((variant.address, variant.port)) {
                    servers.push(variant);
                }
            }
        }
    }
}

/// The reference's `IsBogon`: an address no handshake steering IP should name.
fn is_bogon(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => is_bogon_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return is_bogon_v4(ip);
            }
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

fn is_bogon_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
        || octets[0] >= 240
}

/// Decode one base64 server-list entry for the tunnel race.
#[cfg(test)]
fn decode_entry(line: &str) -> Option<Server> {
    decode_entry_with(line, false, &[])
}

/// The port an in-proxy destination names.
fn destination_port(destination: &crate::psiphon_broker::Destination) -> u16 {
    destination
        .address
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or(443)
}

/// The ports and keys one server entry names.
struct EntryPorts {
    obfuscated: Option<u16>,
    obfuscated_key: Option<String>,
    meek_key: Option<String>,
    ssh: Option<u16>,
    tls: Option<u16>,
}

/// Read the direct, meek and TLS ports from one entry.
fn entry_ports(entry: &Json) -> EntryPorts {
    let obfuscated = entry
        .get("sshObfuscatedPort")
        .and_then(Json::as_port)
        .filter(|port| *port > 0);
    let obfuscated_key = entry
        .get("sshObfuscatedKey")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .filter(|key| !key.is_empty());
    let meek_key = entry
        .get("meekObfuscatedKey")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .filter(|key| !key.is_empty());
    let ssh = entry
        .get("sshPort")
        .and_then(Json::as_port)
        .filter(|port| *port > 0);
    let tls = entry
        .get("tlsOSSHPort")
        .and_then(Json::as_port)
        .filter(|port| *port > 0)
        .or_else(|| {
            capability_protocol(entry, &[("TLS-OSSH", "TLS-OSSH")])?;
            entry
                .get("meekServerPort")
                .and_then(Json::as_port)
                .filter(|port| *port > 0)
        });
    EntryPorts {
        obfuscated,
        obfuscated_key,
        meek_key,
        ssh,
        tls,
    }
}

/// Decode one base64 server-list entry, optionally keeping an in-proxy-only one.
#[allow(clippy::too_many_lines)]
fn decode_entry_with(
    line: &str,
    include_inproxy: bool,
    conduit_protocols: &[String],
) -> Option<Server> {
    let decoded = hex_decode(line)?;
    let parts: Vec<&[u8]> = decoded.splitn(5, |byte| *byte == b' ').collect();
    if parts.len() != 5 {
        return None;
    }
    let entry = json::parse(&String::from_utf8_lossy(parts[4])).ok()?;
    let host = entry.get("ipAddress").and_then(Json::as_str)?;
    let address = host.parse::<IpAddr>().ok()?;
    let host = host.to_owned();
    let host_key =
        ferrox_core::b64::decode(entry.get("sshHostKey").and_then(Json::as_str)?.as_bytes())?;
    let user = entry
        .get("sshUsername")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    let password = entry
        .get("sshPassword")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    let EntryPorts {
        obfuscated: obfuscated_port,
        obfuscated_key,
        meek_key: meek_obfuscated_key,
        ssh: ssh_port,
        tls: tls_port,
    } = entry_ports(&entry);
    let quic_port = entry
        .get("sshObfuscatedQUICPort")
        .and_then(Json::as_port)
        .filter(|port| *port > 0);
    let quic_versions = entry
        .get("limitQUICVersions")
        .and_then(Json::as_arr)
        .map(|versions| {
            versions
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let tls_obfuscation_key = obfuscated_key.clone();
    let shadowsocks_key = entry
        .get("sshShadowsocksKey")
        .and_then(Json::as_str)
        .filter(|key| !key.is_empty())
        .map(str::to_owned);
    let shadowsocks = entry
        .get("sshShadowsocksPort")
        .and_then(Json::as_port)
        .filter(|port| *port > 0)
        .zip(shadowsocks_key.clone())
        .map(|(port, key)| crate::psiphon_ssh::Shadowsocks {
            port,
            key,
            obfuscation_key: obfuscated_key.clone(),
        });
    let protocol = meek_protocol(&entry);
    let tactics_capable = tactics_capability(&entry);
    let direct = obfuscated_port.is_some()
        || ssh_port.is_some()
        || quic_port.is_some()
        || (tls_port.is_some() && obfuscated_key.is_some());
    let inproxy = crate::psiphon_broker::destination(&entry, &host, false, conduit_protocols);
    let tls_inproxy = crate::psiphon_broker::destination(&entry, &host, true, conduit_protocols);
    let inproxy_meek = inproxy.as_ref().and_then(|destination| {
        let base = destination.base_protocol();
        (base.starts_with("UNFRONTED-MEEK")
            || matches!(
                base,
                "FRONTED-MEEK-OSSH" | "FRONTED-MEEK-HTTP-OSSH" | "FRONTED-MEEK-QUIC-OSSH"
            ))
        .then(|| meek_entry(&entry, &host, base))
        .flatten()
    });
    let inproxy_port = inproxy
        .as_ref()
        .or(tls_inproxy.as_ref())
        .map_or(0, destination_port);
    let (port, obfuscation_key, tls, ss, quic_base) = match (obfuscated_port, ssh_port) {
        (Some(port), _) if obfuscated_key.is_some() => (port, obfuscated_key, false, false, false),
        (_, Some(port)) => (port, None, false, false, false),
        _ if tls_port.is_some() && obfuscated_key.is_some() => {
            (tls_port.unwrap_or(0), obfuscated_key, true, false, false)
        }
        _ if protocol.is_some() || tactics_capable => {
            let port = entry
                .get("meekServerPort")
                .and_then(Json::as_port)
                .filter(|port| *port > 0)
                .unwrap_or_else(|| {
                    if protocol.is_some_and(|protocol| protocol.contains("-HTTP-")) {
                        80
                    } else {
                        443
                    }
                });
            (port, obfuscated_key, false, false, false)
        }
        _ if include_inproxy && (inproxy.is_some() || tls_inproxy.is_some()) => {
            (inproxy_port, obfuscated_key, false, false, false)
        }
        _ if shadowsocks.is_some() => {
            let ss = shadowsocks.as_ref()?;
            (ss.port, ss.obfuscation_key.clone(), false, true, false)
        }
        _ if quic_port.is_some() => (quic_port.unwrap_or(0), obfuscated_key, false, false, true),
        _ => return None,
    };
    let quic = quic_base
        && obfuscated_port.is_none()
        && ssh_port.is_none()
        && tls_port.is_none()
        && shadowsocks.is_none();
    let direct = direct || ss;
    let (inproxy, tls_inproxy, tls) = if tls {
        (tls_inproxy, None, true)
    } else if inproxy.is_none() && !direct {
        let tls = tls_inproxy.is_some();
        (tls_inproxy, None, tls)
    } else {
        (inproxy, tls_inproxy, false)
    };
    let tls_obfuscation_key = if tls_port.is_some() && obfuscation_key.is_none() {
        tls_obfuscation_key
    } else {
        None
    };
    let region = entry
        .get("region")
        .and_then(Json::as_str)
        .map(str::to_owned);
    let provider_id = entry
        .get("providerID")
        .and_then(Json::as_str)
        .filter(|provider| !provider.is_empty())
        .map(str::to_owned);
    let fronting_provider_id = entry
        .get("frontingProviderID")
        .and_then(Json::as_str)
        .filter(|provider| !provider.is_empty())
        .map(str::to_owned);
    let mut meek = protocol.and_then(|protocol| meek_entry(&entry, &host, protocol));
    let mut unfronted_meek = protocol
        .filter(|protocol| protocol.starts_with("FRONTED-MEEK"))
        .and_then(|_| unfronted_meek_protocol(&entry))
        .and_then(|protocol| meek_entry(&entry, &host, protocol));
    if meek.is_none() {
        meek = unfronted_meek.take();
    }
    let tactics = tactics_entry(&entry, &host);
    if !direct
        && meek.is_none()
        && unfronted_meek.is_none()
        && tactics.is_none()
        && inproxy.is_none()
    {
        return None;
    }
    let ssh_api = entry
        .get("capabilities")
        .and_then(Json::as_arr)
        .is_some_and(|capabilities| {
            capabilities
                .iter()
                .filter_map(Json::as_str)
                .any(|capability| capability == "ssh-api-requests")
        });
    Some(Server {
        host,
        address,
        port,
        ssh_port,
        user,
        password,
        host_key,
        obfuscation_key,
        tls_obfuscation_key,
        meek_obfuscated_key,
        region,
        provider_id,
        fronting_provider_id,
        scan_cdn: true,
        ssh_api,
        direct,
        tls,
        tls_port,
        quic,
        quic_port,
        quic_versions,
        quic_noise: None,
        ss,
        shadowsocks,
        meek,
        unfronted_meek,
        inproxy_meek,
        tactics,
        inproxy,
        tls_inproxy,
        inproxy_shadowsocks_key: shadowsocks_key,
        channel_window: crate::psiphon_ssh::DEFAULT_CHANNEL_WINDOW,
    })
}

/// Whether an entry advertises the untunneled tactics capability.
fn tactics_capability(entry: &Json) -> bool {
    entry
        .get("capabilities")
        .and_then(Json::as_arr)
        .is_some_and(|capabilities| {
            capabilities
                .iter()
                .filter_map(Json::as_str)
                .any(|name| name == "FRONTED-MEEK-TACTICS")
        })
}

/// The keys and front a `FRONTED-MEEK-TACTICS` entry needs for a tactics request.
fn tactics_entry(entry: &Json, host: &str) -> Option<crate::psiphon_tactics::Keys> {
    if !tactics_capability(entry) {
        return None;
    }
    let public_key = entry
        .get("tacticsRequestPublicKey")
        .and_then(Json::as_str)
        .filter(|key| !key.is_empty())?
        .to_owned();
    let obfuscated_key = entry
        .get("tacticsRequestObfuscatedKey")
        .and_then(Json::as_str)
        .filter(|key| !key.is_empty())?
        .to_owned();
    let meek = meek_entry(entry, host, "FRONTED-MEEK-OSSH")?;
    Some(crate::psiphon_tactics::Keys {
        public_key,
        obfuscated_key,
        meek,
    })
}

/// A capability name with the legacy mask and CDN marker removed, as the reference matches it.
fn capability_name(name: &str) -> Cow<'_, str> {
    if !name.contains("-PASSTHROUGH")
        && name != "QUICv1"
        && !name.ends_with("-OSSH")
        && !matches!(
            name,
            "FRONTED-MEEK-CDN" | "FRONTED-MEEK-CDN-HTTP" | "FRONTED-MEEK-CDN-QUIC"
        )
    {
        return Cow::Borrowed(name);
    }
    let stripped = name
        .replace("-PASSTHROUGH-v2", "")
        .replace("-PASSTHROUGH", "");
    if stripped == "QUICv1" {
        return Cow::Owned("QUIC".to_owned());
    }
    let base = match stripped.as_str() {
        "FRONTED-MEEK-CDN" => "FRONTED-MEEK",
        "FRONTED-MEEK-CDN-HTTP" => "FRONTED-MEEK-HTTP",
        "FRONTED-MEEK-CDN-QUIC" => "FRONTED-MEEK-QUIC",
        other => other,
    };
    Cow::Owned(base.strip_suffix("-OSSH").unwrap_or(base).to_owned())
}

/// Whether one advertised capability satisfies a required one.
fn capability_matches(advertised: &str, required: &str) -> bool {
    let required = capability_name(required);
    capability_name(advertised) == required
        || (required.as_ref() == "TLS"
            && matches!(
                advertised,
                "UNFRONTED-MEEK-HTTPS-PASSTHROUGH-v2"
                    | "UNFRONTED-MEEK-SESSION-TICKET-PASSTHROUGH-v2"
            ))
}

/// The capability name an entry advertises for a tunnel protocol.
fn capability_protocol(entry: &Json, candidates: &[(&str, &'static str)]) -> Option<&'static str> {
    let capabilities = entry.get("capabilities").and_then(Json::as_arr)?;
    candidates.iter().find_map(|(name, protocol)| {
        capabilities
            .iter()
            .filter_map(Json::as_str)
            .any(|advertised| capability_matches(advertised, name))
            .then_some(*protocol)
    })
}

/// The fronted or unfronted meek capability an entry offers.
fn meek_protocol(entry: &Json) -> Option<&'static str> {
    let protocol = capability_protocol(
        entry,
        &[
            ("FRONTED-MEEK-QUIC", "FRONTED-MEEK-QUIC-OSSH"),
            ("FRONTED-MEEK-CDN-QUIC", "FRONTED-MEEK-CDN-QUIC-OSSH"),
            ("FRONTED-MEEK", "FRONTED-MEEK-OSSH"),
            ("FRONTED-MEEK-HTTP", "FRONTED-MEEK-HTTP-OSSH"),
            ("UNFRONTED-MEEK-HTTPS", "UNFRONTED-MEEK-HTTPS-OSSH"),
            ("UNFRONTED-MEEK", "UNFRONTED-MEEK-OSSH"),
        ],
    );
    if matches!(
        protocol,
        Some("FRONTED-MEEK-QUIC-OSSH" | "FRONTED-MEEK-CDN-QUIC-OSSH")
    ) && !fronted_quic_supported(entry)
    {
        return capability_protocol(
            entry,
            &[
                ("FRONTED-MEEK", "FRONTED-MEEK-OSSH"),
                ("FRONTED-MEEK-HTTP", "FRONTED-MEEK-HTTP-OSSH"),
                ("UNFRONTED-MEEK-HTTPS", "UNFRONTED-MEEK-HTTPS-OSSH"),
                ("UNFRONTED-MEEK", "UNFRONTED-MEEK-OSSH"),
            ],
        );
    }
    protocol
}

/// Whether an entry names a plain IETF QUIC version HTTP/3 can carry.
pub(crate) fn fronted_quic_supported(entry: &Json) -> bool {
    let Some(versions) = entry.get("limitQUICVersions").and_then(Json::as_arr) else {
        return true;
    };
    versions
        .iter()
        .filter_map(Json::as_str)
        .any(|version| matches!(version, "QUICv1" | "RANDOMIZED-QUICv1"))
}

/// The unfronted meek capability an entry also offers.
fn unfronted_meek_protocol(entry: &Json) -> Option<&'static str> {
    capability_protocol(
        entry,
        &[
            ("UNFRONTED-MEEK-HTTPS", "UNFRONTED-MEEK-HTTPS-OSSH"),
            ("UNFRONTED-MEEK", "UNFRONTED-MEEK-OSSH"),
        ],
    )
}

/// The cookie-encryption and obfuscation keys a meek entry requires.
fn meek_keys(entry: &Json) -> Option<(String, String)> {
    let public_key = entry
        .get("meekCookieEncryptionPublicKey")
        .and_then(Json::as_str)
        .filter(|key| !key.is_empty())?
        .to_owned();
    let obfuscated_key = entry
        .get("meekObfuscatedKey")
        .and_then(Json::as_str)
        .filter(|key| !key.is_empty())?
        .to_owned();
    Some((public_key, obfuscated_key))
}

/// The Host header candidates and the first dial host for a meek entry.
fn meek_hosts(entry: &Json, fallback: &str) -> (String, Vec<String>) {
    let hosts: Vec<String> = entry
        .get("meekFrontingHosts")
        .and_then(Json::as_arr)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(Json::as_str)
                .map(str::trim)
                .filter(|host| !host.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let host = hosts
        .first()
        .cloned()
        .or_else(|| {
            entry
                .get("meekFrontingHost")
                .and_then(Json::as_str)
                .map(str::to_owned)
        })
        .or_else(|| {
            entry
                .get("meekFrontingDomain")
                .and_then(Json::as_str)
                .map(str::to_owned)
        })
        .filter(|host| !host.is_empty())
        .unwrap_or_else(|| fallback.to_owned());
    let hosts = if hosts.is_empty() {
        vec![host.clone()]
    } else {
        hosts
    };
    (host, hosts)
}

/// The transport settings a meek capability selects.
#[allow(clippy::too_many_lines)]
fn meek_entry(
    entry: &Json,
    host: &str,
    protocol: &'static str,
) -> Option<crate::psiphon_meek::Meek> {
    let (public_key, obfuscated_key) = meek_keys(entry)?;
    let disable_sni = entry
        .get("meekFrontingDisableSNI")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    let https = if protocol.starts_with("UNFRONTED-MEEK") {
        protocol != "UNFRONTED-MEEK-OSSH"
    } else {
        !protocol.contains("-HTTP-")
    };
    if !protocol.starts_with("FRONTED-MEEK") {
        let host = host.to_owned();
        let port = entry
            .get("meekServerPort")
            .and_then(Json::as_port)
            .filter(|port| *port > 0)
            .unwrap_or(if https { 443 } else { 80 });
        let sni = if disable_sni || !https {
            String::new()
        } else {
            host.clone()
        };
        return Some(crate::psiphon_meek::Meek {
            dial: host.clone(),
            port,
            host: host.clone(),
            sni,
            public_key,
            obfuscated_key,
            disable_sni,
            alpn: Vec::new(),
            fronts: vec![(host.clone(), port)],
            hosts: vec![host],
            https,
            quic: protocol.contains("-QUIC-"),
            fronted: false,
            protocol,
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
    }
    let (host, hosts) = meek_hosts(entry, host);
    let addresses: Vec<String> = entry
        .get("meekFrontingAddresses")
        .and_then(Json::as_arr)
        .map(|addresses| {
            addresses
                .iter()
                .filter_map(Json::as_str)
                .map(str::trim)
                .filter(|address| !address.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let default_port = if https { 443 } else { 80 };
    let raw = addresses
        .first()
        .map(String::as_str)
        .or_else(|| entry.get("meekFrontingDomain").and_then(Json::as_str))
        .map_or_else(|| host.clone(), str::to_owned);
    let (dial, port) = split_fronting_address_with(&raw, default_port);
    let mut fronts: Vec<(String, u16)> = addresses
        .iter()
        .map(|address| split_fronting_address_with(address, default_port))
        .collect();
    if fronts.is_empty() {
        fronts.push((dial.clone(), port));
    }
    let sni = if disable_sni || !https {
        String::new()
    } else {
        dial.clone()
    };
    Some(crate::psiphon_meek::Meek {
        dial,
        port,
        host,
        sni,
        public_key,
        obfuscated_key,
        disable_sni,
        alpn: Vec::new(),
        fronts,
        hosts,
        https,
        quic: protocol.contains("-QUIC-"),
        fronted: true,
        protocol,
        provider_id: entry
            .get("FrontingProviderID")
            .or_else(|| entry.get("frontingProviderID"))
            .and_then(Json::as_str)
            .filter(|provider| !provider.is_empty())
            .map(str::to_owned),
        headers: Vec::new(),
        dns: Vec::new(),
        verify_server_names: Vec::new(),
        verify_pins: Vec::new(),
        shape: TlsShape::default(),
    })
}

/// Split a fronting address, using the supplied default port.
fn split_fronting_address_with(raw: &str, default_port: u16) -> (String, u16) {
    if let Ok(address) = raw.parse::<std::net::SocketAddr>() {
        return (address.ip().to_string(), address.port());
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return (ip.to_string(), default_port);
    }
    if let Some((host, port)) = raw.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (
                host.trim_matches(|ch| ch == '[' || ch == ']').to_owned(),
                port,
            );
        }
    }
    (raw.to_owned(), default_port)
}

fn fetch_list(
    url: &str,
    public_key: &str,
    custom: &[(String, String)],
    roots: &crate::psiphon_ssh::TlsRoots,
    insecure: bool,
) -> Result<String, String> {
    let body = fetch_bytes(url, custom, roots, insecure)?;
    unpack(&body, public_key)
}

fn fetch_bytes(
    url: &str,
    custom: &[(String, String)],
    roots: &crate::psiphon_ssh::TlsRoots,
    insecure: bool,
) -> Result<Vec<u8>, String> {
    let reply = fetch_reply(url, custom, roots, insecure, &[])?;
    if reply.status != 200 {
        return Err(format!("psiphon: {url}: HTTP {}", reply.status));
    }
    Ok(reply.body)
}

fn fetch_reply(
    url: &str,
    custom: &[(String, String)],
    roots: &crate::psiphon_ssh::TlsRoots,
    insecure: bool,
    extra: &[(&str, &str)],
) -> Result<crate::foxy_account::Reply, String> {
    let roots = if insecure {
        Vec::new().into()
    } else {
        roots.load()?
    };
    let endpoint = crate::foxy_account::Endpoint::parse(url, roots)
        .ok_or_else(|| format!("psiphon: {url} is not https"))?
        .with_insecure(insecure);
    let mut headers: Vec<(&str, &str)> = Vec::with_capacity(custom.len() + extra.len() + 1);
    headers.push(("Accept", "*/*"));
    headers.extend(
        custom
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    headers.extend_from_slice(extra);
    crate::foxy_account::ask(&endpoint, "GET", &endpoint.url(""), &headers, &[])
}

/// A URL's cached body and ETag, keyed by its own identity under the lane's state directory.
#[derive(Clone, Copy)]
struct CacheSlot<'a> {
    dir: &'a Path,
    key: &'a str,
}

impl CacheSlot<'_> {
    fn path(self, suffix: &str) -> PathBuf {
        let digest = Sha256::digest(self.key.as_bytes());
        self.dir.join(format!("{}.{suffix}", hex(&digest)))
    }

    fn body(self) -> Option<Vec<u8>> {
        std::fs::read(self.path("body")).ok()
    }

    fn save(self, body: &[u8], etag: Option<&str>) {
        if std::fs::create_dir_all(self.dir).is_err() {
            return;
        }
        let _ = std::fs::write(self.path("body"), body);
        match etag.filter(|etag| !etag.is_empty()) {
            Some(etag) => {
                let _ = std::fs::write(self.path("etag"), etag);
            }
            None => {
                let _ = std::fs::remove_file(self.path("etag"));
            }
        }
    }

    fn etag(self) -> Option<String> {
        std::fs::read_to_string(self.path("etag"))
            .ok()
            .filter(|etag| !etag.is_empty())
    }
}

/// Fetch a URL, honouring its ETag: a 304 reuses the cached body instead of downloading it again.
fn fetch_cached(
    url: &str,
    headers: &[(String, String)],
    roots: &crate::psiphon_ssh::TlsRoots,
    insecure: bool,
    cache: Option<CacheSlot<'_>>,
) -> Result<Vec<u8>, String> {
    let cached = cache.and_then(CacheSlot::body);
    let etag = cached
        .as_ref()
        .and_then(|_| cache.and_then(CacheSlot::etag));
    let conditional = etag
        .as_deref()
        .map(|etag| ("If-None-Match", etag))
        .into_iter()
        .collect::<Vec<_>>();
    let reply = fetch_reply(url, headers, roots, insecure, &conditional)?;
    match reply.status {
        200 => {
            if let Some(cache) = cache {
                cache.save(&reply.body, reply.header("ETag"));
            }
            Ok(reply.body)
        }
        304 => cached.ok_or_else(|| format!("psiphon: {url}: HTTP 304 without a cached body")),
        status => Err(format!("psiphon: {url}: HTTP {status}")),
    }
}

/// Download, authenticate and decrypt every seeded OSL under the configured roots.
fn fetch_osl_entries(
    settings: &Settings,
    sloks: &crate::psiphon_osl::SlokStore,
) -> Result<Vec<Server>, String> {
    let lookup = |id: &[u8]| sloks.get(id);
    let mut servers = Vec::new();
    let mut seen = HashSet::new();
    let mut last = String::new();
    let cache_dir = settings.state.join("osl-cache");
    let cache_enabled = state_is_ours(&settings.state);
    for root in &settings.osl_roots {
        let base = root.url.trim_end_matches('/');
        let registry_cache = cache_enabled.then(|| CacheSlot {
            dir: &cache_dir,
            key: base,
        });
        let registry = match fetch_cached(
            &format!("{base}/osl-registry"),
            &root.headers,
            &settings.tls_shape.roots,
            root.skip_verify,
            registry_cache,
        ) {
            Ok(body) => body,
            Err(why) => {
                last = why;
                continue;
            }
        };
        let specs = match crate::psiphon_osl::parse_registry(&registry, &settings.remote_list_key) {
            Ok(specs) => specs,
            Err(why) => {
                last = why;
                continue;
            }
        };
        for spec in specs {
            if !spec.seeded(&lookup) {
                continue;
            }
            let key = format!("{base}/osl-{}", hex(&spec.id));
            let slot = cache_enabled.then(|| CacheSlot {
                dir: &cache_dir,
                key: &key,
            });
            let cached = slot.and_then(CacheSlot::body);
            let fresh = cached
                .as_ref()
                .is_some_and(|body| spec.md5.is_some_and(|md5| md5::compute(body).0 == md5));
            let body = if fresh {
                cached.unwrap_or_default()
            } else {
                match fetch_cached(
                    &key,
                    &root.headers,
                    &settings.tls_shape.roots,
                    root.skip_verify,
                    slot,
                ) {
                    Ok(body) => body,
                    Err(why) => {
                        last = why;
                        continue;
                    }
                }
            };
            if let Some(md5) = spec.md5 {
                if md5::compute(&body).0 != md5 {
                    last = format!("psiphon: {key}: MD5 sum does not match");
                    continue;
                }
            }
            match crate::psiphon_osl::decrypt_osl(&body, &spec, &lookup, &settings.remote_list_key)
            {
                Ok(text) => absorb(
                    &text,
                    &mut servers,
                    &mut seen,
                    settings.conduit,
                    &settings.conduit_protocols,
                ),
                Err(why) => last = why,
            }
        }
    }
    if servers.is_empty() {
        return if last.is_empty() {
            Ok(Vec::new())
        } else {
            Err(last)
        };
    }
    let servers: Vec<Server> = servers
        .into_iter()
        .filter(|server| {
            server.direct
                || server.meek.is_some()
                || server.unfronted_meek.is_some()
                || (settings.conduit && server.inproxy.is_some())
        })
        .collect();
    let servers = filter_region(servers, settings);
    let mut selected = select_protocols_with(
        servers,
        &settings.protocols,
        &[],
        0,
        settings.fronted,
        settings.fronted_fallback,
        None,
    );
    apply_session_settings(&mut selected, settings);
    apply_fronting_overrides(&mut selected, settings);
    Ok(limit_quic_versions(selected, settings))
}

pub(crate) fn unpack(body: &[u8], public_key: &str) -> Result<String, String> {
    let mut decompressed = Vec::new();
    let too_large = ZlibDecoder::new(body)
        .take(MAX_LIST_BYTES + 1)
        .read_to_end(&mut decompressed)
        .is_err()
        || decompressed.len() as u64 > MAX_LIST_BYTES;
    if too_large {
        decompressed = body.to_vec();
    }
    let text = String::from_utf8_lossy(&decompressed);
    let package = json::parse(&text)
        .map_err(|_| "psiphon: server list is not a signed package".to_owned())?;
    let data = package.get("data").and_then(Json::as_str);
    let digest = package
        .get("signingPublicKeyDigest")
        .and_then(Json::as_str)
        .and_then(|value| ferrox_core::b64::decode(value.as_bytes()));
    let signature = package
        .get("signature")
        .and_then(Json::as_str)
        .and_then(|value| ferrox_core::b64::decode(value.as_bytes()));
    let (Some(data), Some(digest), Some(signature)) = (data, digest, signature) else {
        return Err("psiphon: server list package is incomplete".to_owned());
    };
    let expected = Sha256::digest(public_key.as_bytes());
    if digest != expected.as_slice() {
        return Err("psiphon: server list key digest does not match".to_owned());
    }
    let der = ferrox_core::b64::decode(public_key.as_bytes())
        .ok_or_else(|| "psiphon: server list key is not base64".to_owned())?;
    let pkcs1 =
        spki_to_pkcs1(&der).ok_or_else(|| "psiphon: server list key is not RSA".to_owned())?;
    signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, pkcs1)
        .verify(data.as_bytes(), &signature)
        .map_err(|_| "psiphon: server list signature is invalid".to_owned())?;
    Ok(data.to_owned())
}

fn spki_to_pkcs1(der: &[u8]) -> Option<Vec<u8>> {
    let (tag, outer, _) = der_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, _, algorithm) = der_tlv(outer)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, bit_string, _) = der_tlv(outer.get(algorithm..)?)?;
    if tag != 0x03 || bit_string.first().copied()? != 0 {
        return None;
    }
    Some(bit_string[1..].to_vec())
}

fn der_tlv(der: &[u8]) -> Option<(u8, &[u8], usize)> {
    let tag = *der.first()?;
    let mut at = 1;
    let first = *der.get(at)?;
    at += 1;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for _ in 0..count {
            length = (length << 8) | usize::from(*der.get(at)?);
            at += 1;
        }
        length
    };
    let end = at.checked_add(length)?;
    Some((tag, der.get(at..end)?, end))
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("psiphon: system entropy");
    bytes
}

/// `Fisher-Yates` over the entry list, so a reset makes every position equally likely.
fn shuffle<T>(items: &mut [T]) {
    for at in (1..items.len()).rev() {
        let pick = (u32::from_le_bytes(random::<4>()) as usize) % (at + 1);
        items.swap(at, pick);
    }
}

/// The identity `add_entries` uses to keep the first copy of a server entry.
fn server_key(entry: &Server) -> (IpAddr, u16, Option<u16>, bool, bool, bool) {
    (
        entry.address,
        entry.port,
        entry.ssh_port,
        entry.quic,
        entry.ss,
        entry.tls,
    )
}

/// The entries not already present, keeping their order and the first copy of each.
fn new_entries(current: &[Server], entries: Vec<Server>) -> Vec<Server> {
    let mut seen: HashSet<_> = current.iter().map(server_key).collect();
    entries
        .into_iter()
        .filter(|entry| seen.insert(server_key(entry)))
        .collect()
}

/// Move a live server to the front; returns whether it moved.
fn move_to_front(entries: &mut Vec<Server>, host: &str, port: u16) -> bool {
    let Some(at) = entries
        .iter()
        .position(|entry| entry.host == host && entry.port == port)
    else {
        return false;
    };
    if at == 0 {
        return false;
    }
    let entry = entries.remove(at);
    entries.insert(0, entry);
    true
}

/// The reference's resource-intensive protocols: meek, QUIC, and an in-proxy transport that is dialled.
fn server_is_intensive(server: &Server, conduit: bool) -> bool {
    server.meek.is_some()
        || server.unfronted_meek.is_some()
        || server.quic
        || (conduit && (server.inproxy.is_some() || server.tls_inproxy.is_some()))
}

/// Fill one batch, stopping before an intensive candidate over the limit so the next batch starts there.
fn take_dial_batch(
    entries: &[Server],
    start: usize,
    offset: usize,
    limit: usize,
    width: usize,
    intensive_limit: usize,
    conduit: bool,
) -> (Vec<Server>, usize) {
    let mut batch = Vec::with_capacity(width);
    let mut intensive = 0;
    while batch.len() < width && offset + batch.len() < limit {
        let server = &entries[(start + offset + batch.len()) % entries.len()];
        if intensive_limit > 0 && server_is_intensive(server, conduit) {
            if intensive >= intensive_limit {
                break;
            }
            intensive += 1;
        }
        batch.push(server.clone());
    }
    let taken = batch.len();
    (batch, taken)
}

/// Dial a batch at once and hand back the first answer inside the budget, so a
/// server that stalls costs its own attempt instead of the batch's.
fn race<T: Send + 'static>(
    batch: Vec<Server>,
    attempt: impl Fn(&Server) -> Result<T, String> + Send + Sync + 'static,
    budget: Duration,
    stagger: Duration,
    lead: Duration,
) -> Result<T, String> {
    let attempt = Arc::new(attempt);
    let done = Arc::new(AtomicBool::new(false));
    let (sender, answers) = std::sync::mpsc::channel();
    for (index, server) in batch.into_iter().enumerate() {
        let sender = sender.clone();
        let attempt = Arc::clone(&attempt);
        let done = Arc::clone(&done);
        let delay = if index == 0 {
            Duration::ZERO
        } else {
            lead.saturating_add(stagger.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX)))
        };
        let _ = thread::Builder::new()
            .name("psiphon-dial".to_owned())
            .spawn(move || {
                if !delay.is_zero() {
                    thread::sleep(delay);
                }
                if done.load(Ordering::Acquire) {
                    return;
                }
                let result = attempt(&server);
                if result.is_ok() {
                    done.store(true, Ordering::Release);
                }
                let _ = sender.send(result);
            });
    }
    drop(sender);
    let deadline = Instant::now() + budget;
    let mut last = String::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match answers.recv_timeout(left) {
            Ok(Ok(value)) => {
                done.store(true, Ordering::Release);
                return Ok(value);
            }
            Ok(Err(why)) => last = why,
            Err(_) => break,
        }
    }
    done.store(true, Ordering::Release);
    if last.is_empty() {
        "no server answered inside the attempt budget".clone_into(&mut last);
    }
    Err(last)
}

/// Lowercase hex for a byte slice.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}

const fn hex_table() -> [u8; 256] {
    let mut table = [0xff; 256];
    let mut digit = 0;
    while digit < 10 {
        table[b'0' as usize + digit] = digit as u8;
        digit += 1;
    }
    let mut letter = 0;
    while letter < 6 {
        table[b'a' as usize + letter] = 10 + letter as u8;
        table[b'A' as usize + letter] = 10 + letter as u8;
        letter += 1;
    }
    table
}

static HEX: [u8; 256] = hex_table();

/// Decode an even-length hex string.
pub(crate) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().as_chunks::<2>().0 {
        let high = HEX[usize::from(pair[0])];
        let low = HEX[usize::from(pair[1])];
        if high | low == 0xff {
            return None;
        }
        out.push((high << 4) | low);
    }
    Some(out)
}

/// The entry an affinity names, compared by host and port.
fn affinity_index(entries: &[Server], affinity: Option<&(String, u16)>) -> Option<usize> {
    affinity.and_then(|affinity| {
        entries
            .iter()
            .position(|entry| entry.host == affinity.0 && entry.port == affinity.1)
    })
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

type UdpFlows = Arc<Mutex<HashMap<(IpAddr, u16), Arc<UdpFlow>>>>;

struct UdpGateway {
    writer: Mutex<Channel>,
    frame: Mutex<Vec<u8>>,
    flows: Mutex<HashMap<u16, Weak<UdpFlow>>>,
    next_id: AtomicU16,
    closed: AtomicBool,
}

struct UdpFlow {
    gateway: Arc<UdpGateway>,
    id: u16,
    ip: IpAddr,
    port: u16,
    packets: Mutex<VecDeque<Vec<u8>>>,
    ready: Condvar,
    closed: AtomicBool,
    first_write: AtomicBool,
}

impl UdpGateway {
    fn start(channel: Channel) -> Arc<Self> {
        let gateway = Arc::new(Self {
            writer: Mutex::new(channel.clone()),
            frame: Mutex::new(Vec::with_capacity(UDPGW_MAX_MESSAGE + 2)),
            flows: Mutex::new(HashMap::new()),
            next_id: AtomicU16::new(0),
            closed: AtomicBool::new(false),
        });
        let reader = Arc::clone(&gateway);
        let _ = thread::Builder::new()
            .name("psiphon-udpgw".to_owned())
            .spawn(move || udpgw_reader(reader, channel));
        gateway
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let flows: Vec<Arc<UdpFlow>> = lock(&self.flows)
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for flow in flows {
            flow.close();
        }
        lock(&self.writer).close();
    }

    fn open_flow(self: &Arc<Self>, ip: IpAddr, port: u16) -> Result<Arc<UdpFlow>, String> {
        if self.is_closed() {
            return Err("psiphon: udpgw channel is closed".to_owned());
        }
        let mut flows = lock(&self.flows);
        flows.retain(|_, flow| flow.strong_count() > 0);
        let mut id = self.next_id.load(Ordering::Relaxed);
        let mut found = None;
        for _ in 0..=u16::MAX {
            if !flows.contains_key(&id) {
                found = Some(id);
                break;
            }
            id = id.wrapping_add(1);
        }
        let Some(id) = found else {
            return Err("psiphon: udpgw has no free flow id".to_owned());
        };
        self.next_id.store(id.wrapping_add(1), Ordering::Relaxed);
        let flow = Arc::new(UdpFlow {
            gateway: Arc::clone(self),
            id,
            ip,
            port,
            packets: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            closed: AtomicBool::new(false),
            first_write: AtomicBool::new(true),
        });
        flows.insert(id, Arc::downgrade(&flow));
        Ok(flow)
    }

    fn send(
        &self,
        id: u16,
        ip: IpAddr,
        port: u16,
        payload: &[u8],
        rebind: bool,
    ) -> Result<(), String> {
        if self.is_closed() {
            return Err("psiphon: udpgw channel is closed".to_owned());
        }
        if payload.len() > UDPGW_MAX_PAYLOAD {
            return Err("psiphon: udpgw payload is too large".to_owned());
        }
        let mut frame = lock(&self.frame);
        udpgw_frame_into(&mut frame, id, ip, port, payload, rebind);
        lock(&self.writer)
            .write_all(&frame)
            .map_err(|error| format!("psiphon: udpgw write: {error}"))
    }
}

impl UdpFlow {
    fn send(&self, payload: &[u8]) -> Result<(), String> {
        if self.closed.load(Ordering::Acquire) {
            return Err("psiphon: udpgw flow is closed".to_owned());
        }
        let rebind = self.first_write.swap(false, Ordering::AcqRel);
        self.gateway
            .send(self.id, self.ip, self.port, payload, rebind)
    }

    fn push(&self, packet: Vec<u8>) {
        let mut packets = lock(&self.packets);
        if packets.len() < 64 {
            packets.push_back(packet);
            self.ready.notify_one();
        }
    }

    fn recv(&self) -> Option<Vec<u8>> {
        let mut packets = lock(&self.packets);
        loop {
            if let Some(packet) = packets.pop_front() {
                return Some(packet);
            }
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            packets = self
                .ready
                .wait(packets)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.ready.notify_all();
    }
}

fn udpgw_frame_into(
    frame: &mut Vec<u8>,
    id: u16,
    ip: IpAddr,
    port: u16,
    payload: &[u8],
    rebind: bool,
) {
    let address_len = match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    };
    let size = (5 + address_len + payload.len()) as u16;
    frame.clear();
    frame.extend_from_slice(&size.to_le_bytes());
    let mut flags = if rebind { UDPGW_FLAG_REBIND } else { 0 };
    if ip.is_ipv6() {
        flags |= UDPGW_FLAG_IPV6;
    }
    frame.push(flags);
    frame.extend_from_slice(&id.to_le_bytes());
    match ip {
        IpAddr::V4(address) => frame.extend_from_slice(&address.octets()),
        IpAddr::V6(address) => frame.extend_from_slice(&address.octets()),
    }
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(payload);
}

#[allow(clippy::needless_pass_by_value)]
fn udpgw_reader(gateway: Arc<UdpGateway>, mut channel: Channel) {
    let mut body = vec![0u8; UDPGW_MAX_MESSAGE];
    loop {
        let mut size = [0u8; 2];
        if channel.read_exact(&mut size).is_err() {
            break;
        }
        let size = usize::from(u16::from_le_bytes(size));
        if !(3..=UDPGW_MAX_MESSAGE).contains(&size) {
            break;
        }
        if channel.read_exact(&mut body[..size]).is_err() {
            break;
        }
        let flags = body[0];
        let id = u16::from_le_bytes([body[1], body[2]]);
        if flags & UDPGW_FLAG_KEEPALIVE != 0 {
            continue;
        }
        let (ip, port, start) = if flags & UDPGW_FLAG_IPV6 != 0 {
            if size < 21 {
                break;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[3..19]);
            (
                IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                u16::from_be_bytes([body[19], body[20]]),
                21,
            )
        } else {
            if size < 9 {
                break;
            }
            let octets = [body[3], body[4], body[5], body[6]];
            (
                IpAddr::V4(Ipv4Addr::from(octets)),
                u16::from_be_bytes([body[7], body[8]]),
                9,
            )
        };
        let flow = lock(&gateway.flows).get(&id).and_then(Weak::upgrade);
        if let Some(flow) = flow {
            if flow.ip == ip && flow.port == port {
                flow.push(body[start..size].to_vec());
            }
        }
    }
    gateway.close();
}

fn serve_udp(mut client: TcpStream, inner: &Arc<Inner>) {
    let _ = client.set_nodelay(true);
    let Ok(local) = client.local_addr() else {
        return;
    };
    let Ok(client_ip) = client.peer_addr().map(|peer| peer.ip()) else {
        return;
    };
    let Ok(relay) = UdpSocket::bind(SocketAddr::new(local.ip(), 0)) else {
        let _ = ask_reply(&mut client, Version::V5, Err(1));
        return;
    };
    let Ok(relay_address) = relay.local_addr() else {
        return;
    };
    let Ok(gateway) = inner.udp() else {
        let _ = ask_reply(&mut client, Version::V5, Err(1));
        return;
    };
    if !ask_reply_bound(&mut client, relay_address) {
        return;
    }
    let _ = client.set_read_timeout(None);
    let relay = Arc::new(relay);
    let source = Arc::new(Mutex::new(None));
    let flows: UdpFlows = Arc::new(Mutex::new(HashMap::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let request_relay = Arc::clone(&relay);
    let request_source = Arc::clone(&source);
    let request_flows = Arc::clone(&flows);
    let request_stop = Arc::clone(&stop);
    let request_gateway = Arc::clone(&gateway);
    let _ = thread::Builder::new()
        .name("psiphon-udp".to_owned())
        .spawn(move || {
            udp_requests(
                &request_relay,
                &request_gateway,
                &request_flows,
                &request_source,
                &request_stop,
                client_ip,
            );
        });
    let mut control = [0u8; 32];
    while matches!(client.read(&mut control), Ok(read) if read > 0) {}
    stop.store(true, Ordering::Release);
    for flow in lock(&flows).values() {
        flow.close();
    }
}

fn udp_requests(
    relay: &Arc<UdpSocket>,
    gateway: &Arc<UdpGateway>,
    flows: &UdpFlows,
    source: &Arc<Mutex<Option<SocketAddr>>>,
    stop: &AtomicBool,
    client_ip: IpAddr,
) {
    let _ = relay.set_read_timeout(Some(Duration::from_secs(1)));
    let mut buffer = vec![0u8; 65_535];
    while !stop.load(Ordering::Acquire) {
        let (read, peer) = match relay.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };
        if peer.ip() != client_ip {
            continue;
        }
        {
            let mut source = lock(source);
            match *source {
                None => *source = Some(peer),
                Some(expected) if expected == peer => {}
                Some(_) => continue,
            }
        }
        let Some((target, payload)) = parse_udp_frame(&buffer[..read]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        let (ip, port) = (target.ip(), target.port());
        let flow = {
            let mut flows = lock(flows);
            if let Some(flow) = flows.get(&(ip, port)) {
                Arc::clone(flow)
            } else {
                let Ok(flow) = gateway.open_flow(ip, port) else {
                    continue;
                };
                flows.insert((ip, port), Arc::clone(&flow));
                spawn_udp_reader(Arc::clone(relay), Arc::clone(source), Arc::clone(&flow));
                flow
            }
        };
        let _ = flow.send(payload);
    }
}

fn spawn_udp_reader(
    relay: Arc<UdpSocket>,
    source: Arc<Mutex<Option<SocketAddr>>>,
    flow: Arc<UdpFlow>,
) {
    let _ = thread::Builder::new()
        .name("psiphon-udp-flow".to_owned())
        .spawn(move || {
            let mut frame = Vec::with_capacity(4 + 16 + 2 + UDPGW_MAX_PAYLOAD);
            while let Some(packet) = flow.recv() {
                let Some(peer) = *lock(&source) else {
                    continue;
                };
                socks_udp_frame_into(&mut frame, flow.ip, flow.port, &packet);
                if relay.send_to(&frame, peer).is_err() {
                    break;
                }
            }
        });
}

fn parse_udp_frame(frame: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if frame.len() < 4 || frame[0] != 0 || frame[1] != 0 || frame[2] != 0 {
        return None;
    }
    let mut at = 4;
    let target = match frame[3] {
        1 => {
            let address = frame.get(at..at + 4)?;
            at += 4;
            let port = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
            at += 2;
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    address[0], address[1], address[2], address[3],
                )),
                port,
            )
        }
        4 => {
            let address = frame.get(at..at + 16)?;
            at += 16;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(address);
            let port = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
            at += 2;
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)
        }
        // Any other target, including a SOCKS name, is dropped: a local lookup would send the name in cleartext outside the tunnel, and udpgw carries an address, not a name.
        _ => return None,
    };
    Some((target, frame.get(at..)?))
}

fn socks_udp_frame_into(frame: &mut Vec<u8>, ip: IpAddr, port: u16, payload: &[u8]) {
    frame.clear();
    frame.extend_from_slice(&[0, 0, 0]);
    match ip {
        IpAddr::V4(address) => {
            frame.push(1);
            frame.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            frame.push(4);
            frame.extend_from_slice(&address.octets());
        }
    }
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(payload);
}

fn ask_reply_bound(client: &mut TcpStream, relay: SocketAddr) -> bool {
    let mut reply = vec![5, 0, 0];
    match relay.ip() {
        IpAddr::V4(address) => {
            reply.push(1);
            reply.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            reply.push(4);
            reply.extend_from_slice(&address.octets());
        }
    }
    reply.extend_from_slice(&relay.port().to_be_bytes());
    client.write_all(&reply).is_ok()
}

/// The first outbound is `psiphon`, built and started. A config that names another protocol answers `None`.
pub(crate) fn psiphon_outbound(root: &Json, test: bool) -> Result<Option<PsiphonOut>, String> {
    let Some(outbound) = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .and_then(|outbounds| outbounds.first())
    else {
        return Ok(None);
    };
    if outbound.get("protocol").and_then(Json::as_str) != Some("psiphon") {
        return Ok(None);
    }
    let settings = outbound.get("settings");
    if test {
        PsiphonOut::validate(settings).map(Some)
    } else {
        PsiphonOut::new(settings).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_five_fields_with_json_last() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshUsername":"u","sshPassword":"p","sshHostKey":"AAAA","region":"US"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert_eq!(server.host, "192.0.2.1");
        assert_eq!(server.port, 22);
        assert_eq!(server.region.as_deref(), Some("US"));
    }

    #[test]
    fn a_tls_ossh_only_entry_dials_its_own_port() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedKey":"k","sshHostKey":"AAAA","tlsOSSHPort":8443,"capabilities":["TLS-OSSH"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert!(server.tls);
        assert_eq!(server.port, 8443);
        assert_eq!(server.tls_port, Some(8443));
    }

    #[test]
    fn a_tls_variant_is_added_only_when_the_limit_names_it() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedPort":443,"sshObfuscatedKey":"k","sshHostKey":"AAAA","tlsOSSHPort":8443,"capabilities":["OSSH","TLS-OSSH"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert!(!server.tls);
        assert_eq!(server.port, 443);
        let selected = select_protocols(
            vec![server.clone()],
            &["TLS-OSSH".to_owned()],
            &[],
            0,
            false,
        );
        assert_eq!(selected.len(), 1);
        assert!(selected[0].tls);
        assert_eq!(selected[0].port, 8443);
    }

    #[test]
    fn a_shadowsocks_entry_carries_its_port_key_and_obfuscation_key() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedKey":"o","sshShadowsocksPort":9000,"sshShadowsocksKey":"s","sshHostKey":"AAAA","capabilities":["SSH","SHADOWSOCKS-OSSH"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert_eq!(server.port, 22);
        assert!(!server.ss);
        let variant = server.shadowsocks_variant().expect("variant");
        assert!(variant.ss);
        assert!(variant.direct);
        assert_eq!(variant.port, 9000);
        assert_eq!(
            variant.shadowsocks.as_ref().map(|ss| ss.key.as_str()),
            Some("s")
        );
        assert_eq!(variant.obfuscation_key.as_deref(), Some("o"));
        assert!(variant.obfuscated());
    }

    #[test]
    fn a_shadowsocks_only_entry_dials_its_own_port() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshShadowsocksPort":9000,"sshShadowsocksKey":"s","sshHostKey":"AAAA","capabilities":["SHADOWSOCKS-OSSH"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert!(server.ss);
        assert_eq!(server.port, 9000);
        assert!(server.shadowsocks_variant().is_none());
    }

    #[test]
    fn a_shadowsocks_sibling_leaves_a_meek_entry_on_its_own_port() {
        let entry = r#"{"ipAddress":"192.0.2.1","meekServerPort":2050,"meekCookieEncryptionPublicKey":"c","meekObfuscatedKey":"m","sshShadowsocksPort":9000,"sshShadowsocksKey":"s","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK","SHADOWSOCKS-OSSH"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert!(!server.ss);
        assert!(!server.direct);
        assert_eq!(server.port, 2050);
        assert!(server.meek.is_some());
        let variant = server.shadowsocks_variant().expect("variant");
        assert!(variant.ss);
        assert!(variant.direct);
        assert_eq!(variant.port, 9000);
        assert!(variant.meek.is_none());
    }

    #[test]
    fn a_shadowsocks_limit_selects_the_variant() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedKey":"o","sshShadowsocksPort":9000,"sshShadowsocksKey":"s","sshHostKey":"AAAA","capabilities":["SSH","SHADOWSOCKS-OSSH"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let variant = server.shadowsocks_variant().expect("variant");
        let selected = select_protocols(
            vec![server, variant],
            &["SHADOWSOCKS-OSSH".to_owned()],
            &[],
            0,
            false,
        );
        assert_eq!(selected.len(), 1);
        assert!(selected[0].ss);
        assert_eq!(selected[0].port, 9000);
    }

    #[test]
    fn a_plain_ssh_entry_keeps_its_key_for_the_tls_variant() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedKey":"k","sshHostKey":"AAAA","tlsOSSHPort":8443,"capabilities":["SSH","TLS-OSSH"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert_eq!(server.port, 22);
        assert!(!server.tls);
        assert!(!server.obfuscated());
        let selected = select_protocols(vec![server], &["TLS-OSSH".to_owned()], &[], 0, false);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].tls);
        assert_eq!(selected[0].port, 8443);
        assert!(selected[0].obfuscated());
    }

    #[test]
    fn a_tls_variant_keeps_the_tls_destination_when_the_entry_names_both() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedPort":443,"sshObfuscatedKey":"k","tlsOSSHPort":8443,"sshHostKey":"AAAA","capabilities":["OSSH","TLS-OSSH","INPROXY-WEBRTC-OSSH","INPROXY-WEBRTC-TLS-OSSH"],"inproxyOSSHPort":443,"inproxyTlsOSSHPort":8443,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        assert!(!server.tls);
        let selected = select_protocols(vec![server], &["TLS-OSSH".to_owned()], &[], 0, false);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].tls);
        assert_eq!(
            selected[0]
                .inproxy
                .as_ref()
                .map(crate::psiphon_broker::Destination::base_protocol),
            Some("TLS-OSSH")
        );
    }

    #[test]
    fn a_tls_base_entry_drops_a_plain_inproxy_destination() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedKey":"k","tlsOSSHPort":8443,"sshHostKey":"AAAA","capabilities":["INPROXY-WEBRTC-OSSH"],"inproxyOSSHPort":443,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        assert!(server.tls);
        assert!(
            server.inproxy.is_none(),
            "a TLS base entry must not keep a plain in-proxy destination"
        );
    }

    #[test]
    fn a_plain_entry_keeps_its_port_and_moves_the_tls_destination_to_the_variant() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedPort":443,"sshObfuscatedKey":"k","tlsOSSHPort":8443,"sshHostKey":"AAAA","capabilities":["INPROXY-WEBRTC-TLS-OSSH"],"inproxyTlsOSSHPort":8443,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        assert!(!server.tls);
        assert_eq!(server.port, 443);
        assert!(server.inproxy.is_none());
        let mut servers = vec![server];
        add_tls_variants(&mut servers);
        let variant = servers
            .iter()
            .find(|server| server.tls)
            .expect("TLS variant");
        assert_eq!(variant.port, 8443);
        assert_eq!(
            variant
                .inproxy
                .as_ref()
                .map(crate::psiphon_broker::Destination::base_protocol),
            Some("TLS-OSSH")
        );
    }

    #[test]
    fn a_tls_base_entry_keeps_the_tls_destination() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedKey":"k","tlsOSSHPort":8443,"sshHostKey":"AAAA","capabilities":["INPROXY-WEBRTC-OSSH","INPROXY-WEBRTC-TLS-OSSH"],"inproxyOSSHPort":443,"inproxyTlsOSSHPort":8443,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        assert!(server.tls);
        assert_eq!(
            server
                .inproxy
                .as_ref()
                .map(crate::psiphon_broker::Destination::base_protocol),
            Some("TLS-OSSH")
        );
    }

    #[test]
    fn a_passthrough_session_ticket_entry_gets_a_tls_port() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedKey":"k","sshHostKey":"AAAA","meekServerPort":2050,"capabilities":["UNFRONTED-MEEK-SESSION-TICKET-PASSTHROUGH-v2"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert!(server.tls);
        assert_eq!(server.port, 2050);
    }

    #[test]
    fn a_passthrough_https_capability_keeps_its_unfronted_shape() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","meekServerPort":2050,"meekCookieEncryptionPublicKey":"c","meekObfuscatedKey":"m","capabilities":["UNFRONTED-MEEK-HTTPS-PASSTHROUGH-v2"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert_eq!(
            server.meek.as_ref().map(|meek| meek.protocol),
            Some("UNFRONTED-MEEK-HTTPS-OSSH")
        );
    }

    #[test]
    fn an_inproxy_quic_destination_keeps_its_udp_shape() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","sshObfuscatedKey":"k","capabilities":["INPROXY-WEBRTC-TLS-OSSH","INPROXY-WEBRTC-QUIC-OSSH"],"inproxyTlsOSSHPort":8443,"inproxyQUICPort":443,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        assert!(!server.tls);
        let destination = server.inproxy.expect("destination");
        assert_eq!(destination.base_protocol(), "QUIC-OSSH");
        assert_eq!(destination.address, "192.0.2.1:443");
        assert_eq!(destination.network_protocol, 1);
    }

    #[test]
    fn an_inproxy_unfronted_meek_destination_keeps_its_http_shape() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","sshObfuscatedKey":"k","meekCookieEncryptionPublicKey":"c","meekObfuscatedKey":"m","capabilities":["INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH"],"inproxyMeekPort":2050,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        assert!(!server.tls);
        assert!(server.meek.is_none());
        let destination = server.inproxy.expect("destination");
        assert_eq!(destination.base_protocol(), "UNFRONTED-MEEK-HTTPS-OSSH");
        assert_eq!(destination.address, "192.0.2.1:2050");
        assert_eq!(destination.network_protocol, 0);
        let meek = server.inproxy_meek.expect("in-proxy meek");
        assert!(meek.https);
        assert_eq!(meek.protocol, "UNFRONTED-MEEK-HTTPS-OSSH");
    }

    #[test]
    fn an_inproxy_fronted_meek_destination_keeps_its_http_shape() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","sshObfuscatedKey":"k","meekCookieEncryptionPublicKey":"c","meekObfuscatedKey":"m","meekFrontingHosts":["cdn.example"],"meekFrontingDomain":"front.example","capabilities":["INPROXY-WEBRTC-FRONTED-MEEK-HTTP-OSSH"],"inproxyMeekPort":2050,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        assert!(!server.tls);
        let destination = server.inproxy.expect("destination");
        assert_eq!(destination.base_protocol(), "FRONTED-MEEK-HTTP-OSSH");
        assert_eq!(destination.address, "192.0.2.1:2050");
        let meek = server.inproxy_meek.expect("in-proxy meek");
        assert!(meek.fronted);
        assert!(!meek.https);
        assert_eq!(meek.host, "cdn.example");
    }

    #[test]
    fn an_inproxy_fronted_quic_destination_keeps_its_udp_shape() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","sshObfuscatedKey":"k","meekCookieEncryptionPublicKey":"c","meekObfuscatedKey":"m","meekFrontingAddresses":["front.example:443"],"meekFrontingHosts":["cdn.example"],"capabilities":["INPROXY-WEBRTC-FRONTED-MEEK-QUIC-OSSH"],"inproxyMeekPort":2050,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        assert!(!server.tls);
        let destination = server.inproxy.expect("destination");
        assert_eq!(destination.base_protocol(), "FRONTED-MEEK-QUIC-OSSH");
        assert_eq!(destination.address, "192.0.2.1:2050");
        assert_eq!(destination.network_protocol, 1);
        let meek = server.inproxy_meek.expect("in-proxy meek");
        assert!(meek.quic && meek.https && meek.fronted);
        assert_eq!(meek.host, "cdn.example");
    }

    #[test]
    fn an_inproxy_tls_destination_keeps_its_own_port() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","sshObfuscatedKey":"k","capabilities":["INPROXY-WEBRTC-TLS-OSSH"],"inproxyTlsOSSHPort":8443,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        assert!(server.tls);
        let destination = server.inproxy.expect("destination");
        assert_eq!(destination.protocol, "INPROXY-WEBRTC-TLS-OSSH");
        assert_eq!(destination.address, "192.0.2.1:8443");
    }

    #[test]
    fn an_inproxy_only_entry_keeps_its_destination() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["INPROXY-WEBRTC-OSSH"],"inproxyOSSHPort":443,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        assert!(decode_entry(&encoded).is_none());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        assert_eq!(server.port, 443);
        let destination = server.inproxy.expect("destination");
        assert_eq!(destination.address, "192.0.2.1:443");
    }

    #[test]
    fn a_tactics_compartment_that_does_not_decode_is_not_echoed() {
        let secret = "not/a/compartment";
        let error = decode_compartment(secret).expect_err("a bad compartment");
        assert_eq!(error, "psiphon: compartment is not 32 base64 bytes");
        assert!(!error.contains(secret));
    }

    #[test]
    fn a_personal_compartment_that_does_not_decode_is_not_echoed() {
        let secret = "not/a/compartment";
        let error = compartment32(secret, "personal compartment").expect_err("a bad compartment");
        assert_eq!(
            error,
            "psiphon broker: personal compartment is not 32 base64 bytes"
        );
        assert!(!error.contains(secret));
    }

    #[test]
    fn regions_count_entries_by_code() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshHostKey":"AAAA","region":"US"}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let settings =
            json::parse(&format!(r#"{{"TargetServerEntry":"{target}"}}"#)).expect("settings");
        assert_eq!(regions(Some(&settings)), Ok(vec![("US".to_owned(), 1)]));
    }

    #[test]
    fn a_fronted_entry_carries_its_cdn_config() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedPort":443,"sshObfuscatedKey":"k","sshHostKey":"AAAA","capabilities":["SSH","OSSH","FRONTED-MEEK"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example:8443","192.0.2.2:443"],"meekFrontingHosts":["cdn.example","cdn2.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let meek = server.meek.expect("fronted");
        assert_eq!(meek.dial, "front.example");
        assert_eq!(meek.port, 8443);
        assert_eq!(meek.host, "cdn.example");
        assert_eq!(meek.sni, "front.example");
        assert_eq!(meek.obfuscated_key, "mk");
        assert_eq!(meek.fronts.len(), 2);
        assert_eq!(meek.hosts, vec!["cdn.example", "cdn2.example"]);
    }

    #[test]
    fn an_unfronted_meek_entry_carries_its_own_port() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["UNFRONTED-MEEK-HTTPS"],"meekServerPort":8443,"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert!(!server.direct);
        let meek = server.meek.expect("unfronted");
        assert_eq!(meek.protocol, "UNFRONTED-MEEK-HTTPS-OSSH");
        assert!(!meek.fronted);
        assert!(meek.https);
        assert_eq!(meek.port, 8443);
        assert_eq!(meek.dial, "192.0.2.1");
        assert_eq!(meek.host, "192.0.2.1");
    }

    #[test]
    fn a_fronted_capability_wins_over_an_unfronted_one() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["UNFRONTED-MEEK-HTTPS","FRONTED-MEEK"],"meekServerPort":8443,"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let meek = server.meek.expect("meek");
        assert_eq!(meek.protocol, "FRONTED-MEEK-OSSH");
        assert!(meek.fronted);
    }

    #[test]
    fn capability_names_borrow_when_no_mask_is_needed() {
        let ((), new) = ferrox_core::alloc_count::measure(|| {
            assert!(capability_matches("SSH", "SSH"));
            assert!(capability_matches("FRONTED-MEEK", "FRONTED-MEEK"));
            assert!(capability_matches(
                "UNFRONTED-MEEK-HTTPS",
                "UNFRONTED-MEEK-HTTPS"
            ));
        });
        assert_eq!(new.allocs, 0, "the common names take no heap: {new:?}");
        assert!(capability_matches("FRONTED-MEEK-OSSH", "FRONTED-MEEK"));
        assert!(capability_matches("QUICv1", "QUIC"));
        assert!(capability_matches(
            "UNFRONTED-MEEK-HTTPS-PASSTHROUGH-v2",
            "TLS"
        ));
        assert!(!capability_matches("FRONTED-MEEK-CDN-HTTP", "FRONTED-MEEK"));
    }

    #[test]
    fn fronting_off_uses_the_unfronted_capability() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK","UNFRONTED-MEEK-HTTPS"],"meekServerPort":8443,"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert_eq!(
            server.meek.as_ref().expect("fronted").protocol,
            "FRONTED-MEEK-OSSH"
        );
        let selected = select_protocols(vec![server], &[], &[], 0, false);
        assert_eq!(selected.len(), 1);
        let meek = selected[0].meek.as_ref().expect("unfronted");
        assert!(!meek.fronted);
        assert_eq!(meek.protocol, "UNFRONTED-MEEK-HTTPS-OSSH");
        assert_eq!(meek.dial, "192.0.2.1");
        assert_eq!(meek.port, 8443);
    }

    #[test]
    fn auto_prefers_unfronted_over_a_fronted_fallback_when_both_exist() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK","UNFRONTED-MEEK-HTTPS"],"meekServerPort":8443,"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let selected = select_protocols_with(vec![server], &[], &[], 0, false, true, None);
        assert_eq!(selected.len(), 1);
        let meek = selected[0].meek.as_ref().expect("unfronted");
        assert!(!meek.fronted);
        assert_eq!(meek.protocol, "UNFRONTED-MEEK-HTTPS-OSSH");
        assert_eq!(meek.dial, "192.0.2.1");
    }

    #[test]
    fn an_entry_without_a_front_falls_back_to_unfronted() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK","UNFRONTED-MEEK-HTTPS"],"meekServerPort":8443,"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let selected = select_protocols(vec![server], &[], &[], 0, false);
        assert_eq!(selected.len(), 1);
        let meek = selected[0].meek.as_ref().expect("unfronted");
        assert!(!meek.fronted);
        assert_eq!(meek.protocol, "UNFRONTED-MEEK-HTTPS-OSSH");
        assert_eq!(meek.dial, "192.0.2.1");
    }

    #[test]
    fn https_fronting_wins_over_http() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK-HTTP","FRONTED-MEEK"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let meek = server.meek.expect("fronted");
        assert_eq!(meek.protocol, "FRONTED-MEEK-OSSH");
        assert!(meek.https);
        assert_eq!(meek.port, 443);
    }

    #[test]
    fn a_fronted_quic_capability_selects_http3() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK","FRONTED-MEEK-QUIC"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let meek = server.meek.expect("fronted");
        assert_eq!(meek.protocol, "FRONTED-MEEK-QUIC-OSSH");
        assert!(meek.quic);
        assert!(meek.https);
    }

    #[test]
    fn a_fronted_quic_limit_without_a_plain_version_falls_back() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK","FRONTED-MEEK-QUIC"],"limitQUICVersions":["OBFUSCATED-QUICv1"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let meek = server.meek.expect("fronted");
        assert_eq!(meek.protocol, "FRONTED-MEEK-OSSH");
        assert!(!meek.quic);
    }

    #[test]
    fn an_https_limit_drops_an_http_front() {
        let http = decode_entry(&hex(
            br#"0 0 0 0 {"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK-HTTP"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#,
        ))
        .expect("http");
        let https = decode_entry(&hex(
            br#"0 0 0 0 {"ipAddress":"192.0.2.2","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#,
        ))
        .expect("https");
        let selected = select_protocols(
            vec![http, https],
            &["FRONTED-MEEK-CDN-OSSH".to_owned()],
            &[],
            0,
            true,
        );
        assert_eq!(selected.len(), 1);
        assert!(selected[0].meek.as_ref().is_some_and(|meek| meek.https));
    }

    #[test]
    fn an_https_limit_refuses_an_http_only_front() {
        let http = decode_entry(&hex(
            br#"0 0 0 0 {"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK-HTTP"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#,
        ))
        .expect("http");
        let selected =
            select_protocols(vec![http], &["FRONTED-MEEK-OSSH".to_owned()], &[], 0, true);
        assert!(selected.is_empty());
    }

    #[test]
    fn an_http_fronted_entry_dials_port_80_without_sni() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK-HTTP"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let meek = server.meek.expect("fronted");
        assert_eq!(meek.protocol, "FRONTED-MEEK-HTTP-OSSH");
        assert!(meek.fronted);
        assert!(!meek.https);
        assert_eq!(meek.port, 80);
        assert_eq!(meek.sni, "");
    }

    #[test]
    fn fronted_overrides_add_dial_and_sni_candidates() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{
                    "FrontedMeekDialOverrides": [{
                        "DialAddresses": ["edge.example:8443", "192.0.2.9:443"],
                        "SNIServerName": "sni.example",
                        "DisableSNI": false,
                        "ALPNProtocols": ["http/1.1"]
                    }],
                    "FrontedMeekCDNScanSpec": {
                        "IPCandidates": ["198.51.100.7:443"],
                        "SNIServerNames": ["scan.example"]
                    }
                }"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(
            settings.fronted_overrides[0].dials,
            vec!["edge.example:8443", "192.0.2.9:443"]
        );
        assert_eq!(settings.fronted_overrides[0].snis, vec!["sni.example"]);
        assert_eq!(settings.fronted_overrides.len(), 1);
        assert!(!settings.fronted_overrides[0].disable_sni);
        assert_eq!(
            settings.fronted_overrides[0].alpn,
            vec![b"http/1.1".to_vec()]
        );
        assert!(settings.cdn_ips.iter().any(|ip| ip == "198.51.100.7:443"));
        assert!(settings.cdn_snis.iter().any(|sni| sni == "scan.example"));

        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        assert!(servers.iter().any(|server| {
            let meek = server.meek.as_ref().expect("fronted");
            meek.dial == "edge.example"
                && meek.port == 8443
                && meek.sni == "sni.example"
                && !meek.disable_sni
        }));
    }

    #[test]
    fn a_fronted_scan_adds_candidates_without_an_override() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{
                    "FrontedMeekCDNScanSpec": {
                        "IPCandidates": ["198.51.100.7:443"],
                        "SNIServerNames": ["scan.example"]
                    }
                }"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        assert!(servers.iter().any(|server| {
            let meek = server.meek.as_ref().expect("fronted");
            meek.dial == "198.51.100.7" && meek.sni == "scan.example"
        }));
    }

    #[test]
    fn a_quic_front_keeps_its_h3_alpn_over_an_override() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{
                    "FrontedMeekDialOverrides": [{
                        "DialAddresses": ["pypi.org"],
                        "SNIServerName": "pypi.org",
                        "ALPNProtocols": ["http/1.1"]
                    }]
                }"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: vec![b"h3".to_vec()],
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: true,
            fronted: true,
            protocol: "FRONTED-MEEK-QUIC-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        let front = servers
            .iter()
            .find(|server| {
                server
                    .meek
                    .as_ref()
                    .is_some_and(|meek| meek.dial == "pypi.org")
            })
            .expect("pypi front");
        assert_eq!(
            front.meek.as_ref().expect("fronted").alpn,
            vec![b"h3".to_vec()]
        );
    }

    #[test]
    fn an_sni_only_override_keeps_the_entry_candidates() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"FrontedMeekDialOverrides":[{"SNIServerName":"sni.example"}]}"#)
                .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![
                ("front.example".to_owned(), 443),
                ("backup.example".to_owned(), 8443),
            ],
            hosts: vec!["cdn.example".to_owned(), "cdn2.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        let meek = servers
            .iter()
            .filter_map(|server| server.meek.as_ref())
            .find(|meek| meek.sni == "sni.example")
            .expect("sni candidate");
        assert_eq!(meek.dial, "front.example");
        assert_eq!(
            meek.fronts,
            vec![
                ("front.example".to_owned(), 443),
                ("backup.example".to_owned(), 8443)
            ]
        );
        assert_eq!(
            meek.hosts,
            vec!["cdn.example".to_owned(), "cdn2.example".to_owned()]
        );
    }

    #[test]
    fn a_scan_keeps_the_entry_sni_setting() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"FrontedMeekCDNScanSpec":{"IPCandidates":["192.0.2.9:443"],"SNIServerNames":["a.example","b.example"]}}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: true,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        assert_eq!(servers.len(), 1);
        assert!(servers
            .iter()
            .filter_map(|server| server.meek.as_ref())
            .all(|meek| meek.disable_sni));
    }

    #[test]
    fn fronted_variants_round_robin_across_servers() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"cdnIps":["192.0.2.0/24"]}"#).expect("settings"),
        ))
        .expect("settings");
        let mut servers = Vec::new();
        for index in 0..3 {
            let mut server = test_server(true);
            server.meek = Some(crate::psiphon_meek::Meek {
                dial: "front.example".to_owned(),
                port: 443,
                host: format!("cdn{index}.example"),
                sni: "front.example".to_owned(),
                public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
                obfuscated_key: "mk".to_owned(),
                disable_sni: false,
                alpn: Vec::new(),
                fronts: vec![("front.example".to_owned(), 443)],
                hosts: vec![format!("cdn{index}.example")],
                https: true,
                quic: false,
                fronted: true,
                protocol: "FRONTED-MEEK-OSSH",
                headers: Vec::new(),
                dns: Vec::new(),
                provider_id: None,
                verify_server_names: Vec::new(),
                verify_pins: Vec::new(),
                shape: TlsShape::default(),
            });
            servers.push(server);
        }
        apply_fronting_overrides(&mut servers, &settings);
        assert_eq!(servers.len(), FRONTED_SERVERS);
        for index in 0..3 {
            let host = format!("cdn{index}.example");
            let count = servers
                .iter()
                .filter_map(|server| server.meek.as_ref())
                .filter(|meek| meek.host == host)
                .count();
            assert!(count > 100, "server {index} got {count} variants");
        }
    }

    #[test]
    fn a_candidate_list_wider_than_the_cap_still_names_every_dial() {
        let ips: Vec<String> = (1..=20).map(|index| format!("192.0.2.{index}")).collect();
        let snis: Vec<String> = (1..=20)
            .map(|index| format!("sni{index}.example"))
            .collect();
        let ips_json = ips
            .iter()
            .map(|ip| format!("\"{ip}\""))
            .collect::<Vec<_>>()
            .join(",");
        let snis_json = snis
            .iter()
            .map(|sni| format!("\"{sni}\""))
            .collect::<Vec<_>>()
            .join(",");
        let settings = Settings::from_json(Some(
            &json::parse(&format!(
                r#"{{"cdnIps":[{ips_json}],"cdnSni":[{snis_json}]}}"#
            ))
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "front.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["front.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        let meeks: Vec<_> = servers
            .iter()
            .filter_map(|server| server.meek.as_ref())
            .collect();
        for ip in &ips {
            assert_eq!(
                meeks.iter().filter(|meek| meek.dial == *ip).count(),
                2,
                "{ip}"
            );
        }
    }

    #[test]
    fn an_override_survives_a_full_scan() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{
                    "cdnIps": ["192.0.2.0/24"],
                    "FrontedMeekDialOverrides": [{
                        "DialAddresses": ["edge.example:8443"],
                        "SNIServerName": "sni.example"
                    }]
                }"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        assert!(servers.iter().any(|server| {
            let meek = server.meek.as_ref().expect("fronted");
            meek.dial == "edge.example" && meek.sni == "sni.example"
        }));
    }

    #[test]
    fn the_builtin_scan_set_adds_fronting_candidates() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"FrontedMeekCDNScanUseBuiltInSpec":true}"#).expect("settings"),
        ))
        .expect("settings");
        let first = Ipv4Addr::from(BUILTIN_CDN_RANGES[0].first).to_string();
        assert!(settings.cdn_ips.iter().any(|ip| ip == &first));
        assert!(settings
            .cdn_snis
            .iter()
            .any(|sni| sni == BUILTIN_CDN_SNIS[0]));
    }

    #[test]
    fn cdn_fronting_selects_the_android_protocols_and_scan() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"protocolSelection":"cdn_fronting"}"#).expect("settings"),
        ))
        .expect("settings");
        assert!(settings.fronted);
        assert!(!settings.fronted_fallback);
        assert!(settings.disable_tactics);
        assert_eq!(
            settings.protocols,
            CDN_FRONTING_PROTOCOLS
                .iter()
                .map(|protocol| (*protocol).to_owned())
                .collect::<Vec<_>>()
        );
        assert_ne!(settings.cdn_ips, Vec::<String>::new());
        assert_ne!(settings.cdn_snis, Vec::<String>::new());
        assert!(settings
            .fronted_overrides
            .iter()
            .any(|fronted| fronted.dials.iter().any(|dial| dial.as_str() == "pypi.org")));
    }

    /// One fronted QUIC entry with a real fronting host for the scan gate.
    fn scan_front() -> crate::psiphon_meek::Meek {
        crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: vec![b"h3".to_vec()],
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: true,
            fronted: true,
            protocol: "FRONTED-MEEK-QUIC-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        }
    }

    #[test]
    fn only_cdn_suffixed_fronted_protocols_take_the_scan() {
        assert!(uses_fronted_meek_cdn("FRONTED-MEEK-CDN-OSSH"));
        assert!(uses_fronted_meek_cdn("FRONTED-MEEK-CDN-HTTP-OSSH"));
        assert!(uses_fronted_meek_cdn("FRONTED-MEEK-CDN-QUIC-OSSH"));
        assert!(!uses_fronted_meek_cdn("FRONTED-MEEK-QUIC-OSSH"));
        assert!(!uses_fronted_meek_cdn("FRONTED-MEEK-OSSH"));
        assert!(!uses_fronted_meek_cdn("UNFRONTED-MEEK-HTTPS-OSSH"));
    }

    #[test]
    fn a_bare_protocol_limit_keeps_the_real_fronting_host() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"LimitTunnelProtocols":["FRONTED-MEEK-QUIC-OSSH"],"cdnIps":["198.51.100.7"],"cdnSni":["scan.example"]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(scan_front());
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        assert_eq!(servers.len(), 1, "a bare protocol took scan candidates");
        let meek = servers[0].meek.as_ref().expect("fronted");
        assert_eq!(meek.dial, "front.example");
        assert_eq!(meek.sni, "front.example");
        assert_eq!(meek.fronts, vec![("front.example".to_owned(), 443)]);
    }

    #[test]
    fn a_cdn_protocol_limit_takes_the_scan_candidates() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"LimitTunnelProtocols":["FRONTED-MEEK-CDN-QUIC-OSSH"],"cdnIps":["198.51.100.7"],"cdnSni":["scan.example"]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(scan_front());
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        assert!(servers.iter().any(|server| {
            server
                .meek
                .as_ref()
                .is_some_and(|meek| meek.dial == "198.51.100.7")
        }));
    }

    #[test]
    fn cdn_fronting_selection_still_scans_a_bare_capability_entry() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"protocolSelection":"cdn_fronting"}"#).expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(scan_front());
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        assert!(servers.len() > 1, "the scan lost its candidates");
        assert!(servers.iter().any(|server| {
            server
                .meek
                .as_ref()
                .is_some_and(|meek| meek.dial != "front.example")
        }));
    }

    #[test]
    fn a_cdn_limit_for_another_base_does_not_scan_this_front() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"LimitTunnelProtocols":["FRONTED-MEEK-CDN-HTTP-OSSH"],"cdnIps":["198.51.100.7"]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(scan_front());
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        assert_eq!(servers.len(), 1);
        assert_eq!(
            servers[0].meek.as_ref().expect("fronted").dial,
            "front.example"
        );
    }

    /// A configured limit that the probability coin rejected never selected
    /// these candidates, so it cannot remove their CDN scan.
    #[test]
    fn a_rejected_protocol_limit_keeps_the_scan_candidates() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"LimitTunnelProtocols":["FRONTED-MEEK-QUIC-OSSH"],"LimitTunnelProtocolsProbability":0,"cdnIps":["198.51.100.7"]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let drawn: &[String] = if coin(settings.limit_protocols_probability) {
            &settings.protocols
        } else {
            &[]
        };
        assert!(drawn.is_empty(), "the coin rejected the configured limit");
        let mut server = test_server(true);
        server.meek = Some(scan_front());
        let mut servers = select_protocols_with(vec![server], drawn, &[], 0, true, false, None);
        apply_fronting_overrides_selected(&mut servers, &settings);
        assert!(servers.iter().any(|server| {
            server
                .meek
                .as_ref()
                .is_some_and(|meek| meek.dial == "198.51.100.7")
        }));
    }

    /// An active initial limit can name CDN protocols even when the configured
    /// limit is bare; the gate must follow the limit selection really used.
    #[test]
    fn an_initial_cdn_limit_keeps_the_scan_candidates() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"LimitTunnelProtocols":["FRONTED-MEEK-QUIC-OSSH"],"InitialLimitTunnelProtocols":["FRONTED-MEEK-CDN-QUIC-OSSH"],"InitialLimitTunnelProtocolsCandidateCount":1,"cdnIps":["198.51.100.7"]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(scan_front());
        let mut configured = vec![server];
        apply_fronting_overrides(&mut configured, &settings);
        assert_eq!(
            configured.len(),
            1,
            "the bare configured limit gates the scan"
        );
        let mut server = test_server(true);
        server.meek = Some(scan_front());
        let mut servers = select_protocols_with(
            vec![server],
            &settings.protocols,
            &settings.initial_protocols,
            settings.initial_count,
            true,
            false,
            None,
        );
        apply_fronting_overrides_selected(&mut servers, &settings);
        assert!(servers.iter().any(|server| {
            server
                .meek
                .as_ref()
                .is_some_and(|meek| meek.dial == "198.51.100.7")
        }));
    }

    /// A bare initial limit gates only the candidate it selected; the
    /// unrestricted candidates that follow keep their scan candidates.
    #[test]
    fn a_bare_initial_limit_does_not_gate_unrestricted_candidates() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"InitialLimitTunnelProtocols":["FRONTED-MEEK-QUIC-OSSH"],"InitialLimitTunnelProtocolsCandidateCount":1,"cdnIps":["198.51.100.7"]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut initial = test_server(true);
        let mut initial_front = scan_front();
        initial_front.dial = "front.initial".to_owned();
        initial_front.host = "initial.example".to_owned();
        initial_front.hosts = vec!["initial.example".to_owned()];
        initial.meek = Some(initial_front);
        let mut rest = test_server(true);
        let mut rest_front = scan_front();
        rest_front.dial = "front.rest".to_owned();
        rest_front.host = "rest.example".to_owned();
        rest_front.hosts = vec!["rest.example".to_owned()];
        rest.meek = Some(rest_front);
        let mut servers = select_protocols_with(
            vec![initial, rest],
            &[],
            &settings.initial_protocols,
            settings.initial_count,
            true,
            false,
            None,
        );
        apply_fronting_overrides_selected(&mut servers, &settings);
        assert!(
            servers.iter().any(|server| {
                server
                    .meek
                    .as_ref()
                    .is_some_and(|meek| meek.dial == "front.initial")
            }),
            "the initial candidate kept its advertised front"
        );
        assert!(
            !servers.iter().any(|server| {
                server.meek.as_ref().is_some_and(|meek| {
                    meek.host == "initial.example" && meek.dial != "front.initial"
                })
            }),
            "the bare initial candidate must not take scan candidates"
        );
        assert!(
            servers.iter().any(|server| {
                server
                    .meek
                    .as_ref()
                    .is_some_and(|meek| meek.host == "rest.example" && meek.dial == "198.51.100.7")
            }),
            "the unrestricted candidate kept its scan"
        );
    }

    #[test]
    fn direct_selects_the_android_protocols() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"protocolSelection":"direct"}"#).expect("settings"),
        ))
        .expect("settings");
        assert!(!settings.fronted);
        assert!(settings.fronted_fallback);
        assert!(settings.disable_tactics);
        assert_eq!(
            settings.protocols,
            DIRECT_PROTOCOLS
                .iter()
                .map(|protocol| (*protocol).to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_explicit_limit_overrides_the_connection_mode() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"protocolSelection":"cdn_fronting","LimitTunnelProtocols":["TLS-OSSH"]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.protocols, vec!["TLS-OSSH".to_owned()]);
        assert!(settings.disable_tactics);
    }

    #[test]
    fn auto_enables_the_android_scan_without_a_limit() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"protocolSelection":"auto"}"#).expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.protocols, Vec::<String>::new());
        assert!(!settings.disable_tactics);
        assert_ne!(settings.cdn_ips, Vec::<String>::new());
    }

    #[test]
    fn a_builtin_scan_dials_an_http_front_on_port_80() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"protocolSelection":"cdn_fronting"}"#).expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.direct = false;
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 80,
            host: "cdn.example".to_owned(),
            sni: String::new(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 80)],
            hosts: vec!["cdn.example".to_owned()],
            https: false,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-HTTP-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        let edge = Ipv4Addr::from(BUILTIN_CDN_RANGES[0].first).to_string();
        assert!(servers.iter().any(|server| {
            let meek = server.meek.as_ref().expect("fronted");
            meek.dial == edge && meek.port == 80 && !meek.https && !meek.disable_sni
        }));
        assert!(servers.iter().any(|server| {
            let meek = server.meek.as_ref().expect("fronted");
            meek.dial == edge && meek.port == 80 && !meek.https && meek.disable_sni
        }));
    }

    #[test]
    fn a_fronted_override_matches_its_dial_host_and_provider() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{
                    "FrontedMeekDialOverrides": [{
                        "MatchFrontingProviderIDRegexes": ["^provider$"],
                        "MatchDialAddressRegexes": ["^front\\.example$"],
                        "MatchHostHeaderRegexes": ["^cdn\\.example$"],
                        "DialAddresses": ["edge.example:443"],
                        "SNIServerName": "sni.example",
                        "VerifyServerNames": ["cdn.example"],
                        "TLSProfile": "chrome_120"
                    }]
                }"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: Some("provider".to_owned()),
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        let variant = servers
            .iter()
            .find(|server| {
                server
                    .meek
                    .as_ref()
                    .is_some_and(|meek| meek.dial == "edge.example")
            })
            .expect("matched override");
        let meek = variant.meek.as_ref().expect("fronted");
        assert_eq!(meek.sni, "sni.example");
        assert_eq!(meek.verify_server_names, vec!["cdn.example"]);
        assert_eq!(
            meek.shape.profiles,
            vec![Fingerprint::resolve("chrome_120").expect("profile")]
        );
    }

    #[test]
    fn an_http_fronted_override_keeps_only_the_dial_and_host() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{
                    "FrontedMeekDialOverrides": [{
                        "DialAddresses": ["edge.example:80"],
                        "SNIServerName": "sni.example",
                        "ALPNProtocols": ["http/1.1"],
                        "TLSProfile": "chrome_120",
                        "VerifyServerNames": ["cdn.example"]
                    }]
                }"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 80,
            host: "cdn.example".to_owned(),
            sni: String::new(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 80)],
            hosts: vec!["cdn.example".to_owned()],
            https: false,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-HTTP-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        let meek = servers
            .iter()
            .filter_map(|server| server.meek.as_ref())
            .find(|meek| meek.dial == "edge.example")
            .expect("http override");
        assert_eq!(meek.sni, "");
        assert!(meek.disable_sni);
        assert_eq!(meek.alpn, Vec::<Vec<u8>>::new());
        assert_eq!(meek.verify_server_names, Vec::<String>::new());
        assert_ne!(
            meek.shape.profiles,
            vec![Fingerprint::resolve("chrome_120").expect("profile")]
        );
    }

    #[test]
    fn a_quic_override_keeps_a_routable_sni_for_an_edge_ip() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{
                    "FrontedMeekDialOverrides": [{
                        "DialAddresses": ["192.0.2.9:443"],
                        "SNIServerName": "192.0.2.9",
                        "ALPNProtocols": ["http/1.1"],
                        "TLSProfile": "chrome_120",
                        "VerifyServerNames": ["cdn.example"]
                    }]
                }"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: vec![b"h3".to_vec()],
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: true,
            fronted: true,
            protocol: "FRONTED-MEEK-QUIC-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        let meek = servers
            .iter()
            .filter_map(|server| server.meek.as_ref())
            .find(|meek| meek.dial == "192.0.2.9")
            .expect("quic override");
        assert_eq!(meek.sni, "front.example");
        assert_eq!(meek.alpn, vec![b"h3".to_vec()]);
        assert_eq!(meek.verify_server_names, Vec::<String>::new());
        assert_eq!(meek.verify_pins, Vec::<String>::new());
        assert_ne!(
            meek.shape.profiles,
            vec![Fingerprint::resolve("chrome_120").expect("profile")]
        );
    }

    #[test]
    fn a_fronted_override_keeps_its_tls_profile_after_session_settings() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"FrontedMeekDialOverrides":[{"DialAddresses":["edge.example:443"],"TLSProfile":"chrome_120"}]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_session_settings(&mut servers, &settings);
        apply_fronting_overrides(&mut servers, &settings);
        let meek = servers
            .iter()
            .filter_map(|server| server.meek.as_ref())
            .find(|meek| meek.dial == "edge.example")
            .expect("matched override");
        assert_eq!(
            meek.shape.profiles,
            vec![Fingerprint::resolve("chrome_120").expect("profile")]
        );
    }

    #[test]
    fn a_fronted_override_that_does_not_match_is_skipped() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{
                    "FrontedMeekDialOverrides": [{
                        "MatchDialAddressRegexes": ["^other\\.example$"],
                        "DialAddresses": ["edge.example:443"],
                        "SNIServerName": "sni.example"
                    }]
                }"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        assert!(servers.iter().all(|server| server
            .meek
            .as_ref()
            .is_some_and(|meek| meek.dial == "front.example")));
    }

    #[test]
    fn a_shirokhorshid_selection_defaults_to_beast_mode() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"protocolSelection":"auto"}"#).expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.workers, 30);
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"protocolSelection":"auto","beastMode":false}"#).expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.workers, 10);
        let settings =
            Settings::from_json(Some(&json::parse("{}").expect("settings"))).expect("settings");
        assert_eq!(settings.workers, 10);
    }

    #[test]
    fn the_fastly_set_adds_its_override() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"cdnSets":["fastly"]}"#).expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.fronted_overrides.len(), 1);
        assert_eq!(settings.fronted_overrides[0].dials, vec!["pypi.org"]);
        assert_eq!(settings.fronted_overrides[0].snis, vec!["pypi.org"]);
        assert_eq!(
            settings.fronted_overrides[0].alpn,
            vec![b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn a_disable_sni_override_clears_the_name() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"FrontedMeekDialOverrides":[{"DialAddresses":["192.0.2.9:443"],"DisableSNI":true}]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(true);
        server.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let mut servers = vec![server];
        apply_fronting_overrides(&mut servers, &settings);
        let meek = servers
            .iter()
            .filter_map(|server| server.meek.as_ref())
            .find(|meek| meek.dial == "192.0.2.9")
            .expect("override candidate");
        assert_eq!(meek.sni, "");
        assert!(meek.disable_sni);
    }

    #[test]
    fn a_front_only_entry_without_meek_config_is_not_dialable() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedKey":"k","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        assert!(decode_entry(&encoded).is_none());
    }

    #[test]
    fn a_fronted_limit_drops_entries_without_a_front() {
        let mut fronted = test_server(true);
        fronted.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let selected = select_protocols(vec![test_server(false), fronted], &[], &[], 0, true);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].meek.is_some());
    }

    #[test]
    fn fronting_off_keeps_direct_entries_and_drops_front_only() {
        let meek = || crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        };
        let mut direct = test_server(true);
        direct.meek = Some(meek());
        let mut front_only = test_server(true);
        front_only.direct = false;
        front_only.meek = Some(meek());
        let selected = select_protocols(vec![direct, front_only], &[], &[], 0, false);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].direct);
        assert!(selected[0].meek.is_none());
    }

    #[test]
    fn auto_keeps_front_only_entries_as_a_fallback() {
        let mut front_only = test_server(true);
        front_only.direct = false;
        front_only.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let selected = select_protocols_with(
            vec![test_server(false), front_only],
            &[],
            &[],
            0,
            false,
            true,
            None,
        );
        assert_eq!(selected.len(), 2);
        assert!(selected[1].meek.is_some());
    }

    #[test]
    fn fronting_off_keeps_unfronted_meek_entries() {
        let mut unfronted = test_server(true);
        unfronted.direct = false;
        unfronted.meek = Some(crate::psiphon_meek::Meek {
            dial: "192.0.2.1".to_owned(),
            port: 8443,
            host: "192.0.2.1".to_owned(),
            sni: "192.0.2.1".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("192.0.2.1".to_owned(), 8443)],
            hosts: vec!["192.0.2.1".to_owned()],
            https: true,
            quic: false,
            fronted: false,
            protocol: "UNFRONTED-MEEK-HTTPS-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let selected = select_protocols(vec![test_server(false), unfronted], &[], &[], 0, false);
        assert_eq!(selected.len(), 2);
        assert!(selected
            .iter()
            .any(|server| server.meek.as_ref().is_some_and(|meek| !meek.fronted)));
    }

    #[test]
    fn a_cidr_candidate_expands_to_its_first_256_addresses() {
        let candidates = expand_cidr("198.51.100.0/24");
        assert_eq!(candidates.len(), 256);
        assert_eq!(candidates[0], "198.51.100.0");
        assert_eq!(candidates[255], "198.51.100.255");
        assert_eq!(expand_cidr("198.51.100.7/32"), vec!["198.51.100.7"]);
        assert_eq!(
            expand_cidr("front.example:8443"),
            vec!["front.example:8443"]
        );
    }

    #[test]
    fn a_bare_ipv6_front_keeps_its_address() {
        assert_eq!(
            split_fronting_address_with("2001:db8::1", 443),
            ("2001:db8::1".to_owned(), 443)
        );
    }

    #[test]
    fn a_compartment_defaults_to_the_public_id() {
        let settings = Settings::from_json(None).expect("settings");
        assert_eq!(settings.compartment, PRIVATE_COMPARTMENT_ID);
    }

    #[test]
    fn a_private_conduit_mode_uses_the_personal_compartment() {
        let settings = json::parse(r#"{"conduitMode":"private"}"#).expect("settings");
        assert!(matches!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .conduit_mode,
            ConduitMode::Shirokhorshid
        ));
    }

    #[test]
    fn the_shirokhorshid_identity_is_the_default() {
        let settings = Settings::from_json(None).expect("settings");
        assert_eq!(settings.sponsor, SPONSOR_ID);
        assert_eq!(settings.propagation, PROPAGATION_CHANNEL_ID);
        assert_eq!(settings.client_version, CLIENT_VERSION);
        assert_eq!(settings.platform, "Android");
    }

    #[test]
    fn custom_headers_accept_a_string_and_an_array() {
        let settings =
            json::parse(r#"{"CustomHeaders":{"X-One":"a","X-Two":["b","c"]}}"#).expect("settings");
        let headers = custom_headers(Some(&settings));
        let got: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(got, [("X-One", "a"), ("X-Two", "b"), ("X-Two", "c")]);
    }

    #[test]
    fn osl_roots_decode_transfer_urls_and_the_legacy_single_url() {
        let encoded = ferrox_core::b64::encode(b"https://osl.example/root");
        let text = format!(
            r#"{{"ObfuscatedServerListRootURLs":[{{"URL":"{encoded}"}},{{"URL":"https://plain.example"}}]}}"#
        );
        let settings = json::parse(&text).expect("settings");
        let roots = osl_roots(Some(&settings));
        let urls: Vec<&str> = roots.iter().map(|root| root.url.as_str()).collect();
        assert_eq!(urls, ["https://osl.example/root", "https://plain.example"]);
        assert!(!roots[0].skip_verify);
        let settings = json::parse(r#"{"ObfuscatedServerListRootURL":"https://legacy.example"}"#)
            .expect("settings");
        assert_eq!(osl_roots(Some(&settings))[0].url, "https://legacy.example");
    }

    #[test]
    fn transfer_root_carries_per_url_headers_and_skip_verify() {
        let settings = json::parse(
            r#"{"CustomHeaders":{"X-Global":"g","X-Both":"global"},"ObfuscatedServerListRootURLs":[{"URL":"https://osl.example","SkipVerify":true,"RequestHeaders":{"X-Both":["local"],"X-Local":"v"}}]}"#,
        )
        .expect("settings");
        let roots = osl_roots(Some(&settings));
        assert!(roots[0].skip_verify);
        assert_eq!(
            roots[0].headers,
            [
                ("X-Global".to_owned(), "g".to_owned()),
                ("X-Both".to_owned(), "local".to_owned()),
                ("X-Local".to_owned(), "v".to_owned())
            ]
        );
    }

    #[test]
    fn ssh_algorithms_accept_only_the_names_this_engine_carries() {
        let settings = json::parse(
            r#"{"ObfuscatedSSHAlgorithms":["curve25519-sha256","aes128-ctr","hmac-sha2-256","ssh-ed25519"]}"#,
        )
        .expect("settings");
        assert_eq!(
            ssh_algorithms(Some(&settings)),
            Some([
                "curve25519-sha256".to_owned(),
                "aes128-ctr".to_owned(),
                "hmac-sha2-256".to_owned(),
                "ssh-ed25519".to_owned()
            ])
        );
        let settings = json::parse(
            r#"{"ObfuscatedSSHAlgorithms":["diffie-hellman-group14-sha256","aes128-ctr","hmac-sha2-256","ssh-ed25519"]}"#,
        )
        .expect("settings");
        assert_eq!(ssh_algorithms(Some(&settings)), None);
    }

    #[test]
    fn additional_custom_headers_follow_the_base_map() {
        let settings = json::parse(
            r#"{"CustomHeaders":{"X-One":"a","X-Two":"old"},"AdditionalCustomHeaders":{"X-Two":["b","c"]}}"#,
        )
        .expect("settings");
        let headers = custom_headers(Some(&settings));
        let got: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(got, [("X-One", "a"), ("X-Two", "b"), ("X-Two", "c")]);
    }

    #[test]
    fn additional_custom_headers_reach_dial_headers() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"MeekAdditionalHeaders":{"X-One":"a"},"AdditionalCustomHeaders":{"X-Two":"b"}}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(
            settings.meek_headers,
            vec![
                ("X-One".to_owned(), "a".to_owned()),
                ("X-Two".to_owned(), "b".to_owned()),
            ]
        );
    }

    #[test]
    fn the_obfuscated_ssh_padding_window_is_read() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"ObfuscatedSSHMinPadding":100,"ObfuscatedSSHMaxPadding":200,"OSSHPrefixSplitMinDelay":5000000}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.tls_shape.obfuscated_min_padding, 100);
        assert_eq!(settings.tls_shape.obfuscated_max_padding, 200);
        assert_eq!(
            settings.tls_shape.ossh_prefix.split_min,
            Duration::from_millis(5)
        );
    }

    #[test]
    fn a_dial_port_list_reads_scalars_ranges_and_the_all_key() {
        let settings = json::parse(
            r#"{"LimitTunnelDialPortNumbers":{"SSH":[[10,11]],"QUIC-OSSH":[30,31,[40,41]],"All":"80-81"}}"#,
        )
        .expect("settings");
        let lists = port_lists(Some(&settings));
        let ssh = lists.iter().find(|(name, _)| name == "SSH").expect("ssh");
        assert!(ssh.1.contains(10));
        assert!(ssh.1.contains(11));
        assert!(!ssh.1.contains(12));
        let quic = lists
            .iter()
            .find(|(name, _)| name == "QUIC-OSSH")
            .expect("quic");
        assert!(quic.1.contains(31));
        assert!(quic.1.contains(41));
        let all = lists.iter().find(|(name, _)| name == "ALL").expect("all");
        assert!(all.1.contains(81));
    }

    #[test]
    fn a_dial_port_limit_selects_an_allowed_sibling() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedKey":"o","sshShadowsocksPort":9000,"sshShadowsocksKey":"s","sshHostKey":"AAAA","capabilities":["SSH","SHADOWSOCKS-OSSH"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let limits = vec![(
            "ALL".to_owned(),
            PortList {
                ranges: vec![(9000, 9000)],
            },
        )];
        let selected = apply_dial_port_limits(vec![server.clone()], &limits, None, false, &[]);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].ss);
        assert_eq!(selected[0].port, 9000);
        let refused = vec![(
            "All".to_owned(),
            PortList {
                ranges: vec![(443, 443), (8443, 8443)],
            },
        )];
        assert!(apply_dial_port_limits(vec![server], &refused, None, false, &[]).is_empty());
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedPort":443,"sshObfuscatedKey":"k","sshHostKey":"AAAA"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let plain = vec![(
            "All".to_owned(),
            PortList {
                ranges: vec![(22, 22)],
            },
        )];
        let selected = apply_dial_port_limits(vec![server.clone()], &plain, None, false, &[]);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].port, 22);
        assert!(!selected[0].obfuscated());
        let obfuscated_only = vec!["OSSH".to_owned()];
        let filter = shape_filter(&obfuscated_only, "test");
        assert!(apply_dial_port_limits(
            vec![server.clone()],
            &plain,
            filter,
            false,
            &obfuscated_only
        )
        .is_empty());
        let selected =
            select_protocols_with(vec![server.clone()], &[], &[], 0, false, true, Some(&plain));
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].port, 22);
        assert!(!selected[0].obfuscated());
        let named = vec![(
            "SSH".to_owned(),
            PortList {
                ranges: vec![(22, 22)],
            },
        )];
        let selected = apply_dial_port_limits(vec![server], &named, None, false, &[]);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].port, 443);
        let mut fronted = test_server(true);
        fronted.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 8443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 8443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        let https = vec![(
            "All".to_owned(),
            PortList {
                ranges: vec![(443, 443)],
            },
        )];
        let selected = apply_dial_port_limits(vec![fronted], &https, None, false, &[]);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].meek.as_ref().expect("fronted").port, 8443);
    }

    #[test]
    fn a_prioritized_protocol_moves_to_the_front() {
        let plain = test_server(true);
        let mut quic = test_server(true);
        quic.quic = true;
        quic.port = 4443;
        quic.quic_versions = vec!["QUICv1".to_owned()];
        let mut servers = vec![plain, quic];
        prioritize_servers(&mut servers, &["QUIC-OSSH".to_owned()], 1);
        assert!(servers[0].quic);
    }

    #[test]
    fn an_obfuscated_port_wins_when_it_has_a_key() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedPort":443,"sshObfuscatedKey":"k","sshHostKey":"AAAA"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert_eq!(server.port, 443);
        assert!(server.obfuscated());
    }

    #[test]
    fn a_quic_limit_selects_the_quic_sibling() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedPort":443,"sshObfuscatedQUICPort":4443,"sshObfuscatedKey":"k","sshHostKey":"AAAA"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert_eq!(server.port, 443);
        assert!(!server.quic);
        let selected = select_protocols(vec![server], &["QUIC-OSSH".to_owned()], &[], 0, false);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].quic);
        assert_eq!(selected[0].port, 4443);
    }

    #[test]
    fn a_quic_only_entry_survives_without_an_obfuscated_port() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedQUICPort":4443,"sshObfuscatedKey":"k","sshHostKey":"AAAA"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        assert!(server.quic);
        assert_eq!(server.port, 4443);
    }

    #[test]
    fn a_quic_limit_selects_obfuscated_quicv1() {
        let mut server = test_server(true);
        server.quic_port = Some(4443);
        server.quic_versions = vec!["OBFUSCATED-QUICv1".to_owned()];
        let selected = select_protocols(vec![server], &["QUIC-OSSH".to_owned()], &[], 0, false);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].quic);
    }

    #[test]
    fn a_quic_limit_selects_a_randomized_quicv1() {
        let mut server = test_server(true);
        server.quic_port = Some(4443);
        server.quic_versions = vec!["RANDOMIZED-QUICv1".to_owned()];
        let selected = select_protocols(vec![server], &["QUIC-OSSH".to_owned()], &[], 0, false);
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].quic_versions,
            vec!["RANDOMIZED-QUICv1".to_owned()]
        );
    }

    #[test]
    fn alternate_dns_servers_are_parsed() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"DNSResolverAlternateServers":["192.0.2.53","[2001:db8::1]:5353","not-an-address"]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(
            settings.dns_servers,
            vec![
                SocketAddr::from(([192, 0, 2, 53], 53)),
                SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 5353)),
            ]
        );
    }

    /// The five DNS knobs reach the runtime config.
    #[test]
    fn dns_transforms_and_the_verified_extension_are_parsed() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{
                    "DNSResolverProtocolTransformProbability": 1.0,
                    "DNSResolverProtocolTransformSpecs": {"any": [["^12", "ef"]]},
                    "DNSResolverProtocolTransformScopedSpecNames": {"": ["any"]},
                    "DNSResolverQNameMustMatchProbability": 1.0,
                    "DNSResolverCacheExtensionVerifiedTTLMilliseconds": 60000
                }"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.dns.transform_probability, 1.0);
        assert_eq!(settings.dns.qname_must_match_probability, 1.0);
        assert_eq!(
            settings.dns.cache_extension_verified,
            std::time::Duration::from_secs(60)
        );
    }

    #[test]
    fn a_quic_noise_profile_reaches_each_entry() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"QUICNoiseProfile":"gfw"}"#).expect("settings"),
        ))
        .expect("settings");
        let mut servers = [test_server(true)];
        apply_session_settings(&mut servers, &settings);
        assert_eq!(servers[0].quic_noise.as_deref(), Some("gfw"));
    }

    #[test]
    fn a_client_quic_limit_narrows_an_entry() {
        let mut server = test_server(true);
        server.quic_port = Some(4443);
        server.quic_versions = vec!["OBFUSCATED-QUICv1".to_owned(), "QUICv1".to_owned()];
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"LimitQUICVersions":["QUICv1"]}"#).expect("settings"),
        ))
        .expect("settings");
        let servers = limit_quic_versions(vec![server], &settings);
        assert_eq!(servers[0].quic_versions, vec!["QUICv1".to_owned()]);
    }

    #[test]
    fn a_client_quic_limit_drops_an_inproxy_fronted_h3_destination() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","sshObfuscatedKey":"k","meekCookieEncryptionPublicKey":"c","meekObfuscatedKey":"m","meekFrontingAddresses":["front.example:443"],"meekFrontingHosts":["cdn.example"],"capabilities":["INPROXY-WEBRTC-FRONTED-MEEK-QUIC-OSSH"],"inproxyMeekPort":2050,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"LimitQUICVersions":["OBFUSCATED-QUICv1"]}"#).expect("settings"),
        ))
        .expect("settings");
        assert!(limit_quic_versions(vec![server], &settings).is_empty());
    }

    #[test]
    fn a_client_quic_limit_drops_an_inproxy_quic_destination_without_a_shared_version() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","sshObfuscatedKey":"k","limitQUICVersions":["QUICv1"],"capabilities":["INPROXY-WEBRTC-QUIC-OSSH"],"inproxyQUICPort":443,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"LimitQUICVersions":["OBFUSCATED-QUICv1"]}"#).expect("settings"),
        ))
        .expect("settings");
        assert!(limit_quic_versions(vec![server], &settings).is_empty());
    }

    #[test]
    fn session_headers_reach_an_inproxy_meek_entry() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","sshObfuscatedKey":"k","meekCookieEncryptionPublicKey":"c","meekObfuscatedKey":"m","meekFrontingAddresses":["front.example:443"],"meekFrontingHosts":["cdn.example"],"capabilities":["INPROXY-WEBRTC-FRONTED-MEEK-OSSH"],"inproxyMeekPort":2050,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry_with(&encoded, true, &[]).expect("entry");
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"MeekAdditionalHeaders":{"X-Test":"one"}}"#).expect("settings"),
        ))
        .expect("settings");
        let mut servers = [server];
        apply_session_settings(&mut servers, &settings);
        let meek = servers[0].inproxy_meek.as_ref().expect("in-proxy meek");
        assert_eq!(meek.headers, vec![("X-Test".to_owned(), "one".to_owned())]);
    }

    #[test]
    fn a_target_with_an_inproxy_destination_and_a_meek_sibling_is_accepted() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","sshObfuscatedKey":"k","meekCookieEncryptionPublicKey":"c","meekObfuscatedKey":"m","capabilities":["UNFRONTED-MEEK-HTTPS","INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH"],"meekServerPort":8443,"inproxyMeekPort":2050,"signature":"AA=="}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let text = format!(
            r#"{{"TargetServerEntry":"{encoded}","LimitTunnelProtocols":["INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH"]}}"#
        );
        let settings =
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings");
        let server = load_target_entry(&settings, &encoded, true, true).expect("target");
        let destination = server.inproxy.expect("in-proxy destination");
        assert_eq!(destination.base_protocol(), "UNFRONTED-MEEK-HTTPS-OSSH");
    }

    #[test]
    fn a_target_honors_the_dial_port_limit() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedPort":443,"sshObfuscatedKey":"k","sshHostKey":"AAAA"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let text = format!(
            r#"{{"TargetServerEntry":"{encoded}","LimitTunnelDialPortNumbers":{{"All":[22]}}}}"#
        );
        let settings =
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings");
        let error = load_target_entry(&settings, &encoded, true, false)
            .expect_err("the target has no permitted dial port");
        assert!(error.contains("no dial port allowed"));
    }

    #[test]
    fn a_client_quic_limit_demotes_a_fronted_h3_entry() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK","FRONTED-MEEK-QUIC"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("entry");
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"LimitQUICVersions":["OBFUSCATED-QUICv1"]}"#).expect("settings"),
        ))
        .expect("settings");
        let servers = limit_quic_versions(vec![server], &settings);
        let meek = servers[0].meek.as_ref().expect("fronted");
        assert!(!meek.quic);
        assert_eq!(meek.protocol, "FRONTED-MEEK-OSSH");
    }

    #[test]
    fn a_pre_selection_target_quic_limit_is_reported() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","sshObfuscatedKey":"k","sshObfuscatedQUICPort":4443,"limitQUICVersions":["OBFUSCATED-QUICv1"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let text = format!(
            r#"{{"TargetServerEntry":"{encoded}","LimitQUICVersions":["QUICv1"],"LimitTunnelProtocols":["QUIC-OSSH"]}}"#
        );
        let settings =
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings");
        let error = load_target_entry(&settings, &encoded, true, false)
            .expect_err("the target has no permitted QUIC version");
        assert!(error.contains("no QUIC version allowed"));
    }

    #[test]
    fn an_inproxy_quic_limit_does_not_match_plain_ossh() {
        let mut plain = test_server(true);
        plain.inproxy = Some(crate::psiphon_broker::Destination {
            address: "192.0.2.1:443".to_owned(),
            network_protocol: 0,
            protocol: "INPROXY-WEBRTC-OSSH",
            packed_server_entry: Vec::new(),
        });
        let selected = select_protocols(
            vec![plain],
            &["INPROXY-WEBRTC-QUIC-OSSH".to_owned()],
            &[],
            0,
            false,
        );
        assert!(selected.is_empty());
        let mut quic = test_server(true);
        quic.inproxy = Some(crate::psiphon_broker::Destination {
            address: "192.0.2.1:443".to_owned(),
            network_protocol: 0,
            protocol: "INPROXY-WEBRTC-QUIC-OSSH",
            packed_server_entry: Vec::new(),
        });
        let selected = select_protocols(
            vec![quic],
            &["INPROXY-WEBRTC-QUIC-OSSH".to_owned()],
            &[],
            0,
            false,
        );
        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn a_client_quic_limit_drops_an_entry_with_no_shared_version() {
        let mut server = test_server(true);
        server.port = 4443;
        server.quic = true;
        server.quic_port = Some(4443);
        server.quic_versions = vec!["DECOY-QUICv1".to_owned()];
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"LimitQUICVersions":["QUICv1"]}"#).expect("settings"),
        ))
        .expect("settings");
        let servers = limit_quic_versions(vec![server], &settings);
        assert!(servers.is_empty());
    }

    #[test]
    fn a_quic_limit_without_a_supported_version_does_not_select_quic() {
        let mut server = test_server(true);
        server.quic_port = Some(4443);
        server.quic_versions = vec!["QUIC_VERSION_GQUIC43".to_owned()];
        let selected = select_protocols(vec![server], &["QUIC-OSSH".to_owned()], &[], 0, false);
        assert!(selected.is_empty());
    }

    fn test_server(obfuscated: bool) -> Server {
        Server {
            host: "192.0.2.1".to_owned(),
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 22,
            ssh_port: Some(22),
            user: String::new(),
            password: String::new(),
            host_key: Vec::new(),
            obfuscation_key: obfuscated.then(|| "k".to_owned()),
            tls_obfuscation_key: None,
            meek_obfuscated_key: None,
            region: None,
            provider_id: None,
            fronting_provider_id: None,
            scan_cdn: true,
            ssh_api: true,
            direct: true,
            tls: false,
            tls_port: None,
            quic: false,
            quic_port: None,
            quic_versions: Vec::new(),
            quic_noise: None,
            ss: false,
            shadowsocks: None,
            meek: None,
            unfronted_meek: None,
            inproxy_meek: None,
            tactics: None,
            inproxy: None,
            tls_inproxy: None,
            inproxy_shadowsocks_key: None,
            channel_window: crate::psiphon_ssh::DEFAULT_CHANNEL_WINDOW,
        }
    }

    #[test]
    fn a_runtime_entry_must_still_match_the_cdn_lane() {
        let protocols = selection_protocols(Some("cdn_fronting"));
        assert!(!entry_allowed(&test_server(true), &protocols, true));
        let mut fronted = test_server(false);
        fronted.direct = false;
        fronted.meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-CDN-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        assert!(entry_allowed(&fronted, &protocols, true));
    }

    #[test]
    fn a_meek_only_limit_drops_a_direct_ossh_server() {
        let selected = select_protocols(
            vec![test_server(true)],
            &["FRONTED-MEEK-OSSH".to_owned()],
            &[],
            0,
            false,
        );
        assert!(selected.is_empty());
        let selected = select_protocols(
            vec![test_server(true)],
            &["FRONTED-MEEK-OSSH".to_owned(), "OSSH".to_owned()],
            &[],
            0,
            false,
        );
        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn a_tls_variant_drops_an_inproxy_destination_that_cannot_carry_tls() {
        let mut capable = test_server(true);
        capable.tls_port = Some(8443);
        capable.inproxy = Some(crate::psiphon_broker::Destination {
            address: "192.0.2.1:443".to_owned(),
            network_protocol: 0,
            protocol: "INPROXY-WEBRTC-OSSH",
            packed_server_entry: Vec::new(),
        });
        let selected = select_protocols(
            vec![capable.clone()],
            &["TLS-OSSH".to_owned()],
            &[],
            0,
            false,
        );
        assert_eq!(selected.len(), 1);
        assert!(selected[0].tls);
        assert!(
            selected[0].inproxy.is_none(),
            "a plain in-proxy destination must not bypass TLS"
        );
        let mut tls = capable;
        tls.tls_inproxy = Some(crate::psiphon_broker::Destination {
            address: "192.0.2.1:8443".to_owned(),
            network_protocol: 0,
            protocol: "INPROXY-WEBRTC-TLS-OSSH",
            packed_server_entry: Vec::new(),
        });
        let selected = select_protocols(vec![tls], &["TLS-OSSH".to_owned()], &[], 0, false);
        assert_eq!(
            selected[0]
                .inproxy
                .as_ref()
                .map(crate::psiphon_broker::Destination::base_protocol),
            Some("TLS-OSSH")
        );
    }

    #[test]
    fn a_mixed_limit_keeps_the_tls_variant_and_drops_direct_ossh() {
        let mut capable = test_server(true);
        capable.tls_port = Some(8443);
        let selected = select_protocols(
            vec![capable.clone(), test_server(true)],
            &["FRONTED-MEEK-OSSH".to_owned(), "TLS-OSSH".to_owned()],
            &[],
            0,
            false,
        );
        assert_eq!(selected.len(), 1);
        assert!(selected[0].tls);
        let selected = select_protocols(
            vec![capable, test_server(true)],
            &["SSH".to_owned()],
            &["FRONTED-MEEK-OSSH".to_owned(), "TLS-OSSH".to_owned()],
            1,
            false,
        );
        assert_eq!(selected.len(), 1);
        assert!(selected[0].tls);
    }

    #[test]
    fn a_tactics_entry_keeps_its_keys_and_front() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK-TACTICS"],"tacticsRequestPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","tacticsRequestObfuscatedKey":"dGFjdGljcw==","meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["203.0.113.9"],"meekFrontingHosts":["front.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("tactics");
        let keys = server.tactics.expect("tactics keys");
        assert_eq!(
            keys.public_key,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(keys.obfuscated_key, "dGFjdGljcw==");
        assert_eq!(keys.meek.dial, "203.0.113.9");
        assert_eq!(keys.meek.host, "front.example");
        assert_eq!(keys.meek.sni, "203.0.113.9");
        assert_eq!(keys.meek.port, 443);
    }

    #[test]
    fn a_tactics_only_entry_survives_default_settings() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK-TACTICS"],"tacticsRequestPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","tacticsRequestObfuscatedKey":"dGFjdGljcw==","meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingHosts":["front.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let settings = Settings::from_json(Some(
            &json::parse(&format!(
                r#"{{"TargetServerEntry":"{encoded}","LimitTunnelProtocols":["SSH"]}}"#
            ))
            .expect("json"),
        ))
        .expect("settings");
        let servers = load_tactics_entries(&settings).expect("tactics entries");
        assert!(servers[0].tactics.is_some());
        assert!(load_entries(&settings).is_err());
    }

    #[test]
    fn a_fronting_override_reaches_the_tactics_front() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK-TACTICS","UNFRONTED-MEEK"],"tacticsRequestPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","tacticsRequestObfuscatedKey":"dGFjdGljcw==","meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingHosts":["front.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let settings = Settings::from_json(Some(
            &json::parse(&format!(
                r#"{{"TargetServerEntry":"{encoded}","cdnIps":["198.51.100.7"],"cdnSni":["edge.example"]}}"#
            ))
            .expect("json"),
        ))
        .expect("settings");
        let servers = load_tactics_entries(&settings).expect("tactics entries");
        let keys = servers[0].tactics.as_ref().expect("tactics keys");
        assert_eq!(keys.meek.dial, "198.51.100.7");
        assert_eq!(keys.meek.sni, "edge.example");
        assert_eq!(
            servers[0].meek.as_ref().expect("tunnel front").dial,
            "192.0.2.1"
        );
    }

    #[test]
    fn a_fronted_filter_keeps_a_named_shadowsocks_sibling() {
        let fronted = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let ssh = r#"{"ipAddress":"192.0.2.2","sshShadowsocksPort":9000,"sshShadowsocksKey":"s","sshHostKey":"AAAA","capabilities":["SHADOWSOCKS-OSSH"]}"#;
        let servers = vec![
            decode_entry(&hex(format!("0 0 0 0 {fronted}").as_bytes())).expect("fronted"),
            decode_entry(&hex(format!("0 0 0 0 {ssh}").as_bytes())).expect("shadowsocks"),
        ];
        let selected = select_protocols(servers, &["SHADOWSOCKS-OSSH".to_owned()], &[], 0, true);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].ss);
        assert_eq!(selected[0].port, 9000);
    }

    #[test]
    fn a_direct_limit_drops_an_unfronted_meek_server() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["UNFRONTED-MEEK-HTTPS"],"meekServerPort":8443,"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk"}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("unfronted");
        let selected = select_protocols(vec![server], &["OSSH".to_owned()], &[], 0, false);
        assert!(selected.is_empty());
    }

    #[test]
    fn a_direct_limit_keeps_a_direct_entry_that_also_has_meek() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshHostKey":"AAAA","capabilities":["SSH","FRONTED-MEEK"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let encoded = hex(format!("0 0 0 0 {entry}").as_bytes());
        let server = decode_entry(&encoded).expect("dual");
        let selected = select_protocols(vec![server], &["SSH".to_owned()], &[], 0, false);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].meek.is_none());
        assert_eq!(selected[0].port, 22);
    }

    #[test]
    fn a_protocol_limit_keeps_only_the_named_ssh_shape() {
        let servers = || vec![test_server(false), test_server(true)];
        let shapes = |selected: Vec<Server>| {
            selected
                .into_iter()
                .map(|server| server.obfuscated())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["SSH".to_owned()],
                &[],
                0,
                false
            )),
            [false]
        );
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["UNFRONTED-OSSH".to_owned()],
                &[],
                0,
                false
            )),
            [true]
        );
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["SSH".to_owned(), "OSSH".to_owned()],
                &[],
                0,
                false
            )),
            [false, true]
        );
        assert!(select_protocols(servers(), &["TLS-OSSH".to_owned()], &[], 0, false).is_empty());
        let mut capable = test_server(true);
        capable.tls_port = Some(443);
        let selected = select_protocols(vec![capable], &["TLS-OSSH".to_owned()], &[], 0, false);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].tls);
        assert_eq!(selected[0].port, 443);
    }

    #[test]
    fn an_initial_protocol_limit_applies_to_its_first_candidates() {
        let servers = || {
            vec![
                test_server(false),
                test_server(true),
                test_server(false),
                test_server(true),
            ]
        };
        let shapes = |selected: Vec<Server>| {
            selected
                .into_iter()
                .map(|server| server.obfuscated())
                .collect::<Vec<_>>()
        };
        // The first two OSSH candidates lead; the normal limit keeps every plain entry after them.
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["SSH".to_owned()],
                &["OSSH".to_owned()],
                2,
                false
            )),
            [true, true, false, false]
        );
        // An entry the initial phase skips is not lost while it matches the normal limit.
        let servers = || vec![test_server(false), test_server(true), test_server(false)];
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["SSH".to_owned()],
                &["OSSH".to_owned()],
                1,
                false
            )),
            [true, false, false]
        );
        // No initial phase leaves the normal limit in force from the first entry.
        assert_eq!(
            shapes(select_protocols(
                servers(),
                &["SSH".to_owned()],
                &["OSSH".to_owned()],
                0,
                false
            )),
            [false, false]
        );
    }

    #[test]
    fn a_target_entry_still_honors_the_protocol_limit() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshHostKey":"AAAA"}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let settings = |protocol| {
            let text = format!(
                r#"{{"TargetServerEntry":"{target}","LimitTunnelProtocols":["{protocol}"]}}"#
            );
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings")
        };
        assert!(load_entries(&settings("OSSH")).is_err());
        let selected = load_entries(&settings("SSH")).expect("plain SSH is named");
        assert_eq!(selected.len(), 1);
        assert!(!selected[0].obfuscated());
    }

    #[test]
    fn a_target_tls_limit_promotes_the_tls_destination() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedPort":443,"sshObfuscatedKey":"k","tlsOSSHPort":8443,"sshHostKey":"AAAA","capabilities":["OSSH","TLS-OSSH","INPROXY-WEBRTC-OSSH","INPROXY-WEBRTC-TLS-OSSH"],"inproxyOSSHPort":443,"inproxyTlsOSSHPort":8443,"signature":"AA=="}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let text = format!(
            r#"{{"protocolSelection":"conduit","TargetServerEntry":"{target}","LimitTunnelProtocols":["TLS-OSSH"]}}"#
        );
        let settings =
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings");
        let selected = load_entries(&settings).expect("TLS destination");
        assert!(selected[0].tls);
        assert_eq!(
            selected[0]
                .inproxy
                .as_ref()
                .map(crate::psiphon_broker::Destination::base_protocol),
            Some("TLS-OSSH")
        );
    }

    #[test]
    fn a_target_tls_limit_promotes_when_no_shadowsocks_config_exists() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedPort":443,"sshObfuscatedKey":"k","tlsOSSHPort":8443,"sshHostKey":"AAAA","capabilities":["OSSH","TLS-OSSH"]}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let text = format!(
            r#"{{"TargetServerEntry":"{target}","LimitTunnelProtocols":["TLS-OSSH","SHADOWSOCKS-OSSH"]}}"#
        );
        let settings =
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings");
        let selected = load_entries(&settings).expect("TLS is named");
        assert!(selected[0].tls);
        assert_eq!(selected[0].port, 8443);
    }

    #[test]
    fn a_target_http_front_is_refused_by_an_https_limit() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["FRONTED-MEEK-HTTP"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let settings = |protocol| {
            let text = format!(
                r#"{{"TargetServerEntry":"{target}","LimitTunnelProtocols":["{protocol}"]}}"#
            );
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings")
        };
        assert!(load_entries(&settings("FRONTED-MEEK-OSSH")).is_err());
        let selected =
            load_entries(&settings("FRONTED-MEEK-CDN-HTTP-OSSH")).expect("HTTP is named");
        assert_eq!(selected.len(), 1);
        assert!(!selected[0].meek.as_ref().expect("meek").https);
    }

    #[test]
    fn a_target_direct_ossh_is_refused_by_a_meek_only_limit() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshObfuscatedPort":443,"sshObfuscatedKey":"k","sshHostKey":"AAAA"}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let settings = |protocols| {
            let text = format!(
                r#"{{"TargetServerEntry":"{target}","LimitTunnelProtocols":[{protocols}]}}"#
            );
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings")
        };
        assert!(load_entries(&settings(r#""FRONTED-MEEK-OSSH""#)).is_err());
        let selected = load_entries(&settings(r#""FRONTED-MEEK-OSSH","OSSH""#))
            .expect("mixed limit names OSSH");
        assert_eq!(selected.len(), 1);
        assert!(selected[0].obfuscated());
    }

    #[test]
    fn a_target_meek_is_refused_by_a_direct_limit() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshHostKey":"AAAA","capabilities":["UNFRONTED-MEEK-HTTPS"],"meekServerPort":8443,"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk"}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let text = format!(r#"{{"TargetServerEntry":"{target}","LimitTunnelProtocols":["OSSH"]}}"#);
        let settings =
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings");
        assert!(load_entries(&settings).is_err());
    }

    #[test]
    fn a_target_naming_both_shapes_keeps_the_base_entry() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedKey":"o","sshShadowsocksPort":9000,"sshShadowsocksKey":"s","sshHostKey":"AAAA","capabilities":["SSH","SHADOWSOCKS-OSSH"]}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let settings = |protocols| {
            let text = format!(
                r#"{{"TargetServerEntry":"{target}","LimitTunnelProtocols":[{protocols}]}}"#
            );
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings")
        };
        let both = load_entries(&settings(r#""SSH","SHADOWSOCKS-OSSH""#)).expect("both named");
        assert_eq!(both.len(), 1);
        assert!(!both[0].ss);
        assert_eq!(both[0].port, 22);
        let ss = load_entries(&settings(r#""SHADOWSOCKS-OSSH""#)).expect("SS named");
        assert_eq!(ss.len(), 1);
        assert!(ss[0].ss);
        assert_eq!(ss[0].port, 9000);
    }

    #[test]
    fn a_target_with_both_uses_its_direct_shape() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshHostKey":"AAAA","capabilities":["SSH","FRONTED-MEEK"],"meekCookieEncryptionPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","meekObfuscatedKey":"mk","meekFrontingAddresses":["front.example"],"meekFrontingHosts":["cdn.example"]}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let text = format!(r#"{{"TargetServerEntry":"{target}","LimitTunnelProtocols":["SSH"]}}"#);
        let settings =
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings");
        let selected = load_entries(&settings).expect("plain SSH is named");
        assert_eq!(selected.len(), 1);
        assert!(selected[0].meek.is_none());
        assert!(!selected[0].obfuscated());
    }

    #[test]
    fn a_target_uses_the_initial_limit_only_when_it_names_a_shape() {
        let entry = r#"{"ipAddress":"192.0.2.1","sshPort":22,"sshObfuscatedPort":443,"sshObfuscatedKey":"k","sshHostKey":"AAAA"}"#;
        let target = hex(format!("0 0 0 0 {entry}").as_bytes());
        let settings = |initial| {
            let text = format!(
                r#"{{"TargetServerEntry":"{target}","LimitTunnelProtocols":["SSH"],"InitialLimitTunnelProtocols":["{initial}"],"InitialLimitTunnelProtocolsCandidateCount":1}}"#
            );
            Settings::from_json(Some(&json::parse(&text).expect("settings"))).expect("settings")
        };
        assert!(
            load_entries(&settings("QUIC-OSSH")).is_err(),
            "an unsupported initial list must fall back to the normal limit"
        );
        let selected = load_entries(&settings("OSSH")).expect("the initial list names OSSH");
        assert_eq!(selected.len(), 1);
        assert!(selected[0].obfuscated());
    }

    #[test]
    fn a_protocol_limit_is_not_read_as_base64() {
        let settings =
            json::parse(r#"{"LimitTunnelProtocols":["AAAA","ossh"]}"#).expect("settings");
        assert_eq!(protocol_list(Some(&settings)), ["AAAA", "OSSH"]);
    }

    #[test]
    fn a_tunnel_pool_is_read_and_clamped_to_the_reference_ceiling() {
        let settings = json::parse(r#"{"TunnelPoolSize":99}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings)).expect("settings").pool,
            32
        );
        let settings = json::parse(r#"{"TunnelPoolSize":0}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings)).expect("settings").pool,
            1
        );
    }

    #[test]
    fn a_targeted_entry_pins_the_pool_to_one_tunnel() {
        let settings = json::parse(
            r#"{"TunnelPoolSize":8,"ConnectionWorkerPoolSize":8,"TargetServerEntry":"entry"}"#,
        )
        .expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert_eq!(settings.pool, 1);
        assert_eq!(settings.workers, 1);
    }

    #[test]
    fn a_limited_meek_buffer_is_read() {
        let settings = json::parse(r#"{"LimitMeekBufferSizes":true}"#).expect("settings");
        assert!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .limit_meek_buffers
        );
        let settings = json::parse(r#"{"LimitMeekBufferSizes":false}"#).expect("settings");
        assert!(
            !Settings::from_json(Some(&settings))
                .expect("settings")
                .limit_meek_buffers
        );
    }

    #[test]
    fn a_limited_relay_buffer_and_stagger_are_read() {
        let settings = json::parse(
            r#"{"LimitRelayBufferSizes":true,"StaggerConnectionWorkersMilliseconds":250}"#,
        )
        .expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert_eq!(settings.relay_buffer, 4 * 1024);
        assert_eq!(settings.stagger, Duration::from_millis(250));
        assert!(settings.keepalive.is_some());
        let quiet = json::parse(r#"{"DisablePeriodicSshKeepAlive":true}"#).expect("settings");
        assert!(Settings::from_json(Some(&quiet))
            .expect("settings")
            .keepalive
            .is_none());
    }

    #[test]
    fn the_reference_keepalive_window_is_read() {
        let defaults = Settings::from_json(None).expect("settings");
        let keepalive = defaults.keepalive.expect("keepalive");
        assert_eq!(keepalive.period_min, Duration::from_secs(60));
        assert_eq!(keepalive.period_max, Duration::from_secs(120));
        assert_eq!(keepalive.padding_min, 0);
        assert_eq!(keepalive.padding_max, 256);
        assert_eq!(keepalive.inactive, Duration::from_secs(10));
        assert_eq!(keepalive.timeout, Duration::from_secs(30));

        let settings = json::parse(
            r#"{"SSHKeepAlivePeriodMinMilliseconds":5000,"SSHKeepAlivePeriodMaxMilliseconds":6000,"SSHKeepAlivePaddingMinBytes":10,"SSHKeepAlivePaddingMaxBytes":20,"SSHKeepAlivePeriodicInactivePeriodMilliseconds":2000,"SSHKeepAlivePeriodicTimeoutMilliseconds":3000}"#,
        )
        .expect("settings");
        let keepalive = Settings::from_json(Some(&settings))
            .expect("settings")
            .keepalive
            .expect("keepalive");
        assert_eq!(keepalive.period_min, Duration::from_secs(5));
        assert_eq!(keepalive.period_max, Duration::from_secs(6));
        assert_eq!(keepalive.padding_min, 10);
        assert_eq!(keepalive.padding_max, 20);
        assert_eq!(keepalive.inactive, Duration::from_secs(2));
        assert_eq!(keepalive.timeout, Duration::from_secs(3));
    }

    #[test]
    fn the_reference_identity_pause_and_affinity_are_read() {
        let settings = json::parse(
            r#"{"PropagationChannelId":"abc","ClientPlatform":"Aether","ClientVersion":"2","EstablishTunnelPausePeriodSeconds":7,"EstablishTunnelServerAffinityGracePeriodMilliseconds":250}"#,
        )
        .expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert_eq!(settings.propagation, "abc");
        assert_eq!(settings.platform, "Aether");
        assert_eq!(settings.client_version, "2");
        assert_eq!(settings.pause, Duration::from_secs(7));
        assert_eq!(settings.affinity_grace, Duration::from_millis(250));
    }

    #[test]
    fn the_reference_device_identity_is_read() {
        let settings = json::parse(
            r#"{"DeviceRegion":"IR","DeviceLocation":"w3g","ClientFeatures":["coarse-location","unsafe-traffic-alerts"]}"#,
        )
        .expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert_eq!(settings.device_region.as_deref(), Some("IR"));
        assert_eq!(settings.device_location.as_deref(), Some("w3g"));
        assert_eq!(
            settings.client_features,
            vec![
                "coarse-location".to_owned(),
                "unsafe-traffic-alerts".to_owned()
            ]
        );
    }

    #[test]
    fn egress_region_selects_the_named_country() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"EgressRegion":" us "}"#).expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.region.as_deref(), Some("US"));
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"EgressRegion":""}"#).expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.region, None);
    }

    #[test]
    fn split_tunnel_settings_normalize_regions() {
        let settings = json::parse(
            r#"{"SplitTunnelOwnRegion":true,"SplitTunnelRegions":["us","DE","usa","de"]}"#,
        )
        .expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert!(settings.split_tunnel_own_region);
        assert_eq!(
            settings.split_tunnel_regions,
            vec!["US".to_owned(), "DE".to_owned()]
        );
    }

    #[test]
    fn queued_packets_leave_in_one_vectored_write() {
        struct Sink {
            calls: usize,
            bytes: Vec<u8>,
        }
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn write_vectored(&mut self, slices: &[IoSlice<'_>]) -> io::Result<usize> {
                self.calls += 1;
                let mut total = 0;
                for slice in slices {
                    self.bytes.extend_from_slice(slice);
                    total += slice.len();
                }
                Ok(total)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut channel = crate::psiphon_ssh::test_channel_with_chunks(&[b"aa", b"bb", b"cc"]);
        let mut sink = Sink {
            calls: 0,
            bytes: Vec::new(),
        };
        pump_channel(&mut channel, &mut sink, None);
        assert_eq!(sink.calls, 1);
        assert_eq!(sink.bytes, b"aabbcc");
    }

    #[test]
    fn aggressive_establishment_widens_the_race() {
        let settings = json::parse(r#"{"AggressiveEstablishment":true}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .workers,
            30
        );
        let settings = json::parse(r#"{"ConnectionWorkerPoolSize":32}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .workers,
            32
        );
        let settings =
            json::parse(r#"{"AggressiveEstablishment":true,"ConnectionWorkerPoolMaxSize":8}"#)
                .expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .workers,
            8
        );
    }

    #[test]
    fn limit_intensive_connection_workers_caps_one_batch() {
        let settings =
            json::parse(r#"{"LimitIntensiveConnectionWorkers":2,"ConnectionWorkerPoolSize":8}"#)
                .expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert_eq!(settings.intensive_workers, 2);
        let intensive = || {
            let mut server = test_server(true);
            server.quic = true;
            server
        };
        let entries = vec![
            intensive(),
            test_server(true),
            intensive(),
            intensive(),
            test_server(false),
        ];
        let (first, taken) = take_dial_batch(&entries, 0, 0, entries.len(), 5, 2, false);
        assert_eq!(taken, 3);
        assert!(first[0].quic && first[2].quic);
        assert!(!first[1].quic);
        let (second, taken) = take_dial_batch(&entries, 0, taken, entries.len(), 5, 2, false);
        assert_eq!(taken, 2);
        assert_eq!(first.len() + second.len(), entries.len());
        assert!(second.iter().any(|server| server.quic));
        assert!(second.iter().any(|server| !server.quic));
        let mut inproxy = test_server(false);
        inproxy.inproxy = Some(crate::psiphon_broker::Destination {
            address: "192.0.2.1".to_owned(),
            network_protocol: 0,
            protocol: "INPROXY-WEBRTC-OSSH",
            packed_server_entry: Vec::new(),
        });
        assert!(!server_is_intensive(&inproxy, false));
        assert!(server_is_intensive(&inproxy, true));
    }

    #[test]
    fn the_default_dial_budget_is_twenty_seconds() {
        let settings = Settings::from_json(None).expect("settings");
        assert_eq!(settings.dial_timeout(), Duration::from_secs(20));
    }

    #[test]
    fn a_steering_ttl_longer_than_a_day_is_kept() {
        let settings = json::parse(r#"{"SteeringIPCacheTTLSeconds":172800}"#).expect("settings");
        let config = dns_config(Some(&settings), &[]);
        assert_eq!(config.steering_ttl, Duration::from_hours(48));
    }

    #[test]
    fn a_latency_multiplier_scales_the_dial_budget() {
        let settings = json::parse(r#"{"NetworkLatencyMultiplier":2}"#).expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert_eq!(settings.dial_timeout(), DIAL_TIMEOUT * 2);
        let settings = json::parse(r#"{"NetworkLatencyMultiplier":1.5}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .dial_timeout(),
            DIAL_TIMEOUT.mul_f64(1.5)
        );
        let settings = json::parse(r#"{"NetworkLatencyMultiplier":0.5}"#).expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .dial_timeout(),
            DIAL_TIMEOUT.mul_f64(0.5)
        );
        let settings = json::parse(r#"{"DisableTimeouts":true}"#).expect("settings");
        let timeout = Settings::from_json(Some(&settings))
            .expect("settings")
            .dial_timeout();
        assert!(timeout >= DIAL_TIMEOUT && timeout <= DIAL_TIMEOUT.mul_f64(3.0));
        let settings = json::parse(r#"{"NetworkLatencyMultiplierLambda":0.1}"#).expect("settings");
        let timeout = Settings::from_json(Some(&settings))
            .expect("settings")
            .dial_timeout();
        assert!(timeout >= DIAL_TIMEOUT && timeout <= DIAL_TIMEOUT.mul_f64(3.0));
        let settings =
            json::parse(r#"{"NetworkLatencyMultiplierMin":2,"NetworkLatencyMultiplierMax":4}"#)
                .expect("settings");
        let timeout = Settings::from_json(Some(&settings))
            .expect("settings")
            .dial_timeout();
        assert!(timeout >= DIAL_TIMEOUT.mul_f64(2.0) && timeout <= DIAL_TIMEOUT.mul_f64(4.0));
        let settings = json::parse(
            r#"{"NetworkLatencyMultiplier":2,"NetworkLatencyMultiplierMin":4,"NetworkLatencyMultiplierMax":4,"DisableTimeouts":true}"#,
        )
        .expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .dial_timeout(),
            DIAL_TIMEOUT.mul_f64(2.0)
        );
        let settings =
            json::parse(r#"{"EstablishTunnelTimeoutSeconds":30,"NetworkLatencyMultiplier":2}"#)
                .expect("settings");
        assert_eq!(
            Settings::from_json(Some(&settings))
                .expect("settings")
                .dial_timeout(),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn a_shared_lane_listens_on_every_interface() {
        let settings = json::parse(r#"{"shareProxyOnNetwork":true}"#).expect("settings");
        assert_eq!(
            listen_address(Some(&settings)).expect("listen").to_string(),
            "0.0.0.0:1821"
        );
    }

    #[test]
    fn a_listen_interface_names_the_edge_address() {
        let any = json::parse(r#"{"ListenInterface":"any","LocalSocksProxyPort":1821}"#)
            .expect("settings");
        assert_eq!(
            listen_address(Some(&any)).expect("listen").to_string(),
            "0.0.0.0:1821"
        );
        let named = json::parse(r#"{"ListenInterface":"192.0.2.7","LocalSocksProxyPort":1821}"#)
            .expect("settings");
        assert_eq!(
            listen_address(Some(&named)).expect("listen").to_string(),
            "192.0.2.7:1821"
        );
    }

    #[test]
    fn a_disabled_local_socks_proxy_keeps_the_edge_private() {
        let settings = json::parse(
            r#"{"DisableLocalSocksProxy":true,"shareProxyOnNetwork":true,"listen":"0.0.0.0:1821"}"#,
        )
        .expect("settings");
        let edge = listen_address(Some(&settings)).expect("listen");
        assert!(edge.ip().is_loopback());
        assert_ne!(edge.port(), 1821);
    }

    #[test]
    fn a_disabled_local_socks_proxy_lane_binds_only_loopback() {
        let entry = r#"{"ipAddress":"127.0.0.1","sshPort":1,"sshUsername":"u","sshPassword":"p","sshHostKey":"AAAA"}"#;
        let settings = json::parse(&format!(
            r#"{{"listen":"0.0.0.0:0","DisableLocalSocksProxy":true,"TargetServerEntry":"{}","DisableRemoteServerListFetcher":true}}"#,
            hex(format!("0 0 0 0 {entry}").as_bytes())
        ))
        .expect("settings");
        let lane = PsiphonOut::new(Some(&settings)).expect("a refused dial is not a refused start");
        assert!(lane.endpoint().ip().is_loopback());
        TcpStream::connect(lane.endpoint()).expect("the private edge answers");
    }

    #[test]
    fn a_lane_whose_servers_refuse_still_binds_its_edge() {
        let entry = r#"{"ipAddress":"127.0.0.1","sshPort":1,"sshUsername":"u","sshPassword":"p","sshHostKey":"AAAA"}"#;
        let settings = json::parse(&format!(
            r#"{{"listen":"127.0.0.1:0","TargetServerEntry":"{}","DisableRemoteServerListFetcher":true}}"#,
            hex(format!("0 0 0 0 {entry}").as_bytes())
        ))
        .expect("settings");
        let lane = PsiphonOut::new(Some(&settings)).expect("a refused dial is not a refused start");
        assert_ne!(lane.endpoint().port(), 0);
        TcpStream::connect(lane.endpoint()).expect("the edge answers before a tunnel exists");
    }

    #[test]
    fn a_shadowsocks_prefix_spec_generates_its_bytes() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"ShadowsocksPrefixSpecs":{"p":[["","\\x16\\x03\\x01"]]},"ShadowsocksPrefixScopedSpecNames":{"":["p"]},"ShadowsocksPrefixProbability":1}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(
            settings.tls_shape.shadowsocks_prefix("9000"),
            Some(vec![0x16, 0x03, 0x01])
        );
    }

    #[test]
    fn an_ossh_seed_transform_reaches_the_ssh_shape() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"OSSHObfuscatorSeedTransformSpecs":{"p":[["^[0-9a-f]+$","\\x30{32}"]]},"OSSHObfuscatorSeedTransformScopedSpecNames":{"":["p"]},"OSSHObfuscatorSeedTransformProbability":1}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut seed = [0xab; crate::psiphon_ssh::SEED_LENGTH];
        settings
            .tls_shape
            .ossh_seed(&mut seed)
            .expect("seed transform");
        assert_eq!(seed, [0u8; crate::psiphon_ssh::SEED_LENGTH]);
    }

    #[test]
    fn an_obfuscated_quic_nonce_transform_keeps_the_nonce_length() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"ObfuscatedQUICNonceTransformSpecs":{"p":[["^[0-9a-f]+$","\\x30{24}"]]},"ObfuscatedQUICNonceTransformScopedSpecNames":{"":["p"]},"ObfuscatedQUICNonceTransformProbability":1}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let selected = settings
            .tls_shape
            .quic_nonce_transform
            .selected("")
            .expect("transform");
        let mut nonce = [0xcd; 12];
        crate::psiphon_ssh::apply_seed_transform(Some(selected.as_slice()), &mut nonce)
            .expect("nonce transform");
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn a_direct_http_transform_rewrites_the_request_head() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"DirectHTTPProtocolTransformSpecs":{"p":[["^POST","GET"]]},"DirectHTTPProtocolTransformScopedSpecNames":{"":["p"]},"DirectHTTPProtocolTransformProbability":1}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let selected = settings
            .tls_shape
            .http_transform(false, None)
            .expect("transform");
        let head = b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let transformed = crate::psiphon_dns::apply_bytes_transform(selected.as_slice(), head)
            .expect("transform");
        assert!(transformed.starts_with(b"GET / HTTP/1.1"));
    }

    #[test]
    fn a_fronted_http_transform_is_scoped_to_its_provider() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"FrontedHTTPProtocolTransformSpecs":{"p":[["^POST","GET"]]},"FrontedHTTPProtocolTransformScopedSpecNames":{"cdn":["p"]},"FrontedHTTPProtocolTransformProbability":1}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert!(settings
            .tls_shape
            .http_transform(true, Some("cdn"))
            .is_some());
        assert!(settings
            .tls_shape
            .http_transform(true, Some("other"))
            .is_none());
        assert!(settings.tls_shape.http_transform(false, None).is_none());
    }

    #[test]
    fn a_transform_that_changes_the_seed_length_is_refused() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"OSSHObfuscatorSeedTransformSpecs":{"p":[["^[0-9a-f]+$","\\x30{8}"]]},"OSSHObfuscatorSeedTransformScopedSpecNames":{"":["p"]},"OSSHObfuscatorSeedTransformProbability":1}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut seed = [0xab; crate::psiphon_ssh::SEED_LENGTH];
        assert!(settings.tls_shape.ossh_seed(&mut seed).is_err());
        assert_eq!(seed, [0xab; crate::psiphon_ssh::SEED_LENGTH]);
    }

    #[test]
    fn an_ossh_prefix_spec_generates_and_terminates_its_bytes() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"OSSHPrefixSpecs":{"p":[["","\\x00{24}"]]},"OSSHPrefixScopedSpecNames":{"":["p"]},"OSSHPrefixProbability":1}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let prefix = settings
            .tls_shape
            .ossh_prefix("9000", "keyword")
            .expect("prefix");
        assert_eq!(prefix.name, "p");
        assert_eq!(prefix.prefix_len, 24);
        assert_eq!(&prefix.bytes[..24], &[0u8; 24][..]);
        assert_eq!(prefix.bytes.len(), 24 + 16);
    }

    #[test]
    fn a_short_ossh_prefix_is_padded_before_its_terminator() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"OSSHPrefixSpecs":{"p":[["","\\x00{4}"]]},"OSSHPrefixScopedSpecNames":{"":["p"]},"OSSHPrefixProbability":1}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let prefix = settings
            .tls_shape
            .ossh_prefix("9000", "keyword")
            .expect("prefix");
        assert_eq!(prefix.prefix_len, 4);
        assert_eq!(prefix.bytes.len(), 24 + 16);
        assert_eq!(&prefix.bytes[..4], &[0u8; 4][..]);
    }

    #[test]
    fn an_ossh_prefix_is_scoped_to_its_dial_port() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"OSSHPrefixSpecs":{"p":[["","\\x00{24}"]]},"OSSHPrefixScopedSpecNames":{"9000":["p"]},"OSSHPrefixProbability":1}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert!(settings.tls_shape.ossh_prefix("9000", "keyword").is_some());
        assert!(settings.tls_shape.ossh_prefix("443", "keyword").is_none());
    }

    #[test]
    fn an_ossh_prefix_split_window_reaches_the_shape() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"OSSHPrefixSplitMinDelayMilliseconds":10,"OSSHPrefixSplitMaxDelayMilliseconds":20}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(
            settings.tls_shape.ossh_prefix.split_min,
            Duration::from_millis(10)
        );
        assert_eq!(
            settings.tls_shape.ossh_prefix.split_max,
            Duration::from_millis(20)
        );
    }

    #[test]
    fn an_ossh_prefix_nanosecond_window_keeps_sub_millisecond_values() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"OSSHPrefixSplitMinDelay":1000,"OSSHPrefixSplitMaxDelay":2000}"#)
                .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(
            settings.tls_shape.ossh_prefix.split_min,
            Duration::from_nanos(1_000)
        );
        assert_eq!(
            settings.tls_shape.ossh_prefix.split_max,
            Duration::from_nanos(2_000)
        );
    }

    #[test]
    fn custom_tls_profiles_become_named_fingerprints() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"CustomTLSProfiles":[{"Name":"tactic","UTLSSpec":{"CipherSuites":[4865],"Extensions":[{"Name":"SNI"},{"Name":"SupportedVersions","Data":{"Versions":[772]}}]}}],"UseOnlyCustomTLSProfiles":true}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.tls_shape.custom_profiles.len(), 1);
        assert!(settings.tls_shape.use_only_custom_profiles);
        let profile = settings.tls_shape.fingerprint(false, None);
        assert_eq!(profile.name(), Some("tactic"));
        assert_eq!(settings.tls_shape.named_profile("tactic"), Some(profile));
    }

    #[test]
    fn a_disabled_fronting_profile_is_not_drawn_for_that_provider() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"LimitTLSProfiles":["chrome_120","firefox_105"],"DisableFrontingProviderTLSProfiles":{"F1":["firefox_105"]}}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let firefox = Fingerprint::resolve("firefox_105").expect("firefox");
        for _ in 0..64 {
            assert_ne!(settings.tls_shape.fingerprint(true, Some("F1")), firefox);
        }
        assert_eq!(
            settings
                .tls_shape
                .named_profile("firefox_105")
                .expect("firefox"),
            firefox
        );
    }

    /// Limited TLS profiles and meek padding reach every TLS shape.
    #[test]
    fn a_limited_tls_profile_reaches_every_tls_shape() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"LimitTLSProfiles":["Chrome-120","Firefox-105"],"TLSTunnelMinTLSPadding":17,"MeekMinTLSPadding":23,"MeekMaxTLSPadding":29}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.tls_shape.profiles.len(), 2);
        assert!(settings
            .tls_shape
            .profiles
            .contains(&Fingerprint::resolve("chrome_120").expect("chrome")));
        let mut servers = vec![test_server(true)];
        servers[0].meek = Some(crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        });
        apply_session_settings(&mut servers, &settings);
        let padding = servers[0]
            .meek
            .as_ref()
            .expect("meek")
            .shape
            .padding()
            .expect("meek padding");
        assert!((23..=29).contains(&padding));
    }

    /// The reference meek shaping keys reach the lane shape.
    #[test]
    fn the_meek_shaping_settings_reach_the_shape() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"MeekAlternateCookieNameProbability":0.25,"MeekAlternateContentTypeProbability":0.5,"MeekTrafficShapingProbability":0.75,"MeekTrafficShapingLimitProtocols":["fronted-meek-ossh"],"MeekMinLimitRequestPayloadLength":1024,"MeekMaxLimitRequestPayloadLength":4096,"MeekRedialTLSProbability":0.125}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.tls_shape.meek_alternate_cookie_name, 0.25);
        assert_eq!(settings.tls_shape.meek_alternate_content_type, 0.5);
        assert_eq!(settings.tls_shape.meek_traffic_shaping, 0.75);
        assert_eq!(
            settings.tls_shape.meek_traffic_shaping_protocols,
            vec!["FRONTED-MEEK-OSSH"]
        );
        assert_eq!(settings.tls_shape.meek_min_limit_request, 1024);
        assert_eq!(settings.tls_shape.meek_max_limit_request, 4096);
        assert_eq!(settings.tls_shape.meek_redial_tls, 0.125);
    }

    #[test]
    fn tls_padding_and_a_cover_name_reach_the_shape() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"TLSTunnelMinTLSPadding":32,"TLSTunnelMaxTLSPadding":64,"TLSOSSHSNIServerNames":["a.test","b.test"],"CustomHostNameRegexes":["[a-z]{4}\\.test"],"CustomHostNameProbability":1,"TransformHostNameProbability":1}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.tls_shape.min_padding, 32);
        assert_eq!(settings.tls_shape.max_padding, 64);
        assert_eq!(settings.tls_shape.sni_names, vec!["a.test", "b.test"]);
        assert_eq!(settings.tls_shape.transform_probability, 1.0);
        let padding = settings.tls_shape.padding().expect("padding");
        assert!((32..=64).contains(&padding));
    }

    /// The config's CA file replaces the system store, and disabling roots skips the file and verification.
    #[test]
    fn the_config_trust_store_reaches_the_tls_shape() {
        let path = std::env::temp_dir().join(format!(
            "ferrox-psiphon-ca-{}-{}.pem",
            std::process::id(),
            hex(&random::<8>())
        ));
        std::fs::write(
            &path,
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
        )
        .expect("writes");
        let named = Settings::from_json(Some(
            &json::parse(&format!(
                r#"{{"TrustedCACertificatesFilename":{:?}}}"#,
                path.to_string_lossy()
            ))
            .expect("settings"),
        ))
        .expect("settings");
        assert!(matches!(
            &named.tls_shape.roots,
            crate::psiphon_ssh::TlsRoots::File(_)
        ));
        let named_roots = named.tls_shape.roots.load().expect("the file reads");
        assert_eq!(named_roots.len(), 1);
        assert_eq!(named_roots[0], vec![1, 2, 3]);
        assert!(!named.tls_shape.disable_system_root_cas);
        let missing_path = path.with_extension("missing");
        let missing = Settings::from_json(Some(
            &json::parse(&format!(
                r#"{{"TrustedCACertificatesFilename":{:?}}}"#,
                missing_path.to_string_lossy()
            ))
            .expect("settings"),
        ))
        .expect("a config with no verified dial keeps working without the file");
        assert!(missing.tls_shape.roots.load().is_err());
        let disabled = Settings::from_json(Some(
            &json::parse(&format!(
                r#"{{"DisableSystemRootCAs":true,"TrustedCACertificatesFilename":{:?}}}"#,
                missing_path.to_string_lossy()
            ))
            .expect("settings"),
        ))
        .expect("settings");
        assert!(disabled.tls_shape.disable_system_root_cas);
        assert!(matches!(
            &disabled.tls_shape.roots,
            crate::psiphon_ssh::TlsRoots::Empty
        ));
        assert!(disabled
            .tls_shape
            .roots
            .load()
            .expect("empty roots")
            .is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn censored_country_switch_expands_to_the_android_regions() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"rejectCensoredCountryProxies":true}"#).expect("settings"),
        ))
        .expect("settings");
        assert_eq!(
            settings.reject_countries,
            vec!["IR", "CN", "RU", "BY", "TM", "KP"]
        );
        let explicit = Settings::from_json(Some(
            &json::parse(r#"{"InproxyRejectProxyCountryCodes":["ir"," CN "]}"#).expect("settings"),
        ))
        .expect("settings");
        assert_eq!(explicit.reject_countries, vec!["IR", "CN"]);
    }

    #[test]
    fn the_android_upstream_proxy_spelling_is_read() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"UpstreamProxyUrl":"http://127.0.0.1:8080"}"#).expect("settings"),
        ))
        .expect("settings");
        assert!(settings.proxy.is_some());
    }

    #[test]
    fn a_socks5_greeting_reads_its_method_count() {
        let settings =
            Settings::from_json(Some(&json::parse("{}").expect("settings"))).expect("settings");
        let inner = Inner {
            session_id: String::new(),
            settings,
            config_state: 0,
            entries: Mutex::new(Arc::new(Vec::new())),
            sloks: crate::psiphon_osl::SlokStore::open(None),
            requests: Arc::new(crate::psiphon_osl::ServerEvents {
                sloks: crate::psiphon_osl::SlokStore::open(None),
                seeded: Arc::new(AtomicBool::new(false)),
                emit_alerts: false,
                emit_sloks: false,
            }),
            osl_seeded: Arc::new(AtomicBool::new(false)),
            last_osl: Mutex::new(None),
            last_osl_failure: Mutex::new(None),
            sessions: Mutex::new(Vec::new()),
            next_session: AtomicUsize::new(0),
            affinity: Mutex::new(None),
            moved_to_front: Mutex::new(HashSet::new()),
            connecting: Mutex::new(()),
            stopping: AtomicBool::new(false),
            endpoint: SocketAddr::from(([127, 0, 0, 1], 0)),
            http_endpoint: None,
            udpgw: Mutex::new(None),
            conduit: Mutex::new(None),
            split_untunneled: Mutex::new(HashMap::new()),
            replay: Arc::new(crate::psiphon_replay::Cache::new(
                crate::psiphon_replay::Settings::default(),
            )),
            light: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let addr = listener.local_addr().expect("addr");
        let client = thread::spawn(move || {
            let mut sock = TcpStream::connect(addr).expect("connect");
            sock.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            sock.write_all(&[5, 1, 0]).expect("greeting");
            let mut chosen = [0u8; 2];
            sock.read_exact(&mut chosen).expect("method");
            assert_eq!(chosen, [5, 0]);
            sock.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
                .expect("request");
        });
        let (mut server, _) = listener.accept().expect("accept");
        match read_request(&mut server, &inner) {
            Some((Version::V5, Ask::Connect(host, port))) => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 80);
            }
            _ => panic!("one method then a target is a SOCKS5 connect"),
        }
        client.join().expect("client");
    }

    #[test]
    fn a_credentialed_edge_refuses_socks4() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"localProxyUsername":"user","localProxyPassword":"pass"}"#)
                .expect("settings"),
        ))
        .expect("settings");
        let inner = Inner {
            session_id: String::new(),
            settings,
            config_state: 0,
            entries: Mutex::new(Arc::new(Vec::new())),
            sloks: crate::psiphon_osl::SlokStore::open(None),
            requests: Arc::new(crate::psiphon_osl::ServerEvents {
                sloks: crate::psiphon_osl::SlokStore::open(None),
                seeded: Arc::new(AtomicBool::new(false)),
                emit_alerts: false,
                emit_sloks: false,
            }),
            osl_seeded: Arc::new(AtomicBool::new(false)),
            last_osl: Mutex::new(None),
            last_osl_failure: Mutex::new(None),
            sessions: Mutex::new(Vec::new()),
            next_session: AtomicUsize::new(0),
            affinity: Mutex::new(None),
            moved_to_front: Mutex::new(HashSet::new()),
            connecting: Mutex::new(()),
            stopping: AtomicBool::new(false),
            endpoint: SocketAddr::from(([127, 0, 0, 1], 0)),
            http_endpoint: None,
            udpgw: Mutex::new(None),
            conduit: Mutex::new(None),
            split_untunneled: Mutex::new(HashMap::new()),
            replay: Arc::new(crate::psiphon_replay::Cache::new(
                crate::psiphon_replay::Settings::default(),
            )),
            light: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let addr = listener.local_addr().expect("addr");
        let client = thread::spawn(move || {
            let mut sock = TcpStream::connect(addr).expect("connect");
            sock.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            sock.write_all(&[4, 1, 0, 80, 127, 0, 0, 1, 0])
                .expect("request");
            let mut reply = [0u8; 8];
            sock.read_exact(&mut reply).expect("refusal");
            assert_eq!(reply, [0, 91, 0, 0, 0, 0, 0, 0]);
        });
        let (mut server, _) = listener.accept().expect("accept");
        assert!(read_request(&mut server, &inner).is_none());
        client.join().expect("client");
    }

    #[test]
    fn capitalised_proxy_credentials_match_the_platform_client() {
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"LocalProxyUsername":"user","LocalProxyPassword":"pass"}"#)
                .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.proxy_user.as_deref(), Some("user"));
        assert_eq!(settings.proxy_pass.as_deref(), Some("pass"));
    }

    #[test]
    fn an_http_proxy_edge_needs_the_named_credential() {
        let bare = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert!(!http_authorized(bare, "user", "pass"));
        let token = ferrox_core::b64::encode(b"user:pass");
        let named = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
        );
        assert!(http_authorized(&named, "user", "pass"));
        let bearer = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
        );
        assert!(!http_authorized(&bearer, "user", "pass"));
        assert!(!http_authorized(&named, "user", "wrong"));
        assert!(!http_authorized(&named, "other", "pass"));
        let lower = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nproxy-authorization: basic {token}\r\n\r\n"
        );
        assert!(http_authorized(&lower, "user", "pass"));
    }

    #[test]
    fn a_stalled_server_does_not_hold_the_one_that_answers() {
        let servers: Vec<Server> = ["stalled", "answers"]
            .into_iter()
            .map(|name| Server {
                host: name.to_owned(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 22,
                ssh_port: Some(22),
                user: String::new(),
                password: String::new(),
                host_key: Vec::new(),
                obfuscation_key: None,
                tls_obfuscation_key: None,
                meek_obfuscated_key: None,
                region: None,
                provider_id: None,
                fronting_provider_id: None,
                scan_cdn: true,
                ssh_api: true,
                direct: true,
                tls: false,
                tls_port: None,
                quic: false,
                quic_port: None,
                quic_versions: Vec::new(),
                quic_noise: None,
                ss: false,
                shadowsocks: None,
                meek: None,
                unfronted_meek: None,
                inproxy_meek: None,
                tactics: None,
                inproxy: None,
                tls_inproxy: None,
                inproxy_shadowsocks_key: None,
                channel_window: crate::psiphon_ssh::DEFAULT_CHANNEL_WINDOW,
            })
            .collect();
        let began = Instant::now();
        let winner = race(
            servers,
            |server| {
                if server.host == "stalled" {
                    thread::sleep(Duration::from_secs(5));
                    return Err("stalled".to_owned());
                }
                Ok(server.host.clone())
            },
            Duration::from_secs(2),
            Duration::ZERO,
            Duration::ZERO,
        )
        .expect("the answering server wins");
        assert_eq!(winner, "answers");
        let elapsed = began.elapsed();
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn a_stalled_batch_is_cut_at_its_budget() {
        let servers: Vec<Server> = (0..4)
            .map(|index| Server {
                host: format!("stalled-{index}"),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 22,
                ssh_port: Some(22),
                user: String::new(),
                password: String::new(),
                host_key: Vec::new(),
                obfuscation_key: None,
                tls_obfuscation_key: None,
                meek_obfuscated_key: None,
                region: None,
                provider_id: None,
                fronting_provider_id: None,
                scan_cdn: true,
                ssh_api: true,
                direct: true,
                tls: false,
                tls_port: None,
                quic: false,
                quic_port: None,
                quic_versions: Vec::new(),
                quic_noise: None,
                ss: false,
                shadowsocks: None,
                meek: None,
                unfronted_meek: None,
                inproxy_meek: None,
                tactics: None,
                inproxy: None,
                tls_inproxy: None,
                inproxy_shadowsocks_key: None,
                channel_window: crate::psiphon_ssh::DEFAULT_CHANNEL_WINDOW,
            })
            .collect();
        let began = Instant::now();
        let outcome: Result<String, String> = race(
            servers,
            |_| {
                thread::sleep(Duration::from_secs(5));
                Err("stalled".to_owned())
            },
            Duration::from_millis(100),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert!(outcome.is_err());
        let elapsed = began.elapsed();
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn a_spki_key_unwraps_to_pkcs1() {
        let der = [
            0x30, 0x0e, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x03, 0x05, 0x00, 0x30, 0x02,
            0x05, 0x00,
        ];
        assert_eq!(spki_to_pkcs1(&der), Some(vec![0x30, 0x02, 0x05, 0x00]));
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 0x7f, 0x80, 0xff];
        assert_eq!(hex_decode(&hex(&bytes)), Some(bytes.to_vec()));
        assert_eq!(hex_decode("0g"), None);
        assert_eq!(hex_decode("abc"), None);
    }

    #[test]
    fn a_list_without_a_package_is_refused() {
        assert!(unpack(b"not json", "key").is_err());
    }

    #[test]
    fn a_flow_clone_shares_the_credential_words() {
        let out = PsiphonOut::validate(None).expect("settings");
        let (copy, counts) = ferrox_core::alloc_count::measure(|| out.clone());
        assert_eq!(counts.allocs, 0);
        assert!(std::ptr::eq(
            Arc::as_ptr(&out.credential),
            Arc::as_ptr(&copy.credential)
        ));
    }

    #[test]
    fn a_socks_udp_frame_keeps_its_target_and_payload() {
        let mut frame = Vec::new();
        socks_udp_frame_into(
            &mut frame,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            5300,
            b"hello",
        );
        let (target, payload) = parse_udp_frame(&frame).expect("frame");
        assert_eq!(
            target,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 5300)
        );
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn a_socks_udp_name_is_not_resolved_outside_the_tunnel() {
        let name = b"example.com";
        let mut frame = vec![0, 0, 0, 3, name.len() as u8];
        frame.extend_from_slice(name);
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(b"dns");
        assert!(parse_udp_frame(&frame).is_none());
    }

    #[test]
    fn a_udpgw_frame_carries_the_preamble_and_payload() {
        let mut frame = Vec::new();
        udpgw_frame_into(
            &mut frame,
            7,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            53,
            b"hi",
            true,
        );
        assert_eq!(u16::from_le_bytes([frame[0], frame[1]]), 11);
        assert_eq!(frame[2], UDPGW_FLAG_REBIND);
        assert_eq!(u16::from_le_bytes([frame[3], frame[4]]), 7);
        assert_eq!(&frame[5..9], &[192, 0, 2, 1]);
        assert_eq!(u16::from_be_bytes([frame[9], frame[10]]), 53);
        assert_eq!(&frame[11..], b"hi");
    }

    #[test]
    fn an_ipv6_udpgw_frame_names_its_flag() {
        let octets = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let address = IpAddr::V6(std::net::Ipv6Addr::from(octets));
        let mut frame = Vec::new();
        udpgw_frame_into(&mut frame, 7, address, 53, b"hi", false);
        assert_eq!(u16::from_le_bytes([frame[0], frame[1]]), 23);
        assert_eq!(frame[2], UDPGW_FLAG_IPV6);
        assert_eq!(&frame[5..21], &octets);
        assert_eq!(u16::from_be_bytes([frame[21], frame[22]]), 53);
        assert_eq!(&frame[23..], b"hi");
    }

    #[test]
    fn the_tls_fragment_and_user_agent_settings_reach_the_shape() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"TLSFragmentClientHelloProbability":0.25,"TLSFragmentClientHelloLimitProtocols":["tls-ossh"],"PickUserAgentProbability":0.0,"QUICDialEarlyProbability":0.25,"QUICDisableClientPathMTUDiscoveryProbability":0.75,"QUICObfuscatedPSKProbability":0.4}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.tls_shape.tls_fragment_client_hello, 0.25);
        assert_eq!(
            settings.tls_shape.tls_fragment_client_hello_protocols,
            vec!["TLS-OSSH"]
        );
        assert_eq!(settings.tls_shape.user_agent_probability, 0.0);
        assert_eq!(settings.tls_shape.quic_dial_early, 0.25);
        assert_eq!(settings.tls_shape.quic_disable_path_mtu, 0.75);
        assert_eq!(settings.tls_shape.quic_obfuscated_psk, 0.4);
        assert!(!settings.tls_shape.fragment_client_hello("SSH"));
        let always = Settings::from_json(Some(
            &json::parse(
                r#"{"TLSFragmentClientHelloProbability":1.0,"TLSFragmentClientHelloLimitProtocols":["tls-ossh"]}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert!(!always.tls_shape.fragment_client_hello("SSH"));
        assert!(always.tls_shape.fragment_client_hello("TLS-OSSH"));
    }

    #[test]
    /// The fragmentor window, protocol list, and OSSH prefix switch are read and clamped.
    fn the_fragmentor_window_and_prefix_switch_are_read() {
        let settings = json::parse(
            r#"{"FragmentorProbability":1.0,"FragmentorMinTotalBytes":16,"FragmentorMaxTotalBytes":64,"FragmentorMaxWriteBytes":8,"FragmentorLimitProtocols":["SSH"]}"#,
        )
        .expect("settings");
        let settings = Settings::from_json(Some(&settings)).expect("settings");
        assert!(settings.tls_shape.may_fragment("SSH"));
        assert!(!settings.tls_shape.may_fragment("TLS-OSSH"));
        let quiet = json::parse(r#"{"FragmentorMaxTotalBytes":0}"#).expect("settings");
        assert!(!Settings::from_json(Some(&quiet))
            .expect("settings")
            .tls_shape
            .may_fragment("SSH"));
    }

    #[test]
    /// A rate config that cannot throttle leaves the lane on its fast path.
    fn the_rate_limits_are_read_only_when_they_do_something() {
        let settings = json::parse(
            r#"{"RateLimits":{"ReadBytesPerSecond":1000,"ReadUnthrottledBytes":10,"WriteBytesPerSecond":500}}"#,
        )
        .expect("settings");
        assert!(Settings::from_json(Some(&settings))
            .expect("settings")
            .rate
            .is_some());
        let quiet = json::parse(r#"{"RateLimits":{"ReadBytesPerSecond":0}}"#).expect("settings");
        assert!(Settings::from_json(Some(&quiet))
            .expect("settings")
            .rate
            .is_none());
    }

    #[test]
    /// Only 32 lowercase hex digits are accepted as a session ID.
    fn a_session_id_is_read_only_as_32_lowercase_hex_digits() {
        let valid =
            json::parse(r#"{"SessionID":"0123456789abcdef0123456789abcdef"}"#).expect("settings");
        assert_eq!(
            client_session_id(Some(&valid)).as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        let upper =
            json::parse(r#"{"SessionID":"0123456789ABCDEF0123456789ABCDEF"}"#).expect("settings");
        assert!(client_session_id(Some(&upper)).is_none());
        let short = json::parse(r#"{"SessionID":"00"}"#).expect("settings");
        assert!(client_session_id(Some(&short)).is_none());
    }

    #[test]
    /// Tactics timing fields are read, floored, and defaulted as the reference does.
    fn the_tactics_timing_is_read_and_clamped() {
        let settings = json::parse(
            r#"{"TacticsWaitPeriodMilliseconds":5000,"TacticsRetryPeriodMilliseconds":250,"TacticsRetryPeriodJitter":0.5,"TacticsTimeoutMilliseconds":60000}"#,
        )
        .expect("settings");
        let timing = tactics_timing(Some(&settings));
        assert_eq!(timing.wait, Duration::from_secs(5));
        assert_eq!(timing.retry, Duration::from_millis(250));
        assert!((timing.jitter - 0.5).abs() < f64::EPSILON);
        assert_eq!(timing.timeout, Some(Duration::from_secs(60)));
        let quiet = tactics_timing(None);
        assert_eq!(quiet.wait, Duration::ZERO);
        assert_eq!(quiet.timeout, None);
        let hostile = json::parse(r#"{"TacticsRetryPeriodJitter":9.0}"#).expect("settings");
        assert!((tactics_timing(Some(&hostile)).jitter - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    /// Hold-off names match exactly and durations stay inside the cap.
    fn the_protocol_hold_off_is_read_and_matches_exact_names() {
        let settings = json::parse(
            r#"{"HoldOffTunnelProtocolNames":["SSH"],"HoldOffTunnelProtocolProbability":1.0,"HoldOffTunnelProtocolMinDurationMilliseconds":5,"HoldOffTunnelProtocolMaxDurationMilliseconds":10}"#,
        )
        .expect("settings");
        let delay = holdoff(Some(&settings));
        assert_eq!(delay.duration("TLS-OSSH"), Duration::ZERO);
        let wait = u64::try_from(delay.duration("SSH").as_millis()).expect("millis");
        assert!((5..=10).contains(&wait));
        let off = json::parse(r#"{"HoldOffTunnelProtocolNames":["SSH"]}"#).expect("settings");
        assert_eq!(holdoff(Some(&off)).duration("SSH"), Duration::ZERO);
    }

    fn test_meek() -> crate::psiphon_meek::Meek {
        crate::psiphon_meek::Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "mk".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape::default(),
        }
    }

    #[test]
    fn the_provider_hold_off_classes_are_read() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"HoldOffDirectTunnelMinDurationMilliseconds":5,"HoldOffDirectTunnelMaxDurationMilliseconds":10,"HoldOffDirectTunnelProbability":1.0,"HoldOffDirectTunnelProviderRegions":{"P1":[""]},"HoldOffFrontingTunnelMinDurationMilliseconds":5,"HoldOffFrontingTunnelMaxDurationMilliseconds":10,"HoldOffFrontingTunnelProviderIDs":["F1"],"HoldOffFrontingTunnelProbability":1.0,"HoldOffInproxyTunnelMinDurationMilliseconds":5,"HoldOffInproxyTunnelMaxDurationMilliseconds":10,"HoldOffInproxyTunnelProviderRegions":{"P2":["US"]},"HoldOffInproxyTunnelProbability":1.0}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let direct = settings.holdoff_for("SSH", Some("P1"), Some("CA"), None);
        assert!((5..=10).contains(&u64::try_from(direct.as_millis()).expect("millis")));
        assert_eq!(
            settings.holdoff_for("SSH", Some("P9"), Some("CA"), None),
            Duration::ZERO
        );
        assert_eq!(
            settings.holdoff_for("FRONTED-MEEK-OSSH", Some("P1"), None, Some("F9")),
            Duration::ZERO
        );
        assert!(!settings
            .holdoff_for("FRONTED-MEEK-OSSH", Some("P1"), None, Some("F1"))
            .is_zero());
        assert!(!settings
            .holdoff_for("INPROXY-QUIC-OSSH", Some("P2"), Some("US"), None)
            .is_zero());
        assert_eq!(
            settings.holdoff_for("INPROXY-QUIC-OSSH", Some("P2"), Some("CA"), None),
            Duration::ZERO
        );
    }

    #[test]
    fn the_client_restrictions_skip_matching_entries() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"RestrictDirectProviderIDsClientProbability":1.0,"RestrictDirectProviderRegions":{"P1":[""]},"RestrictFrontingProviderIDs":["F1"],"RestrictFrontingProviderIDsClientProbability":1.0,"RestrictInproxyProviderIDsClientProbability":1.0,"RestrictInproxyProviderRegions":{"P2":["US"]}}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        let mut server = test_server(false);
        server.provider_id = Some("P1".to_owned());
        assert!(settings.restricted(&server, false));
        server.provider_id = Some("P9".to_owned());
        assert!(!settings.restricted(&server, false));
        let mut fronted = test_server(false);
        fronted.meek = Some(test_meek());
        fronted.fronting_provider_id = Some("F1".to_owned());
        assert!(settings.restricted(&fronted, false));
        fronted.fronting_provider_id = Some("F9".to_owned());
        assert!(!settings.restricted(&fronted, false));
        let mut inproxy = test_server(false);
        inproxy.inproxy = Some(crate::psiphon_broker::Destination {
            address: "broker.example:443".to_owned(),
            network_protocol: 0,
            protocol: "INPROXY-QUIC-OSSH",
            packed_server_entry: Vec::new(),
        });
        inproxy.provider_id = Some("P2".to_owned());
        inproxy.region = Some("US".to_owned());
        assert!(settings.restricted(&inproxy, true));
        inproxy.region = Some("CA".to_owned());
        assert!(!settings.restricted(&inproxy, true));
    }

    #[test]
    fn the_server_entry_iterator_and_timeout_are_read() {
        let settings = Settings::from_json(Some(
            &json::parse(
                r#"{"ServerEntryIteratorMaxMoveToFront":3,"ServerEntryIteratorResetProbability":0.25,"TunnelConnectTimeoutSeconds":45}"#,
            )
            .expect("settings"),
        ))
        .expect("settings");
        assert_eq!(settings.server_entry_max_move_to_front, 3);
        assert!((settings.server_entry_reset_probability - 0.25).abs() < f64::EPSILON);
        assert_eq!(settings.establish, Some(Duration::from_secs(45)));
        assert!(settings.compress_tactics);
        let off = Settings::from_json(Some(
            &json::parse(r#"{"CompressTactics":false}"#).expect("settings"),
        ))
        .expect("settings");
        assert!(!off.compress_tactics);
    }

    /// The affinity lookup compares the entry's own fields, so a dial does not
    /// format a `host:port` string for every server it scans past.
    #[test]
    fn an_affinity_lookup_does_not_format_each_entry() {
        let mut entries: Vec<Server> = (0..64).map(|_| test_server(false)).collect();
        for (at, entry) in entries.iter_mut().enumerate() {
            entry.host = "192.0.2.1".to_owned();
            entry.port = 10_000 + at as u16;
        }
        let affinity = ("192.0.2.1".to_owned(), 10_042);
        let settings = Settings::from_json(Some(
            &json::parse(r#"{"ServerEntryIteratorResetProbability":0}"#).expect("settings"),
        ))
        .expect("settings");
        let inner = Inner {
            session_id: String::new(),
            settings,
            config_state: 0,
            entries: Mutex::new(Arc::new(entries.clone())),
            sloks: crate::psiphon_osl::SlokStore::open(None),
            requests: Arc::new(crate::psiphon_osl::ServerEvents {
                sloks: crate::psiphon_osl::SlokStore::open(None),
                seeded: Arc::new(AtomicBool::new(false)),
                emit_alerts: false,
                emit_sloks: false,
            }),
            osl_seeded: Arc::new(AtomicBool::new(false)),
            last_osl: Mutex::new(None),
            last_osl_failure: Mutex::new(None),
            sessions: Mutex::new(Vec::new()),
            next_session: AtomicUsize::new(0),
            affinity: Mutex::new(Some(affinity.clone())),
            moved_to_front: Mutex::new(HashSet::new()),
            connecting: Mutex::new(()),
            stopping: AtomicBool::new(false),
            endpoint: SocketAddr::from(([127, 0, 0, 1], 0)),
            http_endpoint: None,
            udpgw: Mutex::new(None),
            conduit: Mutex::new(None),
            split_untunneled: Mutex::new(HashMap::new()),
            replay: Arc::new(crate::psiphon_replay::Cache::new(
                crate::psiphon_replay::Settings::default(),
            )),
            light: None,
        };
        let (at, _) = inner.start();
        assert_eq!(at, 42, "start uses the shared lookup");
        let ((), new) = ferrox_core::alloc_count::measure(|| {
            let at = affinity_index(&entries, Some(&affinity));
            assert_eq!(at, Some(42));
        });
        assert_eq!(new.allocs, 0, "the field compare takes no heap: {new:?}");

        let ((), old) = ferrox_core::alloc_count::measure(|| {
            let host = format!("{}:{}", affinity.0, affinity.1);
            let at = entries
                .iter()
                .position(|entry| format!("{}:{}", entry.host, entry.port) == host);
            assert_eq!(at, Some(42));
        });
        assert_eq!(
            old.allocs, 88,
            "the old scan formatted the target and every entry it passed: {old:?}"
        );
    }

    #[test]
    fn a_live_server_moves_to_the_front() {
        let mut first = test_server(false);
        first.host = "a".to_owned();
        let mut second = test_server(false);
        second.host = "b".to_owned();
        let mut entries = vec![first, second];
        let ((), new) = ferrox_core::alloc_count::measure(|| {
            assert!(move_to_front(&mut entries, "b", 22));
        });
        assert_eq!(new.allocs, 0, "the field compare takes no heap: {new:?}");
        assert_eq!(entries[0].host, "b");
        assert!(!move_to_front(&mut entries, "b", 22));
        assert!(!move_to_front(&mut entries, "c", 22));
    }

    #[test]
    fn new_entries_keep_the_first_copy_of_each_server() {
        let mut first = test_server(false);
        first.port = 22;
        let mut next = test_server(false);
        next.port = 23;
        let current = vec![first.clone()];
        let added = new_entries(&current, vec![first, next.clone(), next]);
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].port, 23);
    }

    #[test]
    /// Liveness probes are read and selected by their protocol pattern.
    fn the_liveness_probes_are_read_and_matched_by_pattern() {
        let settings = json::parse(
            r#"{"InitialLivenessTest":{"*":{"MinUpstreamBytes":0,"MaxUpstreamBytes":10},"SSH":{"MaxUpstreamBytes":20}},"LivenessTest":{"SSH":{"MaxDownstreamBytes":30}}}"#,
        )
        .expect("settings");
        let liveness = liveness(Some(&settings));
        assert_eq!(
            liveness
                .spec("SSH", false)
                .expect("SSH initial probe")
                .max_upstream,
            20
        );
        assert_eq!(
            liveness
                .spec("TLS-OSSH", false)
                .expect("fallback probe")
                .max_upstream,
            10
        );
        assert_eq!(
            liveness
                .spec("SSH", true)
                .expect("SSH periodic probe")
                .max_downstream,
            30
        );
        assert!(liveness.spec("TLS-OSSH", true).is_none());
        assert!(wildcard_match("TLS-*", "TLS-OSSH"));
        assert!(wildcard_match("*@psiphon.ca", "random@psiphon.ca"));
        assert!(!wildcard_match("TLS-*", "SSH"));
        assert!(wildcard_match("A*B", "AxBzB"));
        assert!(wildcard_match("A*B", "AB"));
        assert!(!wildcard_match("A*B", "AxBzC"));
        assert!(!wildcard_match("A*B", "BA"));
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "A"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("**", "anything"));
        assert!(wildcard_match("A*", "A"));
        assert!(wildcard_match("A*", "AB"));
        assert!(wildcard_match("*B", "AB"));
        assert!(wildcard_match("A*B*C", "AxByC"));
        assert!(wildcard_match("A*B*C", "AxBzBzC"));
        assert!(!wildcard_match("A*B*C", "AxBzCzB"));
    }

    /// Matching a wildcard takes no heap, even with several `*` runs.
    #[test]
    fn wildcard_matching_does_not_allocate() {
        let (matched, counts) = ferrox_core::alloc_count::measure(|| {
            wildcard_match("TLS-*", "TLS-OSSH")
                && wildcard_match("*@psiphon.ca", "random@psiphon.ca")
                && wildcard_match("A*B*C", "AxByC")
                && !wildcard_match("A*B", "AxBzC")
        });
        assert!(matched);
        assert_eq!(
            counts.allocs, 0,
            "wildcard matching takes no heap: {counts:?}"
        );
    }

    #[test]
    fn a_reused_udp_frame_buffer_holds_no_stale_bytes() {
        let mut frame = Vec::new();
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        udpgw_frame_into(&mut frame, 7, address, 53, b"a-longer-payload", false);
        udpgw_frame_into(&mut frame, 8, address, 53, b"hi", true);
        assert_eq!(frame.len(), 13);
        assert_eq!(&frame[11..], b"hi");
        socks_udp_frame_into(&mut frame, address, 5300, b"x");
        assert_eq!(frame.len(), 11);
        assert_eq!(&frame[10..], b"x");
    }

    #[test]
    fn an_unknown_api_encoding_is_refused() {
        let settings = json::parse(r#"{"TargetAPIEncoding":"bogus"}"#).expect("settings");
        assert!(PsiphonOut::validate(Some(&settings)).is_err());
    }

    #[test]
    fn a_steering_ip_is_not_a_bogon() {
        for bogon in ["10.0.0.1", "172.16.0.1", "192.168.0.1", "127.0.0.1", "::1"] {
            assert!(is_bogon(bogon.parse().expect("address")), "{bogon}");
        }
        for bogon in [
            Ipv4Addr::from([100, 64, 0, 1]),
            Ipv4Addr::from([240, 0, 0, 1]),
        ] {
            assert!(is_bogon(bogon.into()), "{bogon}");
        }
        assert!(!is_bogon(Ipv4Addr::from([8, 8, 8, 8]).into()));
    }
}
