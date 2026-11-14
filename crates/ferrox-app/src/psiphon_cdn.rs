//! The reference CDN scan corpus, split into its named built-in sets.

#[derive(Clone, Copy)]
pub(crate) struct CdnRange {
    pub(crate) first: u32,
    pub(crate) last: u32,
}

pub(crate) struct CdnSet {
    pub(crate) name: &'static str,
    pub(crate) ranges: &'static [CdnRange],
    pub(crate) snis: &'static [&'static str],
}

#[rustfmt::skip]
const LEGACYANDROIDOVERRIDE_RANGES: &[CdnRange] = &[
    CdnRange { first: 0x170c_930d, last: 0x170c_930d },
    CdnRange { first: 0x170c_931d, last: 0x170c_931d },
    CdnRange { first: 0x1749_cf08, last: 0x1749_cf08 },
    CdnRange { first: 0x1749_cf0f, last: 0x1749_cf0f },
    CdnRange { first: 0x17d4_fa4e, last: 0x17d4_fa4e },
    CdnRange { first: 0x17d4_fa5b, last: 0x17d4_fa5b },
    CdnRange { first: 0x17d7_00cb, last: 0x17d7_00cb },
    CdnRange { first: 0x17d7_00ce, last: 0x17d7_00ce },
    CdnRange { first: 0x5c7b_662b, last: 0x5c7b_662b },
];
const LEGACYANDROIDOVERRIDE_SNIS: &[&str] = &[
    "a.akamaihd-staging.net",
    "a.akamaihd.net",
    "a.akamaized-staging.net",
    "a.akamaized.net",
    "a248.e.akamai.net",
    "www.akamai.com",
];

#[rustfmt::skip]
const CURATED_RANGES: &[CdnRange] = &[
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
    CdnRange { first: 0x1702_0d88, last: 0x1702_0d88 },
    CdnRange { first: 0x1722_4be5, last: 0x1722_4be5 },
    CdnRange { first: 0x172b_edef, last: 0x172b_edef },
    CdnRange { first: 0x172c_c995, last: 0x172c_c995 },
    CdnRange { first: 0x1730_1785, last: 0x1730_1785 },
    CdnRange { first: 0x1730_1797, last: 0x1730_1797 },
    CdnRange { first: 0x1730_17b2, last: 0x1730_17b2 },
    CdnRange { first: 0x1730_17ba, last: 0x1730_17ba },
    CdnRange { first: 0x1730_17c3, last: 0x1730_17c3 },
    CdnRange { first: 0x173a_5f8a, last: 0x173a_5f8a },
    CdnRange { first: 0x173a_c18c, last: 0x173a_c18c },
    CdnRange { first: 0x17ca_8a7d, last: 0x17ca_8a7d },
    CdnRange { first: 0x17cf_d253, last: 0x17cf_d253 },
    CdnRange { first: 0x17d0_4128, last: 0x17d0_4128 },
    CdnRange { first: 0x17d7_3c29, last: 0x17d7_3c29 },
    CdnRange { first: 0x17d8_4d23, last: 0x17d8_4d23 },
    CdnRange { first: 0x17dd_1c05, last: 0x17dd_1c05 },
    CdnRange { first: 0x17dd_1c39, last: 0x17dd_1c39 },
    CdnRange { first: 0x17dd_1d1d, last: 0x17dd_1d1d },
    CdnRange { first: 0x3f8d_fccb, last: 0x3f8d_fccb },
    CdnRange { first: 0x48f6_1c25, last: 0x48f6_1c25 },
    CdnRange { first: 0x5c7a_117c, last: 0x5c7a_117c },
    CdnRange { first: 0x5c7a_a6ed, last: 0x5c7a_a6ed },
    CdnRange { first: 0x5c7b_6a0b, last: 0x5c7b_6a0b },
    CdnRange { first: 0x5c7b_6a5a, last: 0x5c7b_6a5a },
    CdnRange { first: 0x5f65_236a, last: 0x5f65_236a },
    CdnRange { first: 0x5f65_2370, last: 0x5f65_2370 },
    CdnRange { first: 0x5f65_852a, last: 0x5f65_852a },
    CdnRange { first: 0x5f65_8552, last: 0x5f65_8552 },
    CdnRange { first: 0x5f65_8583, last: 0x5f65_8583 },
    CdnRange { first: 0x6867_4007, last: 0x6867_4007 },
    CdnRange { first: 0x6867_4105, last: 0x6867_4105 },
    CdnRange { first: 0x6867_4132, last: 0x6867_4132 },
    CdnRange { first: 0x6867_414a, last: 0x6867_414a },
    CdnRange { first: 0x6870_9252, last: 0x6870_9252 },
    CdnRange { first: 0x8e36_b2d3, last: 0x8e36_b2d3 },
    CdnRange { first: 0x9765_80df, last: 0x9765_80df },
    CdnRange { first: 0xacea_9f3a, last: 0xacea_9f3a },
    CdnRange { first: 0xacea_c70f, last: 0xacea_c70f },
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
    CdnRange { first: 0xb9c8_e829, last: 0xb9c8_e82b },
    CdnRange { first: 0xb9c8_e831, last: 0xb9c8_e832 },
];
const CURATED_SNIS: &[&str] = &[
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
];

#[rustfmt::skip]
const AKAMAI_RANGES: &[CdnRange] = &[
    CdnRange { first: 0x1730_cb00, last: 0x1730_cbff },
    CdnRange { first: 0x173e_e600, last: 0x173e_e6ff },
    CdnRange { first: 0x17d7_0000, last: 0x17d7_00ff },
    CdnRange { first: 0x226b_8600, last: 0x226b_86ff },
    CdnRange { first: 0x226e_ce00, last: 0x226e_ceff },
    CdnRange { first: 0x6861_5500, last: 0x6861_55ff },
    CdnRange { first: 0x820e_1d00, last: 0x820e_1dff },
    CdnRange { first: 0xa570_0700, last: 0xa570_07ff },
];
const AKAMAI_SNIS: &[&str] = &[
    "a.akamaihd-staging.net",
    "a.akamaihd.net",
    "a.akamaized-staging.net",
    "a.akamaized.net",
    "a248.e.akamai.net",
    "alchzwwfzmrtgoaf-a.akamaihd.net",
    "bbe-getimage.akamaized.net",
    "cdn.ncbi.nlm.nih.gov",
    "jkiysqntxacscicm-a.akamaihd.net",
    "ncbi.nlm.nih.gov",
    "pmc.ncbi.nlm.nih.gov",
    "prfzquobemaspprl-a.akamaihd.net",
    "pubmed.ncbi.nlm.nih.gov",
    "pubmed.redirect",
    "www.akamai.com",
    "www.ncbi.nlm.nih.gov",
    "www.st-va.ncbi.nlm.nih.gov",
    "yryirjrhqffsxwpg-a.akamaihd.net",
];

#[rustfmt::skip]
const FASTLY_RANGES: &[CdnRange] = &[
    CdnRange { first: 0x17eb_2000, last: 0x17eb_2fff },
    CdnRange { first: 0x2bf9_4800, last: 0x2bf9_4bff },
    CdnRange { first: 0x67f4_3200, last: 0x67f4_32ff },
    CdnRange { first: 0x67f5_de00, last: 0x67f5_e0ff },
    CdnRange { first: 0x689c_5000, last: 0x689c_5fff },
    CdnRange { first: 0x8cf8_4000, last: 0x8cf8_ffff },
    CdnRange { first: 0x924b_0000, last: 0x924b_7fff },
    CdnRange { first: 0x9765_0000, last: 0x9765_ffff },
    CdnRange { first: 0x9d34_4000, last: 0x9d34_7fff },
    CdnRange { first: 0xa752_0000, last: 0xa752_8fff },
    CdnRange { first: 0xa752_a000, last: 0xa752_afff },
    CdnRange { first: 0xa752_e000, last: 0xa752_efff },
    CdnRange { first: 0xac6f_4000, last: 0xac6f_7fff },
    CdnRange { first: 0xb91f_1000, last: 0xb91f_13ff },
    CdnRange { first: 0xc71b_4800, last: 0xc71b_4fff },
    CdnRange { first: 0xc7e8_0000, last: 0xc7e8_ffff },
];
const FASTLY_SNIS: &[&str] = &[
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
    "prod.global.ssl.fastly.net",
    "pypi.org",
    "quic.map.fastly.net",
    "raw.githubusercontent.com",
    "reddit.com",
    "release-assets.githubusercontent.com",
    "uploads.github.com",
    "www.fastly.com",
    "www.github.com",
    "www.python.org",
    "xtls.github.io",
];

#[rustfmt::skip]
const BUNNY_RANGES: &[CdnRange] = &[
    CdnRange { first: 0x0509_4777, last: 0x0509_4777 },
    CdnRange { first: 0x0509_622d, last: 0x0509_622d },
    CdnRange { first: 0x0509_6349, last: 0x0509_6349 },
    CdnRange { first: 0x0509_90b2, last: 0x0509_90b2 },
    CdnRange { first: 0x052a_ce42, last: 0x052a_ce42 },
    CdnRange { first: 0x05bd_ca3e, last: 0x05bd_ca3e },
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
    CdnRange { first: 0x310c_009e, last: 0x310c_009e },
    CdnRange { first: 0x310c_471b, last: 0x310c_471b },
    CdnRange { first: 0x3353_aca3, last: 0x3353_aca3 },
    CdnRange { first: 0x40b9_e852, last: 0x40b9_e852 },
    CdnRange { first: 0x40b9_e8b2, last: 0x40b9_e8b2 },
    CdnRange { first: 0x40b9_e8c2, last: 0x40b9_e8c2 },
    CdnRange { first: 0x40b9_ea72, last: 0x40b9_ea72 },
    CdnRange { first: 0x40b9_eb5a, last: 0x40b9_eb5a },
    CdnRange { first: 0x42b5_a34a, last: 0x42b5_a34a },
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
    CdnRange { first: 0x5db4_d9d6, last: 0x5db4_d9d6 },
    CdnRange { first: 0x5e14_9a16, last: 0x5e14_9a16 },
    CdnRange { first: 0x5e2e_1bba, last: 0x5e2e_1bba },
    CdnRange { first: 0x5e80_fea6, last: 0x5e80_fea6 },
    CdnRange { first: 0x5e82_447a, last: 0x5e82_447a },
    CdnRange { first: 0x5e82_cc6e, last: 0x5e82_cc6e },
    CdnRange { first: 0x6262_f28e, last: 0x6262_f28e },
    CdnRange { first: 0x6643_8a9b, last: 0x6643_8a9b },
    CdnRange { first: 0x66db_7e14, last: 0x66db_7e14 },
    CdnRange { first: 0x673c_0fa2, last: 0x673c_0fa7 },
    CdnRange { first: 0x673c_0fa9, last: 0x673c_0fad },
    CdnRange { first: 0x676c_e505, last: 0x676c_e505 },
    CdnRange { first: 0x676c_e729, last: 0x676c_e729 },
    CdnRange { first: 0x67d4_e309, last: 0x67d4_e309 },
    CdnRange { first: 0x67d6_145f, last: 0x67d6_145f },
    CdnRange { first: 0x67d8_dc09, last: 0x67d8_dc09 },
    CdnRange { first: 0x67eb_c7aa, last: 0x67eb_c7aa },
    CdnRange { first: 0x68a6_906a, last: 0x68a6_906a },
    CdnRange { first: 0x68ed_333a, last: 0x68ed_333a },
    CdnRange { first: 0x68ed_354a, last: 0x68ed_354a },
    CdnRange { first: 0x68ed_369a, last: 0x68ed_369a },
    CdnRange { first: 0x6b9b_2f92, last: 0x6b9b_2f92 },
    CdnRange { first: 0x6bb6_a3a2, last: 0x6bb6_a3a2 },
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
    CdnRange { first: 0x74ca_501d, last: 0x74ca_501d },
    CdnRange { first: 0x74ca_50f7, last: 0x74ca_50f7 },
    CdnRange { first: 0x74ca_76c2, last: 0x74ca_76c2 },
    CdnRange { first: 0x74ca_9b92, last: 0x74ca_9b92 },
    CdnRange { first: 0x74ca_c1b2, last: 0x74ca_c1b2 },
    CdnRange { first: 0x74ca_e0a8, last: 0x74ca_e0a8 },
    CdnRange { first: 0x74ca_eb10, last: 0x74ca_eb10 },
    CdnRange { first: 0x7a0a_fb82, last: 0x7a0a_fb82 },
    CdnRange { first: 0x8001_23aa, last: 0x8001_23aa },
    CdnRange { first: 0x8001_34b3, last: 0x8001_34b3 },
    CdnRange { first: 0x808c_468d, last: 0x808c_468d },
    CdnRange { first: 0x81e3_b312, last: 0x81e3_b312 },
    CdnRange { first: 0x81e3_d9b2, last: 0x81e3_d9b3 },
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
    CdnRange { first: 0x8da4_23a0, last: 0x8da4_23a0 },
    CdnRange { first: 0x8de3_8ef2, last: 0x8de3_8ef2 },
    CdnRange { first: 0x8e84_df4f, last: 0x8e84_df51 },
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
    CdnRange { first: 0x923b_45ca, last: 0x923b_45ca },
    CdnRange { first: 0x92b9_f80f, last: 0x92b9_f80f },
    CdnRange { first: 0x9471_bea1, last: 0x9471_bea1 },
    CdnRange { first: 0x94fb_29f4, last: 0x94fb_29f4 },
    CdnRange { first: 0x94fb_2a7b, last: 0x94fb_2a7b },
    CdnRange { first: 0x94fb_8184, last: 0x94fb_8184 },
    CdnRange { first: 0x94fb_81d9, last: 0x94fb_81d9 },
    CdnRange { first: 0x94fb_8349, last: 0x94fb_834a },
    CdnRange { first: 0x94fb_83ee, last: 0x94fb_83ee },
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
    CdnRange { first: 0x9d5a_b4cd, last: 0x9d5a_b4cd },
    CdnRange { first: 0x9e33_7bcd, last: 0x9e33_7bcd },
    CdnRange { first: 0x9f45_3950, last: 0x9f45_3950 },
    CdnRange { first: 0x9f45_44ab, last: 0x9f45_44ab },
    CdnRange { first: 0xa237_870b, last: 0xa237_870b },
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
    CdnRange { first: 0xacff_fd8c, last: 0xacff_fd8c },
    CdnRange { first: 0xb009_8b37, last: 0xb009_8b37 },
    CdnRange { first: 0xb009_8b5e, last: 0xb009_8b5e },
    CdnRange { first: 0xb23f_0270, last: 0xb23f_0270 },
    CdnRange { first: 0xb23f_1534, last: 0xb23f_1534 },
    CdnRange { first: 0xb23f_29ea, last: 0xb23f_29ea },
    CdnRange { first: 0xb23f_29f2, last: 0xb23f_29f2 },
    CdnRange { first: 0xb23f_29f7, last: 0xb23f_29f7 },
    CdnRange { first: 0xb2af_8633, last: 0xb2af_8633 },
    CdnRange { first: 0xb495_e7af, last: 0xb495_e7af },
    CdnRange { first: 0xb5ae_a866, last: 0xb5ae_a866 },
    CdnRange { first: 0xb918_0b12, last: 0xb918_0b13 },
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
    CdnRange { first: 0xbc28_7ee3, last: 0xbc28_7ee3 },
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
    CdnRange { first: 0xd8ca_c234, last: 0xd8ca_c234 },
    CdnRange { first: 0xd8ca_c2fc, last: 0xd8ca_c2fc },
];
const BUNNY_SNIS: &[&str] = &[
    "b-cdn.net",
    "megram-supg-instem.b-cdn.net",
    "pirtus-moding-hareware.b-cdn.net",
];

#[rustfmt::skip]
const CLOUDFLARE_RANGES: &[CdnRange] = &[
    CdnRange { first: 0x6715_f400, last: 0x6715_f7ff },
    CdnRange { first: 0x6716_c800, last: 0x6716_cbff },
    CdnRange { first: 0x671f_0400, last: 0x671f_07ff },
    CdnRange { first: 0x6810_0000, last: 0x681b_ffff },
    CdnRange { first: 0x6ca2_c000, last: 0x6ca2_ffff },
    CdnRange { first: 0x8300_4800, last: 0x8300_4bff },
    CdnRange { first: 0x8d65_4000, last: 0x8d65_7fff },
    CdnRange { first: 0xa29e_0000, last: 0xa29f_ffff },
    CdnRange { first: 0xac40_0000, last: 0xac47_ffff },
    CdnRange { first: 0xadf5_3000, last: 0xadf5_3fff },
    CdnRange { first: 0xbc72_6000, last: 0xbc72_6fff },
    CdnRange { first: 0xbe5d_f000, last: 0xbe5d_ffff },
    CdnRange { first: 0xc5ea_f000, last: 0xc5ea_f3ff },
    CdnRange { first: 0xc629_8000, last: 0xc629_ffff },
];
const CLOUDFLARE_SNIS: &[&str] = &[
    "cdnjs.cloudflare.com",
    "cloudflare.com",
    "lickbash-nonal-nonink.psiphon3.net",
    "morer-actocumerl-reless.psiphon3.net",
    "serce-sourite-docurch.psiphon3.net",
    "www.cloudflare.com",
];

#[rustfmt::skip]
const CLOUDFRONT_RANGES: &[CdnRange] = &[
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
    CdnRange { first: 0x175b_0000, last: 0x175b_1fff },
    CdnRange { first: 0x17e4_d400, last: 0x17e4_d6ff },
    CdnRange { first: 0x17e4_dc00, last: 0x17e4_dfff },
    CdnRange { first: 0x17e4_f400, last: 0x17e4_f4ff },
    CdnRange { first: 0x17ea_c000, last: 0x17ea_ffff },
    CdnRange { first: 0x186e_2000, last: 0x186e_3fff },
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
    CdnRange { first: 0x2bda_3840, last: 0x2bda_38ff },
    CdnRange { first: 0x2bda_4700, last: 0x2bda_473f },
    CdnRange { first: 0x2cdc_c200, last: 0x2cdc_cbff },
    CdnRange { first: 0x2cde_4200, last: 0x2cde_42ff },
    CdnRange { first: 0x2ce3_b200, last: 0x2ce3_b2ff },
    CdnRange { first: 0x2cea_5afc, last: 0x2cea_5aff },
    CdnRange { first: 0x2cea_6c80, last: 0x2cea_6cff },
    CdnRange { first: 0x2f81_5200, last: 0x2f81_54ff },
    CdnRange { first: 0x332c_ea00, last: 0x332c_efff },
    CdnRange { first: 0x334a_c000, last: 0x334a_ffff },
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
    CdnRange { first: 0x40fc_4000, last: 0x40fc_bfff },
    CdnRange { first: 0x4108_0000, last: 0x4109_bfff },
    CdnRange { first: 0x4684_0000, last: 0x4684_3fff },
    CdnRange { first: 0x4798_0000, last: 0x4798_7fff },
    CdnRange { first: 0x634f_a900, last: 0x634f_a9ff },
    CdnRange { first: 0x6354_0000, last: 0x6354_ffff },
    CdnRange { first: 0x6356_0000, last: 0x6356_ffff },
    CdnRange { first: 0x6c8a_0000, last: 0x6c8b_ffff },
    CdnRange { first: 0x6c9c_0000, last: 0x6c9f_ffff },
    CdnRange { first: 0x6f0d_ab80, last: 0x6f0d_abff },
    CdnRange { first: 0x6f0d_b920, last: 0x6f0d_b95f },
    CdnRange { first: 0x7481_e200, last: 0x7481_e2bf },
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
    CdnRange { first: 0x82b0_0000, last: 0x82b0_efff },
    CdnRange { first: 0x8fcc_0000, last: 0x8fcc_ffff },
    CdnRange { first: 0x90dc_0000, last: 0x90dc_ffff },
    CdnRange { first: 0xb4a3_3900, last: 0xb4a3_39bf },
    CdnRange { first: 0xccf6_a400, last: 0xccf6_bfff },
    CdnRange { first: 0xcdfb_ca00, last: 0xcdfb_dfff },
    CdnRange { first: 0xcdfb_f900, last: 0xcdfb_feff },
    CdnRange { first: 0xd889_2000, last: 0xd889_3fff },
];
const CLOUDFRONT_SNIS: &[&str] = &[
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
];

#[rustfmt::skip]
const VERCEL_RANGES: &[CdnRange] = &[
    CdnRange { first: 0x4c4c_1500, last: 0x4c4c_15ff },
];
const VERCEL_SNIS: &[&str] = &[
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
];

#[rustfmt::skip]
const GITHUB_RANGES: &[CdnRange] = &[
    CdnRange { first: 0x04d0_1ac5, last: 0x04d0_1ac6 },
    CdnRange { first: 0x04d0_1ac8, last: 0x04d0_1ac8 },
    CdnRange { first: 0x04e1_0bc2, last: 0x04e1_0bc2 },
    CdnRange { first: 0x04e1_0bc8, last: 0x04e1_0bc9 },
    CdnRange { first: 0x04e4_1f91, last: 0x04e4_1f91 },
    CdnRange { first: 0x04e4_1f95, last: 0x04e4_1f96 },
    CdnRange { first: 0x04ed_1622, last: 0x04ed_1622 },
    CdnRange { first: 0x04ed_1626, last: 0x04ed_1626 },
    CdnRange { first: 0x04ed_1628, last: 0x04ed_1628 },
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
    CdnRange { first: 0x8c52_7000, last: 0x8c52_7fff },
    CdnRange { first: 0x8f37_4000, last: 0x8f37_4fff },
    CdnRange { first: 0xb9c7_6c00, last: 0xb9c7_6fff },
    CdnRange { first: 0xc01e_fc00, last: 0xc01e_ffff },
];
const GITHUB_SNIS: &[&str] = &[
    "actions.githubusercontent.com",
    "alambic-origin.githubusercontent.com",
    "alive.github.com",
    "api.github.com",
    "api.githubcopilot.com",
    "api.individual.githubcopilot.com",
    "avatars.githubusercontent.com",
    "camo-origin.githubusercontent.com",
    "camo.githubusercontent.com",
    "central.github.com",
    "codeload.github.com",
    "collector.github.com",
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
    "raw.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "uploads.github.com",
    "www.github.com",
    "xtls.github.io",
];

#[rustfmt::skip]
const GOOGLE_RANGES: &[CdnRange] = &[
    CdnRange { first: 0x0808_0400, last: 0x0808_04ff },
    CdnRange { first: 0x0808_0800, last: 0x0808_08ff },
    CdnRange { first: 0x40e9_b400, last: 0x40e9_b4ff },
    CdnRange { first: 0x8efb_9600, last: 0x8efb_9dff },
    CdnRange { first: 0x8efb_a300, last: 0x8efb_a3ff },
    CdnRange { first: 0x8efb_a700, last: 0x8efb_a7ff },
    CdnRange { first: 0x8efb_b300, last: 0x8efb_b3ff },
    CdnRange { first: 0xacfd_8b00, last: 0xacfd_8bff },
];
const GOOGLE_SNIS: &[&str] = &[
    "dns.google",
    "google.com",
    "google-main-services.redirect",
    "googlevideo.com",
    "www.google.com",
    "www.googlevideo.com",
    "www.youtube.com",
];

pub(crate) const CDN_SETS: &[CdnSet] = &[
    CdnSet {
        name: "built-in-legacy-android-overrides",
        ranges: LEGACYANDROIDOVERRIDE_RANGES,
        snis: LEGACYANDROIDOVERRIDE_SNIS,
    },
    CdnSet {
        name: "built-in-curated-fronting",
        ranges: CURATED_RANGES,
        snis: CURATED_SNIS,
    },
    CdnSet {
        name: "built-in-psiphon-akamai",
        ranges: AKAMAI_RANGES,
        snis: AKAMAI_SNIS,
    },
    CdnSet {
        name: "built-in-fastly",
        ranges: FASTLY_RANGES,
        snis: FASTLY_SNIS,
    },
    CdnSet {
        name: "built-in-psiphon-bunny",
        ranges: BUNNY_RANGES,
        snis: BUNNY_SNIS,
    },
    CdnSet {
        name: "built-in-cloudflare",
        ranges: CLOUDFLARE_RANGES,
        snis: CLOUDFLARE_SNIS,
    },
    CdnSet {
        name: "built-in-cloudfront",
        ranges: CLOUDFRONT_RANGES,
        snis: CLOUDFRONT_SNIS,
    },
    CdnSet {
        name: "built-in-vercel",
        ranges: VERCEL_RANGES,
        snis: VERCEL_SNIS,
    },
    CdnSet {
        name: "built-in-github",
        ranges: GITHUB_RANGES,
        snis: GITHUB_SNIS,
    },
    CdnSet {
        name: "built-in-google",
        ranges: GOOGLE_RANGES,
        snis: GOOGLE_SNIS,
    },
];

/// The selected sets, in configuration order, with the reference's
/// `built-in-` prefix optional; an empty name list selects every set.
pub(crate) fn select(names: &[String]) -> Vec<&'static CdnSet> {
    if names.is_empty() {
        return CDN_SETS.iter().collect();
    }
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if matches!(name.as_str(), "builtin" | "fronted-meek") {
            return CDN_SETS.iter().collect();
        }
        let name = match name.as_str() {
            "legacy" => "legacy-android-overrides",
            "akamai" => "psiphon-akamai",
            "bunny" => "psiphon-bunny",
            _ => name.as_str(),
        };
        if let Some(set) = CDN_SETS
            .iter()
            .find(|set| set.name == name || set.name.strip_prefix("built-in-") == Some(name))
        {
            out.push(set);
        }
    }
    out
}

/// At most `limit` addresses, one equal share from each selected set.
pub(crate) fn sample_ips(sets: &[&'static CdnSet], limit: usize) -> Vec<String> {
    if limit == 0 || sets.is_empty() {
        return Vec::new();
    }
    let total: u64 = sets.iter().map(|set| set_size(set)).sum();
    let limit = u64::try_from(limit).unwrap_or(u64::MAX);
    if total <= limit {
        let mut out = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
        for range in sets.iter().flat_map(|set| set.ranges) {
            for address in range.first..=range.last {
                out.push(ipaddress(address));
            }
        }
        return out;
    }
    let capacity: Vec<u64> = sets.iter().map(|set| set_size(set)).collect();
    let mut quotas = vec![0u64; sets.len()];
    let mut assigned = 0;
    while assigned < limit {
        let mut added = false;
        for (quota, capacity) in quotas.iter_mut().zip(&capacity) {
            if *quota < *capacity {
                *quota += 1;
                assigned += 1;
                added = true;
                if assigned == limit {
                    break;
                }
            }
        }
        if !added {
            break;
        }
    }
    let mut out = Vec::with_capacity(usize::try_from(limit).unwrap_or(0));
    let rounds = quotas.iter().copied().max().unwrap_or(0);
    for round in 0..rounds {
        for (set, &quota) in sets.iter().zip(&quotas) {
            if round >= quota {
                continue;
            }
            let size = set_size(set);
            let offset = round.saturating_mul(size) / quota;
            if let Some(address) = address_at(set, offset) {
                out.push(address);
            }
        }
    }
    out
}

fn set_size(set: &CdnSet) -> u64 {
    set.ranges
        .iter()
        .map(|range| u64::from(range.last - range.first) + 1)
        .sum()
}

fn address_at(set: &CdnSet, offset: u64) -> Option<String> {
    let mut offset = offset;
    for range in set.ranges {
        let size = u64::from(range.last - range.first) + 1;
        if offset < size {
            return Some(ipaddress(range.first + u32::try_from(offset).ok()?));
        }
        offset -= size;
    }
    None
}

fn ipaddress(address: u32) -> String {
    std::net::Ipv4Addr::from(address).to_string()
}

/// The selected sets' SNI names, in configuration order, without duplicates.
pub(crate) fn snis(sets: &[&'static CdnSet]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for set in sets {
        for sni in set.snis {
            if !out.contains(sni) {
                out.push(sni);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{select, snis, CdnSet, CDN_SETS};

    #[test]
    fn the_builtin_corpus_is_every_upstream_set() {
        assert_eq!(
            CDN_SETS.iter().map(|set| set.name).collect::<Vec<_>>(),
            vec![
                "built-in-legacy-android-overrides",
                "built-in-curated-fronting",
                "built-in-psiphon-akamai",
                "built-in-fastly",
                "built-in-psiphon-bunny",
                "built-in-cloudflare",
                "built-in-cloudfront",
                "built-in-vercel",
                "built-in-github",
                "built-in-google",
            ]
        );
        let mut ranges = CDN_SETS
            .iter()
            .flat_map(|set| set.ranges)
            .map(|range| (range.first, range.last))
            .collect::<Vec<_>>();
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::new();
        for (first, last) in ranges {
            if let Some(previous) = merged.last_mut() {
                if first <= previous.1.saturating_add(1) {
                    previous.1 = previous.1.max(last);
                    continue;
                }
            }
            merged.push((first, last));
        }
        let addresses: u64 = merged
            .iter()
            .map(|(first, last)| u64::from(last - first) + 1)
            .sum();
        assert_eq!(merged.len(), 687);
        assert_eq!(addresses, 6_036_311);
        let all: Vec<&CdnSet> = CDN_SETS.iter().collect();
        assert_eq!(snis(&all).len(), 122);
    }

    #[test]
    fn sampling_gives_a_small_set_the_same_share_as_a_large_one() {
        use std::net::Ipv4Addr;

        let sets = select(&["vercel".to_owned(), "google".to_owned()]);
        let sampled = super::sample_ips(&sets, 8);
        assert_eq!(sampled.len(), 8);
        for set in &sets {
            let count = sampled
                .iter()
                .filter(|address| {
                    let address = u32::from(address.parse::<Ipv4Addr>().expect("address"));
                    set.ranges
                        .iter()
                        .any(|range| (range.first..=range.last).contains(&address))
                })
                .count();
            assert_eq!(count, 4, "{} got {count}", set.name);
        }
    }

    #[test]
    fn sampling_all_sets_keeps_the_smallest_set_in_the_scan() {
        use std::net::Ipv4Addr;

        let all: Vec<&CdnSet> = CDN_SETS.iter().collect();
        let sampled = super::sample_ips(&all, 128);
        assert_eq!(sampled.len(), 128);
        for set in &all {
            let count = sampled
                .iter()
                .filter(|address| {
                    let address = u32::from(address.parse::<Ipv4Addr>().expect("address"));
                    set.ranges
                        .iter()
                        .any(|range| (range.first..=range.last).contains(&address))
                })
                .count();
            assert!(count >= 9, "{} got {count}", set.name);
        }
    }

    #[test]
    fn a_named_set_is_selected_once_in_configuration_order() {
        let names = ["google".to_owned(), "built-in-google".to_owned()];
        assert_eq!(
            select(&names)
                .iter()
                .map(|set| set.name)
                .collect::<Vec<_>>(),
            vec!["built-in-google", "built-in-google"]
        );
        assert!(select(&["missing".to_owned()]).is_empty());
    }
}
