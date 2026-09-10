// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! RISC Zero-accelerated implementation of the exact BN254 Poseidon2 permutation used by SAFE.

use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};

const WIDTH: usize = 4;
const MODULUS: [u32; 8] = [
    0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FastField([u32; 8]);

impl FastField {
    const ZERO: Self = Self([0; 8]);

    fn from_ark(value: Fr) -> Self {
        let words = value.into_bigint().0;
        Self([
            words[0] as u32,
            (words[0] >> 32) as u32,
            words[1] as u32,
            (words[1] >> 32) as u32,
            words[2] as u32,
            (words[2] >> 32) as u32,
            words[3] as u32,
            (words[3] >> 32) as u32,
        ])
    }

    fn into_ark(self) -> Fr {
        Fr::from_bigint(BigInt([
            u64::from(self.0[0]) | (u64::from(self.0[1]) << 32),
            u64::from(self.0[2]) | (u64::from(self.0[3]) << 32),
            u64::from(self.0[4]) | (u64::from(self.0[5]) << 32),
            u64::from(self.0[6]) | (u64::from(self.0[7]) << 32),
        ]))
        .expect("accelerated field operation returned a non-canonical value")
    }

    fn add(self, rhs: Self) -> Self {
        let mut output = [0u32; 8];
        let mut carry = 0u64;
        for (index, value) in output.iter_mut().enumerate() {
            let sum = u64::from(self.0[index]) + u64::from(rhs.0[index]) + carry;
            *value = sum as u32;
            carry = sum >> 32;
        }
        debug_assert_eq!(carry, 0, "two BN254 values cannot overflow 256 bits");

        if !less_than(&output, &MODULUS) {
            subtract_modulus(&mut output);
        }
        Self(output)
    }

    fn double(self) -> Self {
        self.add(self)
    }

    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    fn multiply(self, rhs: Self) -> Self {
        let mut output = [0u32; 8];
        risc0_bigint2::field::modmul_256(&self.0, &rhs.0, &MODULUS, &mut output);
        Self(output)
    }

    #[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
    fn multiply(self, rhs: Self) -> Self {
        Self::from_ark(self.into_ark() * rhs.into_ark())
    }

    fn pow_five(self) -> Self {
        let squared = self.multiply(self);
        let fourth = squared.multiply(squared);
        self.multiply(fourth)
    }
}

fn less_than(lhs: &[u32; 8], rhs: &[u32; 8]) -> bool {
    for index in (0..8).rev() {
        if lhs[index] != rhs[index] {
            return lhs[index] < rhs[index];
        }
    }
    false
}

fn subtract_modulus(value: &mut [u32; 8]) {
    let mut borrow = false;
    for index in 0..8 {
        let (first, first_borrow) = value[index].overflowing_sub(MODULUS[index]);
        let (second, second_borrow) = first.overflowing_sub(u32::from(borrow));
        value[index] = second;
        borrow = first_borrow || second_borrow;
    }
    debug_assert!(!borrow, "the value must be at least the modulus")
}

const ROUNDS_F: usize = 8;
const ROUNDS_P: usize = 56;

const MAT_DIAG_M_1: [FastField; WIDTH] = [
    FastField([
        0x19d3b6e7, 0xb56821fd, 0x29ca1d7f, 0x0d03f989, 0x4bd9490c, 0x04b1e03b, 0x006ea38b,
        0x10dc6e9c,
    ]),
    FastField([
        0xb45a740b, 0xa86b38cf, 0xd4dd9b84, 0x99df9756, 0xa30b3bb5, 0x0149b3d0, 0x6a44df3e,
        0x0c28145b,
    ]),
    FastField([
        0x141cac15, 0x70067d00, 0x60e35961, 0xb21f75bb, 0x50392798, 0xb2c7645a, 0x38791518,
        0x00544b83,
    ]),
    FastField([
        0x33ee428b, 0x13bc5344, 0xb8fa8526, 0x52e105a3, 0x122789e3, 0x2e2e82eb, 0x5718386f,
        0x222c0117,
    ]),
];
const EXTERNAL_RC: [[FastField; WIDTH]; ROUNDS_F] = [
    // First external
    [
        FastField([
            0x69ed23e5, 0x8b0878e2, 0x4edc2623, 0x02bb8674, 0xbd5e4a43, 0x48da1d39, 0x9450b068,
            0x19b849f6,
        ]),
        FastField([
            0x8dcf34d6, 0xad47f80c, 0x450acc1d, 0x20eb2cc7, 0x758f0a13, 0x7239347b, 0x27dd51bd,
            0x265ddfe1,
        ]),
        FastField([
            0xb497d8aa, 0x3dfc36ba, 0x5015c2aa, 0x4108ac84, 0x5e1e5162, 0xe0f66a54, 0x472f1809,
            0x199750ec,
        ]),
        FastField([
            0xc7f1cdf8, 0xd032f787, 0x5067f0ff, 0x4d743ea2, 0xf74302b1, 0x110f06a5, 0x65ac7208,
            0x157ff3fe,
        ]),
    ],
    [
        FastField([
            0x6ac94902, 0xfe18f489, 0x692f8bee, 0x0b15c590, 0x5fca33f1, 0x5fd35ac4, 0x4569dd9c,
            0x2e49c43c,
        ]),
        FastField([
            0xfa2d1f1e, 0x2731345f, 0x73c24fa8, 0xcb2f0b69, 0x6d6506c3, 0x0d4aef2b, 0x98189052,
            0x0e35fb89,
        ]),
        FastField([
            0x02e0b996, 0xc6fe7230, 0x6d667ffe, 0xa9d9e780, 0x5e944f1b, 0x05f109ae, 0xb15c4f11,
            0x251ad47c,
        ]),
        FastField([
            0x9c22df4e, 0x563fa39d, 0xdd05e5f3, 0xf8beb56f, 0x60234641, 0x9873e971, 0x64d42836,
            0x13da07dc,
        ]),
    ],
    [
        FastField([
            0x55fd4738, 0x46e7b890, 0x89d350cd, 0xa5539396, 0xccef7483, 0x3dc00c7d, 0xe650e6d2,
            0x0c009b84,
        ]),
        FastField([
            0xbefdca06, 0x203dec74, 0x6d535eb0, 0x04eb650c, 0x56f42d8b, 0x01992e39, 0xc63a854f,
            0x011f16b1,
        ]),
        FastField([
            0x3f367549, 0x85df0709, 0x467ad454, 0x2f3f78d0, 0x1daa7961, 0x209d9a56, 0x383a688f,
            0x0ed69e5e,
        ]),
        FastField([
            0x4c9f789b, 0x46367226, 0x5eb3d33f, 0x3aec507f, 0x472b6bbe, 0x21acad41, 0x7b0ce9e2,
            0x04dba94a,
        ]),
    ],
    [
        FastField([
            0xd4fa28e8, 0xce732ff1, 0x4bb50bf7, 0x6036757d, 0x1c9d237b, 0x6eb09427, 0xd840f3a1,
            0x0a3f2637,
        ]),
        FastField([
            0x1182323f, 0xe54a485d, 0x569564b6, 0x39b1f075, 0x2fdb38fa, 0x8f8a1c50, 0x129eea19,
            0x259a666f,
        ]),
        FastField([
            0xede0d6a1, 0x7a32fdf7, 0x1038e515, 0x7745d427, 0x4ee3a47f, 0xd8e7d06a, 0xc9b2f4c6,
            0x28bf7459,
        ]),
        FastField([
            0x41432447, 0xec91bd69, 0xcce6a2ae, 0xc37c85bb, 0x489be8d4, 0x26ea200f, 0xf0570375,
            0x0a1ca941,
        ]),
    ],
    // Second external
    [
        FastField([
            0xb1405d38, 0xf3b16ef2, 0x6be63b09, 0xab0fb85f, 0xc6f287f6, 0x77eb757b, 0x4b7a3e17,
            0x1797130f,
        ]),
        FastField([
            0x5decc6e5, 0x36c66855, 0x20156d4d, 0x8c7f497c, 0xbab59e60, 0x3306c85a, 0xc04170ae,
            0x0a76225d,
        ]),
        FastField([
            0x26a31a5c, 0x96174b53, 0x8acb6647, 0xf8fa76d4, 0x93209af6, 0xa1e77a7b, 0x1992d66b,
            0x1fffb9ec,
        ]),
        FastField([
            0x797b9c5f, 0x0611889b, 0xc6b9c609, 0x5f8fbba6, 0x8fa538d8, 0x53b57c33, 0xc15a3f28,
            0x25721c4f,
        ]),
    ],
    [
        FastField([
            0xbfcaf75a, 0xeb63b982, 0x0705da95, 0xadb4c379, 0xba197216, 0x215e3d07, 0x2d5f7a41,
            0x0c817fd4,
        ]),
        FastField([
            0xe52b5a96, 0x2bc15866, 0xe00a2200, 0xdf8cf86c, 0xc24970b6, 0x9f7e13c2, 0x239915d3,
            0x13abe3f5,
        ]),
        FastField([
            0xb4d391ce, 0x92cd60ac, 0x29bdbd7a, 0x5c1bc3dc, 0x987a46c8, 0x12ef7f39, 0x546224ea,
            0x2106feea,
        ]),
        FastField([
            0x5bb0f959, 0x57e1b334, 0xc748bc71, 0xf1ca5a28, 0xa37dab49, 0xaaa79474, 0x68a746b6,
            0x21ca8594,
        ]),
    ],
    [
        FastField([
            0x9e34185b, 0x8f1a4899, 0x0321662a, 0x2911d14d, 0x934194c6, 0x5cf1f0df, 0x5c1e6f0c,
            0x05ccd625,
        ]),
        FastField([
            0xb09490a4, 0xea28678c, 0x7fe44fe6, 0x16c4fb26, 0x674c4c88, 0xe464d846, 0x4b70a626,
            0x0f0e34a6,
        ]),
        FastField([
            0x2de0d4bf, 0x8f5b1a8a, 0x350d6483, 0x47dbfcfe, 0xa36d0e96, 0x6157794c, 0x4e25470c,
            0x0558531a,
        ]),
        FastField([
            0x961f1455, 0xb72f5864, 0x3f655a60, 0x924cadad, 0x57683d18, 0xceea1251, 0x173ed2fa,
            0x09d3dca9,
        ]),
    ],
    [
        FastField([
            0xe5bd4335, 0x17d4c722, 0x8aaec486, 0xf23f92d6, 0xd03d218b, 0x493f866e, 0x4e8c0913,
            0x0328cbd5,
        ]),
        FastField([
            0x5329d34b, 0xee3347dd, 0x9798c648, 0xe79e7bcc, 0xa7094e07, 0x23a487b1, 0xe2aff0a2,
            0x2bf07216,
        ]),
        FastField([
            0x3fe412df, 0x111e11a6, 0xa6dffc82, 0xd6f78ed6, 0xcb76c316, 0x6499c583, 0x58006b73,
            0x1daf345a,
        ]),
        FastField([
            0x93d2c404, 0x391e6f22, 0xb2edc7ff, 0x1ef39039, 0x0e182361, 0x46b694c6, 0x2456aaa7,
            0x17656347,
        ]),
    ],
];
const INTERNAL_RC: [FastField; ROUNDS_P] = [
    FastField([
        0x926361cf, 0xb43a26fd, 0x39f051dc, 0x5535ed15, 0xc5451285, 0x53d7fd4f, 0x8be0e930,
        0x0c6f8f95,
    ]),
    FastField([
        0x9caaf811, 0x84dd57e6, 0x08e296e0, 0xa9e8a007, 0x8ac9d90a, 0xd426e812, 0x3cd17578,
        0x123106a9,
    ]),
    FastField([
        0xcd2dee75, 0x7b074867, 0xf1e8f187, 0x5e8fa83f, 0xf8e84008, 0x7dd3ab52, 0xad9285d9,
        0x26e1ba52,
    ]),
    FastField([
        0x6a4ae2c5, 0x4471537e, 0xf9e09586, 0xbe4d8b7b, 0x47b9c97c, 0x18a64c5c, 0x7bd133de,
        0x1cb55cad,
    ]),
    FastField([
        0x6e9055d0, 0x7143f08e, 0x5060a41c, 0x2a53043d, 0x4bde7f6d, 0x0e2c7ce0, 0x6acd8f8e,
        0x1dcd73e4,
    ]),
    FastField([
        0x512e5574, 0xb12b9bb4, 0x0eb4e9b9, 0x0cda294a, 0x474a4def, 0xf5852f05, 0x2f6d9c66,
        0x011003e3,
    ]),
    FastField([
        0x2287ae8c, 0xd7c508dd, 0x3f58bafe, 0xbadfe590, 0x03a57dfe, 0x9ad5f20d, 0xc1d10ab2,
        0x2b1e809a,
    ]),
    FastField([
        0x7bcec0a5, 0xeaa69ae8, 0xab2fc5fa, 0xef995d05, 0x5ee17ed0, 0x9fb4dac3, 0x85b73599,
        0x2539de17,
    ]),
    FastField([
        0x1d77951d, 0x43982cb1, 0x1c86d46e, 0xf4e1c3d4, 0x2b3e0a0e, 0x26497f22, 0x2ef8ee01,
        0x0c246c5a,
    ]),
    FastField([
        0xd03b527b, 0x3f0305f5, 0xad1a1c2f, 0xbb09e6a6, 0x7c0632ed, 0x5408148f, 0x974f68e9,
        0x192089c4,
    ]),
    FastField([
        0xb5a60d85, 0x6d8fdc2f, 0x91096b75, 0x8529097d, 0xeb0d0c05, 0x6a0ee36e, 0xab68b2f0,
        0x1eae0ad8,
    ]),
    FastField([
        0xc5d06bfb, 0x9768bd98, 0x0dee99e6, 0xdb6e2fdc, 0x872abc88, 0xe46f8282, 0xd0e22179,
        0x179190e5,
    ]),
    FastField([
        0xa9b3cd1c, 0x6cafe794, 0xb00f31bf, 0x14528f7d, 0x7ac4b832, 0x76e9a81c, 0x90767325,
        0x29bb9e2c,
    ]),
    FastField([
        0x6e691e08, 0xb10e590e, 0x882aac35, 0x52652645, 0x2464a90d, 0x403efd0c, 0x42207599,
        0x225d394e,
    ]),
    FastField([
        0x4b23fd59, 0xe09efd45, 0x451c087d, 0x2be13557, 0x55b44453, 0x753d2380, 0x3c25c8cf,
        0x06476062,
    ]),
    FastField([
        0x8f6b5b87, 0x922910a7, 0x42a75c10, 0x4d67f4bf, 0x716d8a39, 0x7f301c4b, 0x01df92e8,
        0x10ba3a0e,
    ]),
    FastField([
        0x3f21471c, 0x361b7769, 0xc242eb9d, 0xcb511bc0, 0xb0c2a801, 0x4f9c6e96, 0x3f8451b2,
        0x0e070bf5,
    ]),
    FastField([
        0x4de252fb, 0xa7f92101, 0xd2491d8a, 0xccd6cb11, 0x93821a73, 0xd39755ff, 0xb051b04d,
        0x1b94cd61,
    ]),
    FastField([
        0x7d74070b, 0x0487b5aa, 0x5713bb05, 0x9d4e917d, 0x2e70230f, 0xe148787a, 0xafb8c744,
        0x1d7cb39b,
    ]),
    FastField([
        0x303b17db, 0xbb74ac1f, 0x1829f701, 0x8785c296, 0x980c80ff, 0x9117d0fe, 0xbd1ab4f6,
        0x2ec93189,
    ]),
    FastField([
        0x83517926, 0x82ea46bd, 0x9ae07a90, 0xeac404a1, 0x5b86275b, 0xa692bb82, 0xdd36d277,
        0x2db366bf,
    ]),
    FastField([
        0x960711b8, 0xdc99cec6, 0x8450359a, 0x98527542, 0x86a68532, 0x69655cf1, 0x485db062,
        0x062100eb,
    ]),
    FastField([
        0x41f5a59b, 0x00c567bf, 0xfa59e4f9, 0x20243f92, 0x8244ca11, 0x570e7f1e, 0x66614aaa,
        0x0761d33c,
    ]),
    FastField([
        0x4855ad0d, 0xf7a72e49, 0x0f7de4cc, 0x5d78608a, 0x034e3f31, 0x2c2705aa, 0x114d1399,
        0x20fc411a,
    ]),
    FastField([
        0x7250bc5a, 0xc3a30f31, 0xb3effb5f, 0x102c67e8, 0x9ab219ba, 0xadd9ec4e, 0xa4bdfcb5,
        0x25b5c004,
    ]),
    FastField([
        0x62b37f4b, 0xd87e7dff, 0x8474155a, 0x038b186d, 0x6df6f5ed, 0xa494e58f, 0x278ed632,
        0x23b1822d,
    ]),
    FastField([
        0xcc2f69e0, 0x16102a29, 0xfcfcccaa, 0x0f14d13b, 0x012499bf, 0x606c4ba9, 0x5c3f9493,
        0x22734b4c,
    ]),
    FastField([
        0xad795ce5, 0x54413d3f, 0x9aa36102, 0xe5bdff40, 0x33492347, 0xe27a74dc, 0x09eb30b7,
        0x26c0c8fe,
    ]),
    FastField([
        0x348ccad9, 0xbbd626df, 0x3a809829, 0x196be308, 0xfa1fbb26, 0xe88eac03, 0xb6bd7bba,
        0x070dd0cc,
    ]),
    FastField([
        0xfd4250da, 0x6067c4eb, 0x46d8c5ad, 0xc2c0a6de, 0xbb28c3be, 0xb043ba78, 0xdb329b6f,
        0x12b6595b,
    ]),
    FastField([
        0xb7e8d729, 0x5e33d95b, 0x275c671c, 0xc06fca9b, 0xa5876c11, 0x3bec30e7, 0xf76283d6,
        0x248d97d7,
    ]),
    FastField([
        0xbd9baaaa, 0x106d15d9, 0x9ddde4aa, 0x8b45eb75, 0x4cc93931, 0x16fc6fd6, 0x9d463b08,
        0x1a306d43,
    ]),
    FastField([
        0xec7c56cf, 0x0d62d3d6, 0xdc27821b, 0xf4f1b54d, 0x21cb4621, 0xced7c004, 0x2e3c38da,
        0x28a8f837,
    ]),
    FastField([
        0xe1e2ce7e, 0xbc852183, 0xc829f388, 0x071ce320, 0x24d43294, 0xbb35152f, 0x17f9a8a8,
        0x00949757,
    ]),
    FastField([
        0xdb2e8d65, 0xf4103246, 0xf653ae83, 0x593f74d4, 0x716480d3, 0x80fde60d, 0x3aa78f7d,
        0x04d5ee4c,
    ]),
    FastField([
        0x2efde187, 0xd08495c1, 0x8822cc76, 0xc7bef54b, 0xb8ed2269, 0x6349ad6f, 0xaa03d433,
        0x2a6cf5e9,
    ]),
    FastField([
        0xefcba3f3, 0xbaae48d7, 0x08fd6e43, 0xf7921808, 0xe19ddeb7, 0x9274da43, 0xaab960ba,
        0x2304d31e,
    ]),
    FastField([
        0xd199f0b0, 0xe1c11d39, 0x0726fcb4, 0xbff08a7e, 0x85817249, 0xd5e70097, 0x65a4b2a6,
        0x03fd9ac8,
    ]),
    FastField([
        0xd63b0b64, 0x3f7954d4, 0x20919307, 0x798afc3a, 0x55ee5044, 0x2248404d, 0xed52bbda,
        0x00b7258d,
    ]),
    FastField([
        0x65e92d9a, 0x6272c5ca, 0xf3298db3, 0xb13d3a74, 0xd4bf65eb, 0xec38fca2, 0xa0771799,
        0x159f81ad,
    ]),
    FastField([
        0x4264431f, 0x71e144cf, 0xa25f0c54, 0x9000130e, 0xbc28e3bb, 0x50237a75, 0x437fbc85,
        0x1ef90e67,
    ]),
    FastField([
        0x2932e30d, 0x95a79ed8, 0x176b08ec, 0x8df739bc, 0x41a2d256, 0x196b49aa, 0x515e5ff0,
        0x1e65f838,
    ]),
    FastField([
        0x8c94c33f, 0x6575c106, 0x570e1f82, 0xb18c844e, 0xd079ba74, 0xec6ce768, 0xef3a166c,
        0x2b1b045d,
    ]),
    FastField([
        0x168bb173, 0xf1c6e07c, 0xbef715e3, 0x65dc2d73, 0x109229c1, 0x402543b1, 0x3ceb0ff6,
        0x0832e575,
    ]),
    FastField([
        0x90b6ad16, 0xc5a8e3c3, 0xe8b6451b, 0xb1b841c2, 0xa37d41ba, 0x6b762ae0, 0xcedfb3dc,
        0x02f614e9,
    ]),
    FastField([
        0x7e7ed705, 0x0f6a0be2, 0x77bedff4, 0x7370ebb7, 0x362cad96, 0xdd640b8e, 0x8bd46a60,
        0x0e2427d3,
    ]),
    FastField([
        0x9214a53a, 0x0768bbe2, 0x98c3c7c5, 0x049f0ec0, 0x14e7ce79, 0xeb7c84d4, 0x7c670b6d,
        0x0493630b,
    ]),
    FastField([
        0x5327cea9, 0x3dc06cc8, 0x55d5461a, 0x6bb15153, 0x7066c5a2, 0x4decdab1, 0xe8e48267,
        0x22ead100,
    ]),
    FastField([
        0x6d2a6f16, 0xe5084e0b, 0x5626d04d, 0x583f1ae3, 0xd2554d48, 0xaae2626e, 0x655b42cd,
        0x25b3e56e,
    ]),
    FastField([
        0x0cf6f9d0, 0x4b4fdc0a, 0x349e4c58, 0xb599c336, 0xe8ff13db, 0x5837a6cd, 0xda8836ef,
        0x1e32752a,
    ]),
    FastField([
        0x74d412e5, 0x72a98640, 0xf05078f6, 0x23c00995, 0xf3c3455b, 0xc50f68f6, 0xc15a387c,
        0x2fa2a871,
    ]),
    FastField([
        0xa7d83505, 0xcd18e7c7, 0x661bab7f, 0x54ccbf10, 0x311e889f, 0x278e1db7, 0x9a4424c9,
        0x2f569b8a,
    ]),
    FastField([
        0xb246b43d, 0x44165374, 0x332ffd21, 0xa7df93f7, 0x0234c518, 0x531ade53, 0x110a8fdd,
        0x044cb455,
    ]),
    FastField([
        0xa5319025, 0x78ddc723, 0xadfe1181, 0x91fe8c90, 0x7f2e42b1, 0x42024615, 0x93906d5d,
        0x227808de,
    ]),
    FastField([
        0xa6800355, 0x8579d2e7, 0xe090ad4a, 0x5d03781a, 0x87357986, 0x623adead, 0x34e046bc,
        0x02fcca29,
    ]),
    FastField([
        0x0d8befac, 0xcbec2e06, 0xab91a8dd, 0xbad3f3c5, 0x344a1d36, 0x6abccceb, 0xac120b87,
        0x0ef915f0,
    ]),
];

fn matmul_external(state: &mut [FastField; WIDTH]) {
    let t0 = state[0].add(state[1]);
    let t1 = state[2].add(state[3]);
    let t2 = state[1].double().add(t1);
    let t3 = state[3].double().add(t0);
    let t4 = t1.double().double().add(t3);
    let t5 = t0.double().double().add(t2);
    let t6 = t3.add(t5);
    let t7 = t2.add(t4);
    state[0] = t6;
    state[1] = t5;
    state[2] = t7;
    state[3] = t4;
}

fn external_round(state: &mut [FastField; WIDTH], constants: &[FastField; WIDTH]) {
    for index in 0..WIDTH {
        state[index] = state[index].add(constants[index]).pow_five();
    }
    matmul_external(state);
}

fn internal_round(state: &mut [FastField; WIDTH], constant: FastField) {
    state[0] = state[0].add(constant).pow_five();
    let sum = state.iter().copied().fold(FastField::ZERO, FastField::add);
    for index in 0..WIDTH {
        state[index] = state[index].multiply(MAT_DIAG_M_1[index]).add(sum);
    }
}

pub(super) fn permutation(input: &[Fr; WIDTH]) -> [Fr; WIDTH] {
    let mut state = input.map(FastField::from_ark);
    matmul_external(&mut state);

    for constants in &EXTERNAL_RC[..ROUNDS_F / 2] {
        external_round(&mut state, constants);
    }
    for constant in INTERNAL_RC {
        internal_round(&mut state, constant);
    }
    for constants in &EXTERNAL_RC[ROUNDS_F / 2..] {
        external_round(&mut state, constants);
    }

    state.map(FastField::into_ark)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    fn random_field(rng: &mut ChaCha8Rng) -> Fr {
        Fr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>())
    }

    #[test]
    fn accelerated_field_addition_reduces_at_the_modulus() {
        let modulus_minus_one = Fr::from_bigint(BigInt([
            0x43e1f593f0000000,
            0x2833e84879b97091,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ]))
        .unwrap();

        let reduced = FastField::from_ark(modulus_minus_one).add(FastField::from_ark(Fr::from(1)));
        assert_eq!(reduced, FastField::ZERO);
    }

    #[test]
    fn accelerated_algorithm_matches_the_reference_permutation() {
        let mut rng = ChaCha8Rng::seed_from_u64(0x1f01d);
        for _ in 0..100 {
            let input = [
                random_field(&mut rng),
                random_field(&mut rng),
                random_field(&mut rng),
                random_field(&mut rng),
            ];
            assert_eq!(
                permutation(&input),
                taceo_poseidon2::bn254::t4::permutation(&input)
            );
        }
    }
}
