static MAGIC_NUM: u32 = 0x5e04567f;

pub fn xor_u32(data: u32) -> u32 {
    data ^ MAGIC_NUM
}
