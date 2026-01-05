#[derive(Debug, Clone)]
pub struct Crc32 {
    value: u32,
    table: [u32; 256],
}

impl Crc32 {
    pub fn new() -> Self {
        Self {
            value: 0xFFFF_FFFF,
            table: generate_table(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for byte in data {
            let idx = (self.value ^ (*byte as u32)) & 0xFF;
            self.value = (self.value >> 8) ^ self.table[idx as usize];
        }
    }

    pub fn finalize(&self) -> u32 {
        !self.value
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(data);
    crc.finalize()
}

fn generate_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let polynomial: u32 = 0xEDB8_8320;

    for (i, entry) in table.iter_mut().enumerate() {
        let mut value = i as u32;
        for _ in 0..8 {
            if value & 1 == 1 {
                value = (value >> 1) ^ polynomial;
            } else {
                value >>= 1;
            }
        }
        *entry = value;
    }

    table
}
