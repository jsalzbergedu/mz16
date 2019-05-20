use byteorder::ByteOrder;
use byteorder::LittleEndian;

/// At the start of every mz header
pub static MZ_HEADER_START: u16 = 0x5A4D;

/// An error in a header
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HeaderError {
    /// Does not follow the format of an mz 16 bit dos executable.
    NotMZ,
    /// Header could not be read from bytes (too few bytes)
    NoHeader,
}

impl HeaderError {
    pub fn to_str(&self) -> &'static str {
        match self {
            HeaderError::NotMZ => "Not an MZ header.",
            HeaderError::NoHeader => "No header could be read.",
        }
    }
}

/// A definition of a header in a 16 bit dos executable
#[derive(Debug)]
pub struct Header {
    pub signature: u16,
    pub extra_bytes: u16,
    pub pages: u16,
    pub reloc_items: u16,
    pub header_size: u16,
    pub min_alloc: u16,
    pub max_alloc: u16,
    pub init_ss: u16,
    pub init_sp: u16,
    pub checksum: u16,
    pub init_ip: u16,
    pub init_cs: u16,
    pub reloc_table: u16,
    pub overlay: u16,
}

impl Header {
    /// Read a header from 14 16-bit words
    pub fn from_words(words: [u16; 14]) -> Result<Header, HeaderError> {
        if words[0] != MZ_HEADER_START {
            return Err(HeaderError::NotMZ);
        }
        let out = Header {
            signature: words[0],
            extra_bytes: words[1],
            pages: words[2],
            reloc_items: words[3],
            header_size: words[4],
            min_alloc: words[5],
            max_alloc: words[6],
            init_ss: words[7],
            init_sp: words[8],
            checksum: words[9],
            init_ip: words[10],
            init_cs: words[11],
            reloc_table: words[12],
            overlay: words[13],
        };
        Ok(out)
    }

    /// Read a header from bytes
    pub fn new(bytes: &[u8]) -> Result<Header, HeaderError> {
        let mut words: [u16; 14] = [0u16; 14];
        let mut it = bytes.chunks_exact(2);
        for i in 0..14 {
            match it.next() {
                Some(some) => {
                    words[i] = LittleEndian::read_u16(some);
                }
                None => {
                    return Err(HeaderError::NoHeader);
                }
            }
        }
        Header::from_words(words)
    }

    /// Get the start of the exe data
    #[inline]
    pub fn exe_data_start(&self) -> usize {
        (self.header_size as usize) * 16
    }

    /// Get the start of the extra data
    pub fn extra_data_start(&self) -> usize {
        let mut extra_data_start = (self.pages as usize) * 512;
        if self.extra_bytes != 0 {
            extra_data_start -= 512 - (self.extra_bytes as usize);
        }
        extra_data_start
    }

    /// Get the start of the relocation table
    #[inline]
    pub fn relocation_table_start(&self) -> usize {
        self.reloc_table as usize
    }

    /// Get the end of the relocation table
    #[inline]
    pub fn relocation_table_end(&self) -> usize {
        // The *2 *2 comes from there being two
        // words in a relocation table entry
        // and two bytes in a word
        (self.reloc_table + (self.reloc_items * 2 * 2)) as usize
    }

    /// Get the exe data as a slice
    pub fn exe_data<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        match bytes.split_at(self.extra_data_start()) {
            (data, _) => match data.split_at(self.exe_data_start()) {
                (_, data) => data,
            },
        }
    }

    /// Get the extra data as a slice
    pub fn extra_data<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        match bytes.split_at(self.extra_data_start()) {
            (_, data) => data,
        }
    }

    /// Get the header data
    pub fn header_data<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        // A paragraph = 16 bytes
        let header_offset = (self.header_size as usize) * 16;
        match bytes.split_at(header_offset) {
            (data, _) => data,
        }
    }

    /// Get the relocation table data
    pub fn relocation_table_data<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        match bytes.split_at(self.relocation_table_end()) {
            (data, _) => match data.split_at(self.relocation_table_start()) {
                (_, data) => data,
            },
        }
    }
}
