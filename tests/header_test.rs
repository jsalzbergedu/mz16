use mz16::header::*;

/// Test that the header has all the expected fields,
/// starting with the mz magic numbers and continuing
/// with numbers 1-13
fn enumerated_header(header: &Header) {
    assert_eq!(MZ_HEADER_START, header.signature);
    assert_eq!(1, header.extra_bytes);
    assert_eq!(2, header.pages);
    assert_eq!(3, header.reloc_items);
    assert_eq!(4, header.header_size);
    assert_eq!(5, header.min_alloc);
    assert_eq!(6, header.max_alloc);
    assert_eq!(7, header.init_ss);
    assert_eq!(8, header.init_sp);
    assert_eq!(9, header.checksum);
    assert_eq!(10, header.init_ip);
    assert_eq!(11, header.init_cs);
    assert_eq!(12, header.reloc_table);
    assert_eq!(13, header.overlay);
}

#[test]
fn from_words() {
    {
        let words: [u16; 14] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
        let header = Header::from_words(words);
        assert!(header.is_err());
        assert_eq!(header.unwrap_err(), HeaderError::NotMZ);
    }

    {
        let words: [u16; 14] = [0x5A4D, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
        let header = Header::from_words(words);
        assert!(header.is_ok());
        let header = header.unwrap();
        enumerated_header(&header);
    }
}

#[test]
fn new() {
    {
        let bytes: [u8; 28] = [
            0x4d, 0x5a, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0,
            13, 0,
        ];
        let header = Header::new(&bytes[..]);
        assert!(header.is_ok());
        let header = header.unwrap();
        enumerated_header(&header);
    }

    {
        let bytes: [u8; 28] = [
            0x00, 0x00, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0,
            13, 0,
        ];
        let header = Header::new(&bytes[..]);
        assert!(header.is_err());
        let headererr = header.unwrap_err();
        assert_eq!(headererr, HeaderError::NotMZ);
    }

    {
        let bytes: [u8; 10] = [0; 10];
        let header = Header::new(&bytes[..]);
        assert!(header.is_err());
        let headererr = header.unwrap_err();
        assert_eq!(headererr, HeaderError::NoHeader);
    }
}

#[test]
fn exe_data_start() {
    let words: [u16; 14] = [0x5A4D, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    let header = Header::from_words(words).unwrap();
    assert_eq!(64, header.exe_data_start());
}

#[test]
fn extra_data_start() {
    let words: [u16; 14] = [0x5A4D, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    let header = Header::from_words(words).unwrap();
    assert_eq!(513, header.extra_data_start());
}

#[test]
fn relocation_table_start() {
    let words: [u16; 14] = [0x5A4D, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    let header = Header::from_words(words).unwrap();
    assert_eq!(12, header.relocation_table_start());
}

#[test]
fn relocation_table_end() {
    let mut words: [u16; 14] = [0; 14];
    words[0] = 0x5A4D;
    let mut header = Header::from_words(words).unwrap();
    header.reloc_table = 10;
    header.reloc_items = 0;
    assert_eq!(10, header.relocation_table_end());
    header.reloc_items = 1;
    assert_eq!(14, header.relocation_table_end());
}

static FILE: &[u8; 681] = include_bytes!("../resources/helloworld.exe");

#[test]
fn header_data() {
    let header = Header::new(FILE).unwrap();
    assert_eq!(16 * 3, header.header_data(FILE).len());
    let mut actual = String::new();
    for byte in header.header_data(FILE) {
        actual.push_str(&format!("{:02x} ", byte));
    }
    actual.push_str("\n");
    let expected = include_str!("header_data_expected.txt");
    assert_eq!(expected, actual);
}

#[test]
fn relocation_table_data() {
    let header = Header::new(FILE).unwrap();
    let mut actual = String::new();
    for byte in header.relocation_table_data(FILE) {
        actual.push_str(&format!("{:02x} ", byte));
    }
    actual.push_str("\n");
    let expected = include_str!("relocation_data_expected.txt");
    assert_eq!(expected, actual);
}

#[test]
fn exe_data() {
    let header = Header::new(FILE).unwrap();
    let mut actual = String::new();
    for byte in header.exe_data(FILE) {
        actual.push_str(&format!("{:02x} ", byte));
    }
    actual.push_str("\n");
    let expected = include_str!("exe_data_expected.txt");
    assert_eq!(expected, actual);
}

#[test]
fn extra_data() {
    let header = Header::new(FILE).unwrap();
    let mut actual = String::new();
    for byte in header.extra_data(FILE) {
        actual.push_str(&format!("{:02x} ", byte));
    }
    actual.push_str("\n");
    let expected = include_str!("extra_data_expected.txt");
    assert_eq!(expected, actual);
}
