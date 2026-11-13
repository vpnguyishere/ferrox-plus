use std::io::{self, Read, Write};

pub const MAX_PACKET_DATA_LENGTH: usize = 32 * 1024;
pub const MAX_PACKET_BODY_LENGTH: usize = MAX_PACKET_DATA_LENGTH + 5;
pub const MAX_STRING_LENGTH: i32 = 4096;
pub const MAX_BYTES_LENGTH: i32 = 1024;

const SEGMENT_BITS: u8 = 0x7f;
const CONTINUE_BIT: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub id: i32,
    pub data: Vec<u8>,
}

pub type Varint = i32;
pub type UnsignedShort = u16;
pub type Long = i64;

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub fn read_packet<R: Read>(reader: &mut R) -> io::Result<Packet> {
    read_packet_with_length(reader).map(|(packet, _)| packet)
}

pub fn read_packet_with_length<R: Read>(reader: &mut R) -> io::Result<(Packet, usize)> {
    let (frame, wire_length) = read_frame(reader, MAX_PACKET_BODY_LENGTH)?;
    let packet = decode_packet_body(&frame)?;
    Ok((packet, wire_length))
}

pub fn decode_packet_body(packet_data: &[u8]) -> io::Result<Packet> {
    if packet_data.is_empty() || packet_data.len() > MAX_PACKET_BODY_LENGTH {
        return Err(invalid_data(format!(
            "read packet: bad length: {}",
            packet_data.len()
        )));
    }

    let mut body = packet_data;
    let id = read_varint(&mut body)?;
    if body.len() > MAX_PACKET_DATA_LENGTH {
        return Err(invalid_data(format!(
            "read packet: bad length: {}",
            body.len()
        )));
    }

    Ok(Packet {
        id,
        data: body.to_vec(),
    })
}

pub fn read_frame<R: Read>(reader: &mut R, max_length: usize) -> io::Result<(Vec<u8>, usize)> {
    let (frame_length, prefix_length) = read_varint_with_length(reader)?;
    if frame_length < 1 || frame_length as usize > max_length {
        return Err(invalid_data(format!(
            "read packet: bad length: {frame_length}"
        )));
    }

    let mut frame = vec![0; frame_length as usize];
    reader.read_exact(&mut frame)?;
    let wire_length = prefix_length + frame.len();
    Ok((frame, wire_length))
}

pub fn read_varint<R: Read>(reader: &mut R) -> io::Result<Varint> {
    read_varint_with_length(reader).map(|(value, _)| value)
}

pub fn read_varint_with_length<R: Read>(reader: &mut R) -> io::Result<(Varint, usize)> {
    let mut value = 0i32;
    for index in 0..5 {
        let current = read_byte(reader)?;
        if index == 4 && current & 0xf0 != 0 {
            return Err(invalid_data("read varint: too large"));
        }
        value |= i32::from(current & SEGMENT_BITS) << (7 * index);
        if current & CONTINUE_BIT == 0 {
            let length = index + 1;
            if length > 1 && (value as u32) < (1u32 << (7 * (length - 1))) {
                return Err(invalid_data("read varint: non-canonical encoding"));
            }
            return Ok((value, length));
        }
    }
    Err(invalid_data("read varint: too large"))
}

pub fn write_varint<W: Write>(writer: &mut W, value: Varint) -> io::Result<()> {
    let mut remaining = value as u32;
    loop {
        let mut current = (remaining & u32::from(SEGMENT_BITS)) as u8;
        remaining >>= 7;
        if remaining != 0 {
            current |= CONTINUE_BIT;
        }
        writer.write_all(&[current])?;
        if remaining == 0 {
            return Ok(());
        }
    }
}

#[must_use]
pub fn varint_size(value: Varint) -> usize {
    let mut remaining = value as u32;
    let mut size = 0;
    for _ in 0..5 {
        size += 1;
        remaining >>= 7;
        if remaining == 0 {
            break;
        }
    }
    size
}

pub fn read_string<R: Read>(reader: &mut R) -> io::Result<String> {
    let length = read_varint(reader)?;
    if !(0..=MAX_STRING_LENGTH).contains(&length) {
        return Err(invalid_data(format!("read string: bad length: {length}")));
    }
    let mut buffer = vec![0; length as usize];
    reader.read_exact(&mut buffer)?;
    String::from_utf8(buffer).map_err(|_| invalid_data("read string: invalid utf-8"))
}

pub fn write_string<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    write_varint(
        writer,
        Varint::try_from(value.len()).map_err(|_| invalid_input("string exceeds a varint"))?,
    )?;
    writer.write_all(value.as_bytes())
}

pub fn read_unsigned_short<R: Read>(reader: &mut R) -> io::Result<UnsignedShort> {
    let mut buffer = [0; 2];
    reader.read_exact(&mut buffer)?;
    Ok(UnsignedShort::from_be_bytes(buffer))
}

pub fn write_unsigned_short<W: Write>(writer: &mut W, value: UnsignedShort) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

pub fn read_long<R: Read>(reader: &mut R) -> io::Result<Long> {
    let mut buffer = [0; 8];
    reader.read_exact(&mut buffer)?;
    Ok(Long::from_be_bytes(buffer))
}

pub fn write_long<W: Write>(writer: &mut W, value: Long) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

pub fn read_uuid<R: Read>(reader: &mut R) -> io::Result<[u8; 16]> {
    let mut uuid = [0; 16];
    reader.read_exact(&mut uuid)?;
    Ok(uuid)
}

pub fn write_uuid<W: Write>(writer: &mut W, uuid: &[u8; 16]) -> io::Result<()> {
    writer.write_all(uuid)
}

pub fn read_bytes<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let length = read_varint(reader)?;
    if !(0..MAX_BYTES_LENGTH).contains(&length) {
        return Err(invalid_data(format!("read bytes: invalid size: {length}")));
    }
    let mut buffer =
        vec![0; usize::try_from(length).map_err(|_| invalid_data("bytes length is negative"))?];
    reader.read_exact(&mut buffer)?;
    Ok(buffer)
}

pub fn write_bytes<W: Write>(writer: &mut W, value: &[u8]) -> io::Result<()> {
    write_varint(
        writer,
        Varint::try_from(value.len()).map_err(|_| invalid_input("string exceeds a varint"))?,
    )?;
    writer.write_all(value)
}

pub fn read_remaining<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

pub fn write_remaining<W: Write>(writer: &mut W, value: &[u8]) -> io::Result<()> {
    writer.write_all(value)
}

pub fn read_boolean<R: Read>(reader: &mut R) -> io::Result<bool> {
    let value = read_byte(reader)?;
    if value > 1 {
        return Err(invalid_data(format!(
            "read boolean: invalid value: {value}"
        )));
    }
    Ok(value == 1)
}

pub fn write_boolean<W: Write>(writer: &mut W, value: bool) -> io::Result<()> {
    writer.write_all(&[u8::from(value)])
}

pub fn read_byte<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut buffer = [0; 1];
    reader.read_exact(&mut buffer)?;
    Ok(buffer[0])
}

pub fn write_packet<W: Write>(writer: &mut W, id: i32, data: &[u8]) -> io::Result<()> {
    write_packet_with_length(writer, id, data).map(|_| ())
}

pub fn write_packet_with_length<W: Write>(
    writer: &mut W,
    id: i32,
    data: &[u8],
) -> io::Result<usize> {
    let frame = encode_packet(id, data)?;
    writer.write_all(&frame)?;
    Ok(frame.len())
}

pub fn encode_packet(id: i32, data: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() > MAX_PACKET_DATA_LENGTH {
        return Err(invalid_input(format!(
            "write packet: bad length: {}",
            data.len()
        )));
    }
    let body_length = varint_size(id) + data.len();
    if body_length > MAX_PACKET_BODY_LENGTH {
        return Err(invalid_input(format!(
            "write packet: bad length: {body_length}"
        )));
    }

    let body_varint = Varint::try_from(body_length)
        .map_err(|_| invalid_input("packet length exceeds a varint"))?;
    let mut frame = Vec::with_capacity(varint_size(body_varint) + body_length);
    write_varint(&mut frame, body_varint)?;
    write_varint(&mut frame, id)?;
    frame.extend_from_slice(data);
    Ok(frame)
}

pub fn write_disconnect_packet<W: Write>(writer: &mut W, reason: &str) -> io::Result<()> {
    let mut data = Vec::new();
    write_string(&mut data, reason)?;
    write_packet(writer, 0x00, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_truncated_packet_id_leaves_the_next_frame_untouched() {
        let wire = [0x01, 0x80, 0x01, 0x00];
        let mut reader: &[u8] = &wire;
        assert!(read_packet(&mut reader).is_err());
        let packet = read_packet(&mut reader).expect("the next frame still parses");
        assert_eq!(packet.id, 0);
        assert_eq!(packet.data.len(), 0);
    }

    #[test]
    fn packet_lengths_are_the_wire_lengths() {
        let mut wire = Vec::new();
        let written = write_packet_with_length(&mut wire, 0x03, &[]).expect("writes");
        assert_eq!(written, 2);
        assert_eq!(wire, [0x01, 0x03]);

        let mut reader: &[u8] = &wire;
        let (packet, read) = read_packet_with_length(&mut reader).expect("reads");
        assert_eq!(packet.id, 0x03);
        assert_eq!(read, written);
    }

    #[test]
    fn varints_reject_non_canonical_and_oversized_encodings() {
        let mut reader: &[u8] = &[0x81, 0x00, 0x03];
        let error = read_varint(&mut reader).expect_err("non-canonical");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut reader: &[u8] = &[0xff, 0xff, 0xff, 0xff, 0x1f];
        let error = read_varint(&mut reader).expect_err("too large");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn varints_round_trip_at_every_width_and_sign() {
        for value in [
            0_i32,
            1,
            127,
            128,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            268_435_455,
            268_435_456,
            i32::MAX,
            -1,
            i32::MIN,
        ] {
            let mut wire = Vec::new();
            write_varint(&mut wire, value).expect("writes");
            assert_eq!(wire.len(), varint_size(value));
            let mut reader: &[u8] = &wire;
            assert_eq!(read_varint(&mut reader).expect("reads"), value);
        }
    }

    #[test]
    fn a_frame_above_the_body_limit_is_rejected() {
        let mut reader: &[u8] = &[0xff, 0xff, 0x03];
        let error = read_frame(&mut reader, MAX_PACKET_BODY_LENGTH).expect_err("oversized");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_packet_body_with_a_data_overrun_is_rejected() {
        let mut body = vec![0u8];
        body.resize(1 + MAX_PACKET_DATA_LENGTH + 1, 0);
        let error = decode_packet_body(&body).expect_err("data too long");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_string_over_4096_bytes_is_rejected_before_the_read() {
        let mut wire = Vec::new();
        write_varint(&mut wire, 4097).expect("length");
        let mut reader: &[u8] = &wire;
        let error = read_string(&mut reader).expect_err("too long");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn strings_round_trip() {
        for value in ["", "xmc:data", "textures"] {
            let mut wire = Vec::new();
            write_string(&mut wire, value).expect("writes");
            let mut reader: &[u8] = &wire;
            assert_eq!(read_string(&mut reader).expect("reads"), value);
        }
    }

    #[test]
    fn a_byte_array_at_the_limit_is_rejected() {
        let mut wire = Vec::new();
        write_varint(&mut wire, MAX_BYTES_LENGTH).expect("length");
        let mut reader: &[u8] = &wire;
        let error = read_bytes(&mut reader).expect_err("too long");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn booleans_accept_only_zero_and_one() {
        let mut reader: &[u8] = &[2];
        let error = read_boolean(&mut reader).expect_err("invalid");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut wire = Vec::new();
        write_boolean(&mut wire, true).expect("writes");
        write_boolean(&mut wire, false).expect("writes");
        let mut reader: &[u8] = &wire;
        assert!(read_boolean(&mut reader).expect("true"));
        assert!(!read_boolean(&mut reader).expect("false"));
    }

    #[test]
    fn fixed_width_fields_are_big_endian() {
        let uuid = [0x11; 16];
        let mut wire = Vec::new();
        write_unsigned_short(&mut wire, 0x1234).expect("short");
        write_long(&mut wire, 0x0102_0304_0506_0708).expect("long");
        write_uuid(&mut wire, &uuid).expect("uuid");

        let mut reader: &[u8] = &wire;
        assert_eq!(read_unsigned_short(&mut reader).expect("short"), 0x1234);
        assert_eq!(read_long(&mut reader).expect("long"), 0x0102_0304_0506_0708);
        assert_eq!(read_uuid(&mut reader).expect("uuid"), uuid);
    }

    #[test]
    fn trailing_packet_data_round_trips() {
        let mut wire = Vec::new();
        write_remaining(&mut wire, b"payload").expect("writes");
        let mut reader: &[u8] = &wire;
        assert_eq!(read_remaining(&mut reader).expect("reads"), b"payload");
    }
}
