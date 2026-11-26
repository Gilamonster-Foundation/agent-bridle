use super::*;

fn request(payload: Vec<u8>) -> Frame {
    make_frame(payload, vec![7; 32], BTreeSet::new(), None, false).unwrap()
}

fn wire(frame: &Frame) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, frame).unwrap();
    bytes
}

#[test]
fn receiving_request_enforces_payload_bound() {
    for (size, accepted) in [(MAX_PAYLOAD, true), (MAX_PAYLOAD + 1, false)] {
        let bytes = wire(&request(vec![0; size]));
        assert_eq!(
            read_request(&mut bytes.as_slice(), &[7; 32]).is_ok(),
            accepted
        );
    }
}

#[test]
fn canonical_identity_and_response_link_round_trip() {
    let frame = request(b"request".to_vec());
    let bytes = wire(&frame);
    let received = read_request(&mut bytes.as_slice(), &[7; 32]).unwrap();
    assert_eq!(received.id, frame.id);
    assert_eq!(wire(&received), bytes);
    // Q5: retain today's response bound; do not impose the request payload cap.
    let reply = make_frame(
        vec![0; MAX_PAYLOAD + 1],
        vec![7; 32],
        [frame.id].into(),
        None,
        false,
    )
    .unwrap();
    let reply = read_frame(&mut wire(&reply).as_slice()).unwrap();
    verify_frame(&reply, &[7; 32], [frame.id].into()).unwrap();
    assert!(verify_frame(&reply, &[7; 32], BTreeSet::new()).is_err());
}

#[test]
fn wrong_identity_challenge_parents_version_and_request_roles_refuse() {
    for case in 0..7 {
        let mut frame = request(b"request".to_vec());
        match case {
            0 => frame.id = request(b"substitution".to_vec()).id,
            1 => frame.node.payload.challenge = vec![8; 32],
            2 => frame.node.parents = [request(Vec::new()).id].into(),
            3 => frame.node.payload.version = 2,
            4 => frame.node.payload.error = Some("untrusted-error".into()),
            5 => frame.node.payload.endpoint = true,
            _ => frame.node.payload.challenge.truncate(31),
        }
        if case != 0 {
            frame.id = frame.node.id().unwrap();
        }
        let challenge = vec![7; if case == 6 { 31 } else { 32 }];
        assert!(
            read_request(&mut wire(&frame).as_slice(), &challenge).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn malformed_noncanonical_and_oversized_frames_refuse_without_disclosure() {
    for value in [
        serde_json::json!("private-marker"),
        serde_json::json!({"private-marker": 1}),
    ] {
        let bytes = canonical::to_canonical_dagcbor(&value).unwrap();
        let mut data = (bytes.len() as u32).to_le_bytes().to_vec();
        data.extend(bytes);
        let error = read_frame(&mut data.as_slice()).err().unwrap().to_string();
        assert!(error.contains("invalid canonical broker frame"));
        assert!(!error.contains("private-marker"));
    }
    let mut bytes = wire(&request(Vec::new()));
    assert_eq!(bytes[4], 0xa2);
    bytes[4] = 0xb8; // Same map, non-minimal length encoding.
    bytes.insert(5, 2);
    let length = (bytes.len() - 4) as u32;
    bytes[..4].copy_from_slice(&length.to_le_bytes());
    assert!(read_frame(&mut bytes.as_slice()).is_err());
    for length in [0, MAX_FRAME as u32 + 1] {
        assert!(matches!(
            read_frame(&mut length.to_le_bytes().as_slice()),
            Err(ToolError::Denied { .. })
        ));
    }
    assert!(write_frame(&mut Vec::new(), &request(vec![0; MAX_FRAME])).is_err());
}

#[test]
fn complete_frame_survives_eof_but_truncation_refuses() {
    let bytes = wire(&request(b"payload".to_vec()));
    read_request(&mut bytes.as_slice(), &[7; 32]).unwrap();
    for length in [0, 3, bytes.len() - 1] {
        assert!(
            matches!(read_frame(&mut &bytes[..length]), Err(ToolError::Exec(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }
}

struct Disconnected(usize);
impl Read for Disconnected {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::NotConnected.into())
    }
}
impl Write for Disconnected {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0 == 0 {
            return Err(std::io::ErrorKind::NotConnected.into());
        }
        self.0 -= 1;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::NotConnected.into())
    }
}

#[test]
fn injected_io_failures_preserve_phase_kind_and_errno() {
    let mut errors = Vec::new();
    for (prefix, phase) in [
        (Vec::new(), "read frame length"),
        (4u32.to_le_bytes().to_vec(), "read frame body"),
    ] {
        let mut input = std::io::Cursor::new(prefix).chain(Disconnected(0));
        errors.push((read_frame(&mut input).err().unwrap(), phase));
    }
    for (writes, phase) in ["write frame length", "write frame body", "flush frame"]
        .into_iter()
        .enumerate()
    {
        errors.push((
            write_frame(&mut Disconnected(writes), &request(Vec::new())).unwrap_err(),
            phase,
        ));
    }
    for (error, phase) in errors {
        assert!(
            matches!(&error, ToolError::Exec(e) if e.kind() == std::io::ErrorKind::NotConnected)
        );
        assert!(error
            .to_string()
            .contains(&format!("broker RPC socket {phase}")));
    }
    let native = std::io::Error::from_raw_os_error(54);
    let kind = native.kind();
    let error = broker_io("read frame length", native);
    assert!(matches!(&error, ToolError::Exec(e) if e.kind() == kind));
    assert!(error.to_string().contains("raw_os_error=Some(54)"));
}
