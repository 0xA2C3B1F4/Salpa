//! Signed A/B update protocol carried by the CTAPHID vendor command `0x51`.
//!
//! The protocol borrows Solo2's public command assignment and host-facing
//! version, hash, progress, and fresh-user-presence model. Flash operations are
//! deliberately platform-specific and are implemented separately for ESP32-S2.

use sha2::{Digest, Sha256};

pub const VENDOR_COMMAND: u8 = 0x51;
pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_WRITE_CHUNK: usize = 992;
pub const ERASE_STEP_SIZE: u32 = 0x1_0000;
pub const VERIFY_STEP_SIZE: u32 = 0x1_0000;
pub const OTA_SLOT_SIZE: u32 = 0x1e_0000;
pub const SIGNATURE_SECTOR_SIZE: u32 = 0x1000;
pub const SIGNATURE_BLOCK_SIZE: usize = 1216;
pub const SIGNATURE_CRC_LENGTH: usize = 1196;
pub const RSA_PUBLIC_KEY_SIZE: usize = 776;
pub const RSA_SIGNATURE_SIZE: usize = 384;
pub const MAX_VERSION_LENGTH: usize = 31;

const ESP_IMAGE_MAGIC: u8 = 0xe9;
const ESP32S2_CHIP_ID: u16 = 2;
const ESP_APP_DESCRIPTOR_MAGIC: u32 = 0xabcd_5432;
const SECURE_BOOT_V2_SIGNATURE_MAGIC: u8 = 0xe7;
const SECURE_BOOT_V2_RSA_VERSION: u8 = 2;
const APP_DESCRIPTOR_OFFSET: u32 = 32;
const APP_DESCRIPTOR_PREFIX_SIZE: usize = 80;
const APP_SECURE_VERSION_OFFSET: usize = 4;
const APP_VERSION_OFFSET: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Operation {
    Info = 0,
    Begin = 1,
    Write = 2,
    Advance = 3,
    Status = 4,
    Abort = 5,
}

impl Operation {
    fn parse(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Info,
            1 => Self::Begin,
            2 => Self::Write,
            3 => Self::Advance,
            4 => Self::Status,
            5 => Self::Abort,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StatusCode {
    Ok = 0,
    UserPresenceRequired = 1,
    InvalidRequest = 2,
    InvalidState = 3,
    SessionMismatch = 4,
    OutOfOrder = 5,
    ImageSize = 6,
    Flash = 7,
    HashMismatch = 8,
    Signature = 9,
    Rollback = 10,
    VersionMismatch = 11,
    ActiveSlotChanged = 12,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Phase {
    Idle = 0,
    Erasing = 1,
    Receiving = 2,
    Verifying = 3,
    Activated = 4,
    Failed = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateLayout {
    pub active_slot: u8,
    pub active_sequence: u32,
    pub activation_entry: u8,
}

pub trait UpdateBackend {
    type Error;

    fn layout(&mut self) -> Result<UpdateLayout, Self::Error>;
    fn erase(&mut self, slot: u8, offset: u32, length: u32) -> Result<(), Self::Error>;
    fn write(&mut self, slot: u8, offset: u32, data: &[u8]) -> Result<(), Self::Error>;
    fn read(&mut self, slot: u8, offset: u32, output: &mut [u8]) -> Result<(), Self::Error>;
    fn verify_rsa_pss(
        &mut self,
        public_key: &[u8; RSA_PUBLIC_KEY_SIZE],
        signature: &[u8; RSA_SIGNATURE_SIZE],
        image_digest: &[u8; 32],
    ) -> Result<bool, Self::Error>;
    fn activate(
        &mut self,
        slot: u8,
        sequence: u32,
        activation_entry: u8,
    ) -> Result<(), Self::Error>;
}

struct Session {
    id: u32,
    phase: Phase,
    target_slot: u8,
    active_slot: u8,
    active_sequence: u32,
    activation_entry: u8,
    target_sequence: u32,
    total: u32,
    expected_hash: [u8; 32],
    expected_secure_version: u32,
    expected_version: [u8; MAX_VERSION_LENGTH],
    expected_version_length: usize,
    completed: u32,
    full_hasher: Sha256,
    signed_hasher: Sha256,
    failure: StatusCode,
}

impl Session {
    fn expected_version(&self) -> &[u8] {
        &self.expected_version[..self.expected_version_length]
    }
}

pub struct UsbUpdater<B> {
    backend: B,
    trusted_key_digest: [u8; 32],
    current_version: [u8; MAX_VERSION_LENGTH],
    current_version_length: usize,
    current_secure_version: u32,
    next_session_id: u32,
    session: Option<Session>,
}

impl<B: UpdateBackend> UsbUpdater<B> {
    pub fn new(
        backend: B,
        trusted_key_digest: [u8; 32],
        current_version: &str,
        current_secure_version: u32,
    ) -> Self {
        assert!(!current_version.is_empty());
        assert!(current_version.len() <= MAX_VERSION_LENGTH);
        let mut version = [0; MAX_VERSION_LENGTH];
        version[..current_version.len()].copy_from_slice(current_version.as_bytes());
        Self {
            backend,
            trusted_key_digest,
            current_version: version,
            current_version_length: current_version.len(),
            current_secure_version,
            next_session_id: 1,
            session: None,
        }
    }

    pub fn handle(&mut self, request: &[u8], user_present: bool, response: &mut [u8]) -> usize {
        let status = self.handle_inner(request, user_present);
        self.encode_response(status, response)
    }

    pub fn phase(&self) -> Phase {
        self.session
            .as_ref()
            .map_or(Phase::Idle, |session| session.phase)
    }

    fn handle_inner(&mut self, request: &[u8], user_present: bool) -> StatusCode {
        let Some(operation) = request.first().and_then(|value| Operation::parse(*value)) else {
            return StatusCode::InvalidRequest;
        };
        match operation {
            Operation::Info => {
                if request.len() == 1 {
                    StatusCode::Ok
                } else {
                    StatusCode::InvalidRequest
                }
            }
            Operation::Begin => self.begin(&request[1..], user_present),
            Operation::Write => self.write(&request[1..]),
            Operation::Advance => self.advance(&request[1..]),
            Operation::Status => self.status(&request[1..]),
            Operation::Abort => self.abort(&request[1..]),
        }
    }

    fn begin(&mut self, request: &[u8], user_present: bool) -> StatusCode {
        const FIXED: usize = 1 + 4 + 32 + 4 + 1;
        if request.len() < FIXED || request[0] != PROTOCOL_VERSION {
            return StatusCode::InvalidRequest;
        }
        let total = u32::from_le_bytes(request[1..5].try_into().unwrap());
        let version_length = request[41] as usize;
        if request.len() != FIXED + version_length
            || version_length == 0
            || version_length > MAX_VERSION_LENGTH
        {
            return StatusCode::InvalidRequest;
        }
        if !(SIGNATURE_SECTOR_SIZE * 2..=OTA_SLOT_SIZE).contains(&total)
            || !total.is_multiple_of(SIGNATURE_SECTOR_SIZE)
        {
            return StatusCode::ImageSize;
        }
        let mut expected_hash = [0; 32];
        expected_hash.copy_from_slice(&request[5..37]);
        let expected_secure_version = u32::from_le_bytes(request[37..41].try_into().unwrap());
        if expected_secure_version < self.current_secure_version {
            return StatusCode::Rollback;
        }
        if !user_present {
            return StatusCode::UserPresenceRequired;
        }
        let Ok(layout) = self.backend.layout() else {
            return StatusCode::Flash;
        };
        if layout.active_slot > 1 || layout.activation_entry > 1 {
            return StatusCode::InvalidState;
        }
        let target_slot = 1 - layout.active_slot;
        let Some(target_sequence) = next_sequence(layout.active_sequence, target_slot) else {
            return StatusCode::InvalidState;
        };
        let mut expected_version = [0; MAX_VERSION_LENGTH];
        expected_version[..version_length].copy_from_slice(&request[42..]);

        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        self.session = Some(Session {
            id,
            phase: Phase::Erasing,
            target_slot,
            active_slot: layout.active_slot,
            active_sequence: layout.active_sequence,
            activation_entry: layout.activation_entry,
            target_sequence,
            total,
            expected_hash,
            expected_secure_version,
            expected_version,
            expected_version_length: version_length,
            completed: 0,
            full_hasher: Sha256::new(),
            signed_hasher: Sha256::new(),
            failure: StatusCode::Ok,
        });
        StatusCode::Ok
    }

    fn write(&mut self, request: &[u8]) -> StatusCode {
        if request.len() < 9 || request.len() > 9 + MAX_WRITE_CHUNK {
            return StatusCode::InvalidRequest;
        }
        let id = u32::from_le_bytes(request[..4].try_into().unwrap());
        let offset = u32::from_le_bytes(request[4..8].try_into().unwrap());
        let data = &request[8..];
        let Some(session) = self.session.as_mut() else {
            return StatusCode::InvalidState;
        };
        if session.id != id {
            return StatusCode::SessionMismatch;
        }
        if session.phase != Phase::Receiving {
            return StatusCode::InvalidState;
        }
        if data.is_empty() || !data.len().is_multiple_of(32) {
            return StatusCode::InvalidRequest;
        }
        if offset != session.completed {
            return StatusCode::OutOfOrder;
        }
        let Some(end) = offset.checked_add(data.len() as u32) else {
            return StatusCode::ImageSize;
        };
        if end > session.total {
            return StatusCode::ImageSize;
        }
        if self
            .backend
            .write(session.target_slot, offset, data)
            .is_err()
        {
            session.phase = Phase::Failed;
            session.failure = StatusCode::Flash;
            return StatusCode::Flash;
        }
        session.completed = end;
        StatusCode::Ok
    }

    fn advance(&mut self, request: &[u8]) -> StatusCode {
        let Some(id) = parse_session_id(request) else {
            return StatusCode::InvalidRequest;
        };
        let Some(session) = self.session.as_mut() else {
            return StatusCode::InvalidState;
        };
        if session.id != id {
            return StatusCode::SessionMismatch;
        }
        match session.phase {
            Phase::Erasing => {
                let length = (session.total - session.completed).min(ERASE_STEP_SIZE);
                if self
                    .backend
                    .erase(session.target_slot, session.completed, length)
                    .is_err()
                {
                    session.phase = Phase::Failed;
                    session.failure = StatusCode::Flash;
                    return StatusCode::Flash;
                }
                session.completed += length;
                if session.completed == session.total {
                    session.completed = 0;
                    session.phase = Phase::Receiving;
                }
                StatusCode::Ok
            }
            Phase::Receiving => {
                if session.completed != session.total {
                    return StatusCode::InvalidState;
                }
                session.phase = Phase::Verifying;
                session.completed = 0;
                session.full_hasher = Sha256::new();
                session.signed_hasher = Sha256::new();
                self.verify_step()
            }
            Phase::Verifying => self.verify_step(),
            Phase::Activated => StatusCode::Ok,
            Phase::Failed => session.failure,
            Phase::Idle => StatusCode::InvalidState,
        }
    }

    fn verify_step(&mut self) -> StatusCode {
        let Some(session) = self.session.as_mut() else {
            return StatusCode::InvalidState;
        };
        let step_end = (session.completed + VERIFY_STEP_SIZE).min(session.total);
        let signed_length = session.total - SIGNATURE_SECTOR_SIZE;
        let mut buffer = [0_u8; 1024];
        while session.completed < step_end {
            let length = (step_end - session.completed).min(buffer.len() as u32) as usize;
            let chunk = &mut buffer[..length];
            if self
                .backend
                .read(session.target_slot, session.completed, chunk)
                .is_err()
            {
                session.phase = Phase::Failed;
                session.failure = StatusCode::Flash;
                return StatusCode::Flash;
            }
            session.full_hasher.update(&*chunk);
            if session.completed < signed_length {
                let signed_count = (signed_length - session.completed).min(length as u32) as usize;
                session.signed_hasher.update(&chunk[..signed_count]);
            }
            session.completed += length as u32;
        }
        buffer.fill(0);
        if session.completed != session.total {
            return StatusCode::Ok;
        }
        self.finish_verification()
    }

    #[allow(
        clippy::large_stack_frames,
        reason = "the fixed signature block is public update metadata and avoids heap allocation"
    )]
    fn finish_verification(&mut self) -> StatusCode {
        let Some(session) = self.session.as_mut() else {
            return StatusCode::InvalidState;
        };
        let full_digest: [u8; 32] = session.full_hasher.clone().finalize().into();
        if full_digest != session.expected_hash {
            return fail(session, StatusCode::HashMismatch);
        }

        let mut descriptor = [0_u8; APP_DESCRIPTOR_PREFIX_SIZE];
        if self
            .backend
            .read(session.target_slot, 0, &mut descriptor)
            .is_err()
        {
            return fail(session, StatusCode::Flash);
        }
        let Some(metadata) = parse_image_metadata(&descriptor) else {
            return fail(session, StatusCode::Signature);
        };
        if metadata.secure_version != session.expected_secure_version
            || metadata.version != session.expected_version()
        {
            return fail(session, StatusCode::VersionMismatch);
        }
        if metadata.secure_version < self.current_secure_version {
            return fail(session, StatusCode::Rollback);
        }

        let signed_digest: [u8; 32] = session.signed_hasher.clone().finalize().into();
        let mut block = [0_u8; SIGNATURE_BLOCK_SIZE];
        if self
            .backend
            .read(
                session.target_slot,
                session.total - SIGNATURE_SECTOR_SIZE,
                &mut block,
            )
            .is_err()
        {
            return fail(session, StatusCode::Flash);
        }
        let Some(signature) = parse_signature_block(&block, &self.trusted_key_digest) else {
            return fail(session, StatusCode::Signature);
        };
        if *signature.image_digest != signed_digest {
            return fail(session, StatusCode::Signature);
        }
        match self
            .backend
            .verify_rsa_pss(signature.public_key, signature.signature, &signed_digest)
        {
            Ok(true) => {}
            Ok(false) => return fail(session, StatusCode::Signature),
            Err(_) => return fail(session, StatusCode::Flash),
        }

        let Ok(layout) = self.backend.layout() else {
            return fail(session, StatusCode::Flash);
        };
        if layout.active_slot != session.active_slot
            || layout.active_sequence != session.active_sequence
            || layout.activation_entry != session.activation_entry
        {
            return fail(session, StatusCode::ActiveSlotChanged);
        }
        if self
            .backend
            .activate(
                session.target_slot,
                session.target_sequence,
                session.activation_entry,
            )
            .is_err()
        {
            return fail(session, StatusCode::Flash);
        }
        session.phase = Phase::Activated;
        session.failure = StatusCode::Ok;
        StatusCode::Ok
    }

    fn status(&self, request: &[u8]) -> StatusCode {
        if request.is_empty() {
            return StatusCode::Ok;
        }
        let Some(id) = parse_session_id(request) else {
            return StatusCode::InvalidRequest;
        };
        match &self.session {
            Some(session) if session.id == id => {
                if session.phase == Phase::Failed {
                    session.failure
                } else {
                    StatusCode::Ok
                }
            }
            Some(_) => StatusCode::SessionMismatch,
            None => StatusCode::InvalidState,
        }
    }

    fn abort(&mut self, request: &[u8]) -> StatusCode {
        let Some(id) = parse_session_id(request) else {
            return StatusCode::InvalidRequest;
        };
        match &self.session {
            Some(session) if session.id == id && session.phase != Phase::Activated => {
                self.session = None;
                StatusCode::Ok
            }
            Some(session) if session.id != id => StatusCode::SessionMismatch,
            _ => StatusCode::InvalidState,
        }
    }

    fn encode_response(&self, status: StatusCode, output: &mut [u8]) -> usize {
        const FIXED: usize = 21;
        assert!(output.len() >= FIXED + self.current_version_length);
        let (phase, slot, id, completed, total) = match &self.session {
            Some(session) => (
                session.phase,
                session.target_slot,
                session.id,
                session.completed,
                session.total,
            ),
            None => (Phase::Idle, u8::MAX, 0, 0, 0),
        };
        output[..FIXED + self.current_version_length].fill(0);
        output[0] = status as u8;
        output[1] = PROTOCOL_VERSION;
        output[2] = phase as u8;
        output[3] = slot;
        output[4..8].copy_from_slice(&id.to_le_bytes());
        output[8..12].copy_from_slice(&completed.to_le_bytes());
        output[12..16].copy_from_slice(&total.to_le_bytes());
        output[16..20].copy_from_slice(&self.current_secure_version.to_le_bytes());
        output[20] = self.current_version_length as u8;
        output[21..21 + self.current_version_length]
            .copy_from_slice(&self.current_version[..self.current_version_length]);
        FIXED + self.current_version_length
    }
}

fn fail(session: &mut Session, status: StatusCode) -> StatusCode {
    session.phase = Phase::Failed;
    session.failure = status;
    status
}

fn parse_session_id(request: &[u8]) -> Option<u32> {
    (request.len() == 4).then(|| u32::from_le_bytes(request.try_into().unwrap()))
}

fn next_sequence(current: u32, target_slot: u8) -> Option<u32> {
    if current == 0 || target_slot > 1 {
        return None;
    }
    let parity = u32::from(target_slot) + 1;
    let increment = if current % 2 == parity % 2 { 2 } else { 1 };
    current.checked_add(increment)
}

struct ImageMetadata<'a> {
    secure_version: u32,
    version: &'a [u8],
}

fn parse_image_metadata(
    image_prefix: &[u8; APP_DESCRIPTOR_PREFIX_SIZE],
) -> Option<ImageMetadata<'_>> {
    if image_prefix[0] != ESP_IMAGE_MAGIC
        || !(1..=16).contains(&image_prefix[1])
        || u16::from_le_bytes(image_prefix[12..14].try_into().ok()?) != ESP32S2_CHIP_ID
        || u32::from_le_bytes(
            image_prefix[APP_DESCRIPTOR_OFFSET as usize..APP_DESCRIPTOR_OFFSET as usize + 4]
                .try_into()
                .ok()?,
        ) != ESP_APP_DESCRIPTOR_MAGIC
    {
        return None;
    }
    let descriptor = &image_prefix[APP_DESCRIPTOR_OFFSET as usize..];
    let secure_version = u32::from_le_bytes(
        descriptor[APP_SECURE_VERSION_OFFSET..APP_SECURE_VERSION_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    let version_field = &descriptor[APP_VERSION_OFFSET..APP_VERSION_OFFSET + 32];
    let version_length = version_field.iter().position(|byte| *byte == 0)?;
    if version_length == 0 || version_length > MAX_VERSION_LENGTH {
        return None;
    }
    Some(ImageMetadata {
        secure_version,
        version: &version_field[..version_length],
    })
}

struct ParsedSignature<'a> {
    image_digest: &'a [u8; 32],
    public_key: &'a [u8; RSA_PUBLIC_KEY_SIZE],
    signature: &'a [u8; RSA_SIGNATURE_SIZE],
}

fn parse_signature_block<'a>(
    block: &'a [u8; SIGNATURE_BLOCK_SIZE],
    trusted_key_digest: &[u8; 32],
) -> Option<ParsedSignature<'a>> {
    if block[0] != SECURE_BOOT_V2_SIGNATURE_MAGIC
        || block[1] != SECURE_BOOT_V2_RSA_VERSION
        || u32::from_le_bytes(block[1196..1200].try_into().ok()?)
            != esp_crc32_le(0, &block[..SIGNATURE_CRC_LENGTH])
    {
        return None;
    }
    let image_digest = block[4..36].try_into().ok()?;
    let public_key = block[36..812].try_into().ok()?;
    let key_digest: [u8; 32] = Sha256::digest(public_key).into();
    if key_digest != *trusted_key_digest {
        return None;
    }
    let signature = block[812..1196].try_into().ok()?;
    Some(ParsedSignature {
        image_digest,
        public_key,
        signature,
    })
}

fn esp_crc32_le(seed: u32, data: &[u8]) -> u32 {
    let mut crc = !seed;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use self::std::{vec, vec::Vec};

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Mutation {
        Erase(u8, u32, u32),
        Write(u8, u32, usize),
        Activate(u8, u32, u8),
    }

    struct FakeBackend {
        slots: [Vec<u8>; 2],
        layout: UpdateLayout,
        mutations: Vec<Mutation>,
        rsa_valid: bool,
    }

    impl FakeBackend {
        fn new() -> Self {
            Self {
                slots: [
                    vec![0x11; OTA_SLOT_SIZE as usize],
                    vec![0x22; OTA_SLOT_SIZE as usize],
                ],
                layout: UpdateLayout {
                    active_slot: 0,
                    active_sequence: 1,
                    activation_entry: 1,
                },
                mutations: Vec::new(),
                rsa_valid: true,
            }
        }
    }

    impl UpdateBackend for FakeBackend {
        type Error = ();

        fn layout(&mut self) -> Result<UpdateLayout, Self::Error> {
            Ok(self.layout)
        }

        fn erase(&mut self, slot: u8, offset: u32, length: u32) -> Result<(), Self::Error> {
            self.slots[slot as usize][offset as usize..(offset + length) as usize].fill(0xff);
            self.mutations.push(Mutation::Erase(slot, offset, length));
            Ok(())
        }

        fn write(&mut self, slot: u8, offset: u32, data: &[u8]) -> Result<(), Self::Error> {
            self.slots[slot as usize][offset as usize..offset as usize + data.len()]
                .copy_from_slice(data);
            self.mutations
                .push(Mutation::Write(slot, offset, data.len()));
            Ok(())
        }

        fn read(&mut self, slot: u8, offset: u32, output: &mut [u8]) -> Result<(), Self::Error> {
            output.copy_from_slice(
                &self.slots[slot as usize][offset as usize..offset as usize + output.len()],
            );
            Ok(())
        }

        fn verify_rsa_pss(
            &mut self,
            _public_key: &[u8; RSA_PUBLIC_KEY_SIZE],
            _signature: &[u8; RSA_SIGNATURE_SIZE],
            _image_digest: &[u8; 32],
        ) -> Result<bool, Self::Error> {
            Ok(self.rsa_valid)
        }

        fn activate(
            &mut self,
            slot: u8,
            sequence: u32,
            activation_entry: u8,
        ) -> Result<(), Self::Error> {
            self.mutations
                .push(Mutation::Activate(slot, sequence, activation_entry));
            self.layout = UpdateLayout {
                active_slot: slot,
                active_sequence: sequence,
                activation_entry: 1 - activation_entry,
            };
            Ok(())
        }
    }

    fn signed_image(secure_version: u32, version: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let mut image = vec![0xff; (SIGNATURE_SECTOR_SIZE * 2) as usize];
        image[0] = ESP_IMAGE_MAGIC;
        image[1] = 1;
        image[12..14].copy_from_slice(&ESP32S2_CHIP_ID.to_le_bytes());
        image[23] = 1;
        image[32..36].copy_from_slice(&ESP_APP_DESCRIPTOR_MAGIC.to_le_bytes());
        image[36..40].copy_from_slice(&secure_version.to_le_bytes());
        image[48..48 + version.len()].copy_from_slice(version);
        image[48 + version.len()] = 0;

        let signed_digest: [u8; 32] = Sha256::digest(&image[..4096]).into();
        let block = &mut image[4096..4096 + SIGNATURE_BLOCK_SIZE];
        block[0] = SECURE_BOOT_V2_SIGNATURE_MAGIC;
        block[1] = SECURE_BOOT_V2_RSA_VERSION;
        block[4..36].copy_from_slice(&signed_digest);
        for (index, byte) in block[36..812].iter_mut().enumerate() {
            *byte = index as u8;
        }
        block[812..1196].fill(0x5a);
        let crc = esp_crc32_le(0, &block[..SIGNATURE_CRC_LENGTH]);
        block[1196..1200].copy_from_slice(&crc.to_le_bytes());
        let trusted_digest = Sha256::digest(&block[36..812]).into();
        (image, trusted_digest)
    }

    fn begin_request(image: &[u8], secure_version: u32, version: &[u8]) -> Vec<u8> {
        let mut request = vec![Operation::Begin as u8, PROTOCOL_VERSION];
        request.extend_from_slice(&(image.len() as u32).to_le_bytes());
        request.extend_from_slice(&Sha256::digest(image));
        request.extend_from_slice(&secure_version.to_le_bytes());
        request.push(version.len() as u8);
        request.extend_from_slice(version);
        request
    }

    fn response(updater: &mut UsbUpdater<FakeBackend>, request: &[u8], present: bool) -> Vec<u8> {
        let mut output = [0; 64];
        let length = updater.handle(request, present, &mut output);
        output[..length].to_vec()
    }

    fn session_id(reply: &[u8]) -> u32 {
        u32::from_le_bytes(reply[4..8].try_into().unwrap())
    }

    fn erase_all(updater: &mut UsbUpdater<FakeBackend>, id: u32) {
        while updater.phase() == Phase::Erasing {
            assert_eq!(
                response(
                    updater,
                    &[
                        Operation::Advance as u8,
                        id as u8,
                        (id >> 8) as u8,
                        (id >> 16) as u8,
                        (id >> 24) as u8
                    ],
                    false,
                )[0],
                StatusCode::Ok as u8
            );
        }
    }

    fn write_all(updater: &mut UsbUpdater<FakeBackend>, id: u32, image: &[u8]) {
        let mut offset = 0;
        while offset < image.len() {
            let count = (image.len() - offset).min(MAX_WRITE_CHUNK);
            let mut request = vec![Operation::Write as u8];
            request.extend_from_slice(&id.to_le_bytes());
            request.extend_from_slice(&(offset as u32).to_le_bytes());
            request.extend_from_slice(&image[offset..offset + count]);
            assert_eq!(response(updater, &request, false)[0], StatusCode::Ok as u8);
            offset += count;
        }
    }

    fn verify_all(updater: &mut UsbUpdater<FakeBackend>, id: u32) -> u8 {
        let mut status = StatusCode::Ok as u8;
        while matches!(updater.phase(), Phase::Receiving | Phase::Verifying) {
            let mut request = vec![Operation::Advance as u8];
            request.extend_from_slice(&id.to_le_bytes());
            status = response(updater, &request, false)[0];
            if status != StatusCode::Ok as u8 {
                break;
            }
        }
        status
    }

    #[test]
    fn successful_update_mutates_only_inactive_slot_and_activates_last() {
        let (image, trust) = signed_image(1, b"1.2.3");
        let backend = FakeBackend::new();
        let active_before = backend.slots[0].clone();
        let mut updater = UsbUpdater::new(backend, trust, "1.0.0", 1);
        let reply = response(&mut updater, &begin_request(&image, 1, b"1.2.3"), true);
        let id = session_id(&reply);
        erase_all(&mut updater, id);
        write_all(&mut updater, id, &image);
        assert_eq!(verify_all(&mut updater, id), StatusCode::Ok as u8);
        assert_eq!(updater.phase(), Phase::Activated);
        assert_eq!(updater.backend.slots[0], active_before);
        assert_eq!(&updater.backend.slots[1][..image.len()], image);
        assert_eq!(
            updater.backend.mutations.last(),
            Some(&Mutation::Activate(1, 2, 1))
        );
    }

    #[test]
    fn fresh_user_presence_is_required_before_any_erase() {
        let (image, trust) = signed_image(1, b"1.2.3");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "1.0.0", 1);
        let reply = response(&mut updater, &begin_request(&image, 1, b"1.2.3"), false);
        assert_eq!(reply[0], StatusCode::UserPresenceRequired as u8);
        assert_eq!(updater.phase(), Phase::Idle);
        assert!(updater.backend.mutations.is_empty());
    }

    #[test]
    fn malformed_begin_is_rejected_without_requesting_presence() {
        let (_, trust) = signed_image(1, b"1.2.3");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "1.0.0", 1);
        let reply = response(
            &mut updater,
            &[Operation::Begin as u8, PROTOCOL_VERSION, 0],
            false,
        );
        assert_eq!(reply[0], StatusCode::InvalidRequest as u8);
        assert!(updater.backend.mutations.is_empty());
    }

    #[test]
    fn out_of_order_chunk_is_rejected_without_advancing() {
        let (image, trust) = signed_image(1, b"1.2.3");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "1.0.0", 1);
        let id = session_id(&response(
            &mut updater,
            &begin_request(&image, 1, b"1.2.3"),
            true,
        ));
        erase_all(&mut updater, id);
        let mut request = vec![Operation::Write as u8];
        request.extend_from_slice(&id.to_le_bytes());
        request.extend_from_slice(&32_u32.to_le_bytes());
        request.extend_from_slice(&image[..32]);
        let reply = response(&mut updater, &request, false);
        assert_eq!(reply[0], StatusCode::OutOfOrder as u8);
        assert_eq!(u32::from_le_bytes(reply[8..12].try_into().unwrap()), 0);
    }

    #[test]
    fn readback_hash_mismatch_never_activates() {
        let (image, trust) = signed_image(1, b"1.2.3");
        let mut request = begin_request(&image, 1, b"1.2.3");
        request[6] ^= 1;
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "1.0.0", 1);
        let id = session_id(&response(&mut updater, &request, true));
        erase_all(&mut updater, id);
        write_all(&mut updater, id, &image);
        assert_eq!(verify_all(&mut updater, id), StatusCode::HashMismatch as u8);
        assert_eq!(updater.phase(), Phase::Failed);
        assert!(
            !updater
                .backend
                .mutations
                .iter()
                .any(|event| matches!(event, Mutation::Activate(..)))
        );
    }

    #[test]
    fn invalid_signature_never_activates() {
        let (image, trust) = signed_image(1, b"1.2.3");
        let mut backend = FakeBackend::new();
        backend.rsa_valid = false;
        let mut updater = UsbUpdater::new(backend, trust, "1.0.0", 1);
        let id = session_id(&response(
            &mut updater,
            &begin_request(&image, 1, b"1.2.3"),
            true,
        ));
        erase_all(&mut updater, id);
        write_all(&mut updater, id, &image);
        assert_eq!(verify_all(&mut updater, id), StatusCode::Signature as u8);
        assert_eq!(updater.backend.layout.active_slot, 0);
    }

    #[test]
    fn image_signed_by_another_key_never_activates() {
        let (image, mut trust) = signed_image(1, b"1.2.3");
        trust[0] ^= 1;
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "1.0.0", 1);
        let id = session_id(&response(
            &mut updater,
            &begin_request(&image, 1, b"1.2.3"),
            true,
        ));
        erase_all(&mut updater, id);
        write_all(&mut updater, id, &image);
        assert_eq!(verify_all(&mut updater, id), StatusCode::Signature as u8);
        assert_eq!(updater.backend.layout.active_slot, 0);
    }

    #[test]
    fn power_cut_drops_session_and_leaves_active_slot_selected() {
        let (image, trust) = signed_image(1, b"1.2.3");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "1.0.0", 1);
        let id = session_id(&response(
            &mut updater,
            &begin_request(&image, 1, b"1.2.3"),
            true,
        ));
        erase_all(&mut updater, id);
        let mut request = vec![Operation::Write as u8];
        request.extend_from_slice(&id.to_le_bytes());
        request.extend_from_slice(&0_u32.to_le_bytes());
        request.extend_from_slice(&image[..MAX_WRITE_CHUNK]);
        assert_eq!(
            response(&mut updater, &request, false)[0],
            StatusCode::Ok as u8
        );

        let backend = updater.backend;
        assert_eq!(backend.layout.active_slot, 0);
        let mut after_reboot = UsbUpdater::new(backend, trust, "1.0.0", 1);
        assert_eq!(after_reboot.phase(), Phase::Idle);
        assert_eq!(
            response(&mut after_reboot, &[Operation::Info as u8], false)[2],
            Phase::Idle as u8
        );
        assert_eq!(after_reboot.backend.layout.active_slot, 0);
    }

    #[test]
    fn lower_secure_version_is_rejected_before_erase() {
        let (image, trust) = signed_image(0, b"0.9.0");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "1.0.0", 1);
        let reply = response(&mut updater, &begin_request(&image, 0, b"0.9.0"), true);
        assert_eq!(reply[0], StatusCode::Rollback as u8);
        assert!(updater.backend.mutations.is_empty());
    }

    #[test]
    fn crc_matches_standard_esp_rom_seed_contract() {
        assert_eq!(esp_crc32_le(0, b"123456789"), 0xcbf4_3926);
    }
}
