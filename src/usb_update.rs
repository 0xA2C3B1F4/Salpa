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
/// No successful erase, write or verification progress for two minutes.
pub const SESSION_IDLE_TIMEOUT_MS: u64 = 120_000;
/// A single physical approval never authorizes more than fifteen minutes.
pub const SESSION_MAX_LIFETIME_MS: u64 = 900_000;

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
    SessionExpired = 13,
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

    /// Trusted device time, independent of host traffic. A backwards clock
    /// expires live authority. Tests supply an explicitly controlled clock.
    fn now_ms(&self) -> u64;
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
    started_ms: u64,
    last_progress_ms: u64,
    last_checked_ms: u64,
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
    fn expire(&mut self, now_ms: u64) -> bool {
        if !matches!(
            self.phase,
            Phase::Erasing | Phase::Receiving | Phase::Verifying
        ) {
            return self.failure == StatusCode::SessionExpired;
        }
        let expired = now_ms < self.last_checked_ms
            || now_ms.saturating_sub(self.started_ms) >= SESSION_MAX_LIFETIME_MS
            || now_ms.saturating_sub(self.last_progress_ms) >= SESSION_IDLE_TIMEOUT_MS;
        self.last_checked_ms = now_ms;
        if expired {
            fail(self, StatusCode::SessionExpired);
        }
        expired
    }

    fn progress(&mut self, now_ms: u64) -> StatusCode {
        if self.expire(now_ms) {
            return StatusCode::SessionExpired;
        }
        self.last_progress_ms = now_ms;
        StatusCode::Ok
    }

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
        self.poll();
        let status = self.handle_inner(request, user_present);
        self.encode_response(status, response)
    }

    /// Revoke uncommitted authority even when the host sends no update requests.
    /// A flash primitive already in progress is allowed to finish safely.
    pub fn poll(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.expire(self.backend.now_ms());
        }
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
        let started_ms = self.backend.now_ms();
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
            started_ms,
            last_progress_ms: started_ms,
            last_checked_ms: started_ms,
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
        self.session
            .as_mut()
            .unwrap()
            .progress(self.backend.now_ms())
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
        if session.expire(self.backend.now_ms()) {
            return StatusCode::SessionExpired;
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
        session.progress(self.backend.now_ms())
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
        if session.expire(self.backend.now_ms()) {
            return StatusCode::SessionExpired;
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
                session.progress(self.backend.now_ms())
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
            if session.expire(self.backend.now_ms()) {
                return StatusCode::SessionExpired;
            }
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
        if session.expire(self.backend.now_ms()) {
            return StatusCode::SessionExpired;
        }
        if session.completed != session.total {
            return session.progress(self.backend.now_ms());
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
        // Enforce the running firmware's floor directly on the read-back
        // descriptor before comparing it with the untrusted BEGIN claim.
        // Activation still requires the signature over this descriptor below.
        if metadata.secure_version < self.current_secure_version {
            return fail(session, StatusCode::Rollback);
        }
        if metadata.secure_version != session.expected_secure_version
            || metadata.version != session.expected_version()
        {
            return fail(session, StatusCode::VersionMismatch);
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
        // RSA verification and layout reads can take time. Recheck immediately
        // before the persistent activation operation, not just at request entry.
        if session.expire(self.backend.now_ms()) {
            return StatusCode::SessionExpired;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledImageError {
    Slot,
    Read,
    Header,
    Extent,
    Signature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedInstalledImage {
    pub secure_version: u32,
    pub signed_image_bytes: u32,
    pub signed_content_digest: [u8; 32],
}

/// Verify an installed slot without erasing, writing or selecting it.
/// The bounded ESP image layout determines the signature location; a caller
/// cannot supply a shorter length that omits part of the installed image.
/// This authenticates its contents, but does not prove that they boot. Before
/// raising an epoch, bind the returned digest to independent boot evidence.
pub fn verify_installed_slot<B: UpdateBackend>(
    backend: &mut B,
    slot: u8,
    trusted_key_digest: &[u8; 32],
) -> Result<VerifiedInstalledImage, InstalledImageError> {
    if slot > 1 {
        return Err(InstalledImageError::Slot);
    }
    let mut prefix = [0; APP_DESCRIPTOR_PREFIX_SIZE];
    backend
        .read(slot, 0, &mut prefix)
        .map_err(|_| InstalledImageError::Read)?;
    let metadata = parse_image_metadata(&prefix).ok_or(InstalledImageError::Header)?;
    if prefix[23] != 1 || metadata.secure_version > 16 {
        return Err(InstalledImageError::Header);
    }
    let mut position = 24_u32;
    for segment in 0..prefix[1] {
        let mut header = [0; 8];
        backend
            .read(slot, position, &mut header)
            .map_err(|_| InstalledImageError::Read)?;
        let length = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if segment == 0 && length < APP_DESCRIPTOR_PREFIX_SIZE as u32 - APP_DESCRIPTOR_OFFSET {
            return Err(InstalledImageError::Header);
        }
        position = position
            .checked_add(8)
            .and_then(|value| value.checked_add(length))
            .filter(|value| *value <= OTA_SLOT_SIZE - SIGNATURE_SECTOR_SIZE - 48)
            .ok_or(InstalledImageError::Extent)?;
    }
    // ESP images put the checksum at the next 16-byte boundary's last byte,
    // followed by their appended SHA-256. Secure Boot V2 then pads to 4 KiB.
    let trailer_end = (position | 15)
        .checked_add(33)
        .ok_or(InstalledImageError::Extent)?;
    let signature_offset = trailer_end
        .checked_add(SIGNATURE_SECTOR_SIZE - 1)
        .map(|value| value & !(SIGNATURE_SECTOR_SIZE - 1))
        .filter(|value| {
            *value >= SIGNATURE_SECTOR_SIZE && *value <= OTA_SLOT_SIZE - SIGNATURE_SECTOR_SIZE
        })
        .ok_or(InstalledImageError::Extent)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    let mut offset = 0_u32;
    while offset < signature_offset {
        let length = (signature_offset - offset).min(buffer.len() as u32) as usize;
        backend
            .read(slot, offset, &mut buffer[..length])
            .map_err(|_| InstalledImageError::Read)?;
        hasher.update(&buffer[..length]);
        offset += length as u32;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut block = [0; SIGNATURE_BLOCK_SIZE];
    backend
        .read(slot, signature_offset, &mut block)
        .map_err(|_| InstalledImageError::Read)?;
    let signature =
        parse_signature_block(&block, trusted_key_digest).ok_or(InstalledImageError::Signature)?;
    if *signature.image_digest != digest {
        return Err(InstalledImageError::Signature);
    }
    if !backend
        .verify_rsa_pss(signature.public_key, signature.signature, &digest)
        .map_err(|_| InstalledImageError::Signature)?
    {
        return Err(InstalledImageError::Signature);
    }
    Ok(VerifiedInstalledImage {
        secure_version: metadata.secure_version,
        signed_image_bytes: signature_offset + SIGNATURE_SECTOR_SIZE,
        signed_content_digest: digest,
    })
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

    #[derive(Clone)]
    struct FakeBackend {
        now_ms: u64,
        operation_elapsed_ms: u64,
        rsa_elapsed_ms: u64,
        slots: [Vec<u8>; 2],
        layout: UpdateLayout,
        mutations: Vec<Mutation>,
        rsa_valid: bool,
        read_error: bool,
        layout_error: bool,
    }

    impl FakeBackend {
        fn new() -> Self {
            Self {
                now_ms: 0,
                operation_elapsed_ms: 0,
                rsa_elapsed_ms: 0,
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
                read_error: false,
                layout_error: false,
            }
        }
    }

    impl UpdateBackend for FakeBackend {
        type Error = ();

        fn now_ms(&self) -> u64 {
            self.now_ms
        }

        fn layout(&mut self) -> Result<UpdateLayout, Self::Error> {
            self.now_ms = self.now_ms.saturating_add(self.operation_elapsed_ms);
            if self.layout_error {
                return Err(());
            }
            Ok(self.layout)
        }

        fn erase(&mut self, slot: u8, offset: u32, length: u32) -> Result<(), Self::Error> {
            self.now_ms = self.now_ms.saturating_add(self.operation_elapsed_ms);
            self.slots[slot as usize][offset as usize..(offset + length) as usize].fill(0xff);
            self.mutations.push(Mutation::Erase(slot, offset, length));
            Ok(())
        }

        fn write(&mut self, slot: u8, offset: u32, data: &[u8]) -> Result<(), Self::Error> {
            self.now_ms = self.now_ms.saturating_add(self.operation_elapsed_ms);
            self.slots[slot as usize][offset as usize..offset as usize + data.len()]
                .copy_from_slice(data);
            self.mutations
                .push(Mutation::Write(slot, offset, data.len()));
            Ok(())
        }

        fn read(&mut self, slot: u8, offset: u32, output: &mut [u8]) -> Result<(), Self::Error> {
            self.now_ms = self.now_ms.saturating_add(self.operation_elapsed_ms);
            if self.read_error {
                return Err(());
            }
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
            self.now_ms = self.now_ms.saturating_add(self.rsa_elapsed_ms);
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
        sized_signed_image(
            secure_version,
            version,
            (SIGNATURE_SECTOR_SIZE * 2) as usize,
        )
    }

    fn sized_signed_image(secure_version: u32, version: &[u8], size: usize) -> (Vec<u8>, [u8; 32]) {
        assert!(size >= (SIGNATURE_SECTOR_SIZE * 2) as usize);
        assert!(size.is_multiple_of(SIGNATURE_SECTOR_SIZE as usize));
        let mut image = vec![0xff; size];
        image[0] = ESP_IMAGE_MAGIC;
        image[1] = 1;
        image[12..14].copy_from_slice(&ESP32S2_CHIP_ID.to_le_bytes());
        image[23] = 1;
        image[32..36].copy_from_slice(&ESP_APP_DESCRIPTOR_MAGIC.to_le_bytes());
        image[36..40].copy_from_slice(&secure_version.to_le_bytes());
        image[48..48 + version.len()].copy_from_slice(version);
        image[48 + version.len()] = 0;

        let signed_length = size - SIGNATURE_SECTOR_SIZE as usize;
        let signed_digest: [u8; 32] = Sha256::digest(&image[..signed_length]).into();
        let block = &mut image[signed_length..signed_length + SIGNATURE_BLOCK_SIZE];
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

    fn installed_fixture() -> (FakeBackend, [u8; 32]) {
        let (mut image, trusted) = signed_image(4, b"normal");
        image[24..28].copy_from_slice(&0x3f00_0020_u32.to_le_bytes());
        image[28..32].copy_from_slice(&256_u32.to_le_bytes());
        let digest = Sha256::digest(&image[..4096]);
        image[4100..4132].copy_from_slice(&digest);
        let crc = esp_crc32_le(0, &image[4096..4096 + SIGNATURE_CRC_LENGTH]);
        image[4096 + 1196..4096 + 1200].copy_from_slice(&crc.to_le_bytes());
        let mut backend = FakeBackend::new();
        for slot in &mut backend.slots {
            slot[..image.len()].copy_from_slice(&image);
        }
        (backend, trusted)
    }

    #[test]
    fn installed_slot_verification_reads_both_slots_without_mutations() {
        let (mut backend, trusted) = installed_fixture();
        for slot in 0..2 {
            let image = verify_installed_slot(&mut backend, slot, &trusted).unwrap();
            assert_eq!(image.secure_version, 4);
            assert_eq!(image.signed_image_bytes, 8192);
            assert_eq!(
                image.signed_content_digest,
                Sha256::digest(&backend.slots[slot as usize][..4096]).as_slice()
            );
        }
        assert!(backend.mutations.is_empty());
    }

    #[test]
    fn installed_verifier_handles_qualified_multisegment_image_extents() {
        // Segment lengths from the three epoch-4 test builds. Only layout is
        // retained here: all segment contents and signature bytes are synthetic.
        for (lengths, expected_bytes) in [
            ([7436_u32, 1472, 5120, 51476, 344500], 417792_u32),
            ([7452, 1472, 5120, 51460, 345696], 417792),
            ([7444, 1472, 5120, 51468, 343628], 413696),
        ] {
            let (mut backend, trusted) = installed_fixture();
            let signature = backend.slots[0][4096..4096 + SIGNATURE_BLOCK_SIZE].to_vec();
            backend.slots[0][80..].fill(0);
            backend.slots[0][1] = lengths.len() as u8;
            let mut position = 24_usize;
            for length in lengths {
                backend.slots[0][position + 4..position + 8].copy_from_slice(&length.to_le_bytes());
                position += 8 + length as usize;
            }
            let offset = expected_bytes as usize - SIGNATURE_SECTOR_SIZE as usize;
            let digest = Sha256::digest(&backend.slots[0][..offset]);
            let block = &mut backend.slots[0][offset..offset + SIGNATURE_BLOCK_SIZE];
            block.copy_from_slice(&signature);
            block[4..36].copy_from_slice(&digest);
            let crc = esp_crc32_le(0, &block[..SIGNATURE_CRC_LENGTH]);
            block[1196..1200].copy_from_slice(&crc.to_le_bytes());
            let verified = verify_installed_slot(&mut backend, 0, &trusted).unwrap();
            assert_eq!(verified.signed_image_bytes, expected_bytes);
            assert_eq!(verified.signed_content_digest, digest.as_slice());
            assert!(backend.mutations.is_empty());
        }
    }

    #[test]
    fn installed_slot_verification_rejects_unbounded_segment_layouts() {
        for length in [u32::MAX, OTA_SLOT_SIZE, OTA_SLOT_SIZE - 4096, 0] {
            let (mut backend, trusted) = installed_fixture();
            backend.slots[0][28..32].copy_from_slice(&length.to_le_bytes());
            assert!(matches!(
                verify_installed_slot(&mut backend, 0, &trusted),
                Err(InstalledImageError::Extent | InstalledImageError::Header)
            ));
            assert!(backend.mutations.is_empty());
        }
    }

    #[test]
    fn installed_slot_verification_rejects_wrong_root_digest_and_rsa_failure() {
        let (mut backend, mut trusted) = installed_fixture();
        trusted[0] ^= 1;
        assert_eq!(
            verify_installed_slot(&mut backend, 0, &trusted),
            Err(InstalledImageError::Signature)
        );
        let (mut backend, trusted) = installed_fixture();
        backend.slots[0][256] ^= 1;
        assert_eq!(
            verify_installed_slot(&mut backend, 0, &trusted),
            Err(InstalledImageError::Signature)
        );
        let (mut backend, trusted) = installed_fixture();
        backend.rsa_valid = false;
        assert_eq!(
            verify_installed_slot(&mut backend, 0, &trusted),
            Err(InstalledImageError::Signature)
        );
        assert!(backend.mutations.is_empty());
    }

    #[test]
    fn installed_slot_verification_rejects_reads_bad_headers_and_invalid_slot() {
        let (mut backend, trusted) = installed_fixture();
        backend.read_error = true;
        assert_eq!(
            verify_installed_slot(&mut backend, 0, &trusted),
            Err(InstalledImageError::Read)
        );
        assert_eq!(
            verify_installed_slot(&mut backend, 2, &trusted),
            Err(InstalledImageError::Slot)
        );
        for (offset, value) in [(0, 0), (1, 0), (1, 17), (23, 0), (36, 17)] {
            let (mut backend, trusted) = installed_fixture();
            backend.slots[0][offset] = value;
            assert_eq!(
                verify_installed_slot(&mut backend, 0, &trusted),
                Err(InstalledImageError::Header)
            );
        }
    }

    fn response(updater: &mut UsbUpdater<FakeBackend>, request: &[u8], present: bool) -> Vec<u8> {
        let mut output = [0; 64];
        let length = updater.handle(request, present, &mut output);
        output[..length].to_vec()
    }

    #[test]
    fn unqualified_running_layout_rejects_approved_begin_without_mutations() {
        let (image, root) = signed_image(5, b"0.1.0");
        let mut backend = FakeBackend::new();
        backend.layout_error = true;
        let original_slots = backend.slots.clone();
        let mut updater = UsbUpdater::new(backend, root, "0.1.0", 5);
        let reply = response(&mut updater, &begin_request(&image, 5, b"0.1.0"), true);
        assert_eq!(reply[0], StatusCode::Flash as u8);
        assert_eq!(updater.phase(), Phase::Idle);
        assert_eq!(session_id(&reply), 0);
        assert!(updater.backend.mutations.is_empty());
        assert_eq!(updater.backend.slots, original_slots);
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
    fn idle_deadline_revokes_every_live_phase_and_requires_fresh_approval() {
        for phase in [Phase::Erasing, Phase::Receiving, Phase::Verifying] {
            let (image, trust) = sized_signed_image(4, b"next", (VERIFY_STEP_SIZE * 2) as usize);
            let begin = begin_request(&image, 4, b"next");
            let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
            let id = session_id(&response(&mut updater, &begin, true));
            if phase != Phase::Erasing {
                erase_all(&mut updater, id);
            }
            if phase == Phase::Verifying {
                write_all(&mut updater, id, &image);
                response(
                    &mut updater,
                    &session_request(Operation::Advance, id),
                    false,
                );
            }
            assert_eq!(updater.phase(), phase);
            updater.backend.now_ms = SESSION_IDLE_TIMEOUT_MS - 1;
            updater.poll();
            assert_eq!(updater.phase(), phase);
            let mutations = updater.backend.mutations.clone();
            let slots = updater.backend.slots.clone();
            updater.backend.now_ms += 1;
            updater.poll();
            assert_eq!(updater.phase(), Phase::Failed);
            for operation in [Operation::Advance, Operation::Status] {
                assert_eq!(
                    response(&mut updater, &session_request(operation, id), false)[0],
                    StatusCode::SessionExpired as u8
                );
            }
            let mut write = session_request(Operation::Write, id);
            write.extend_from_slice(&0_u32.to_le_bytes());
            write.extend_from_slice(&image[..32]);
            assert_eq!(
                response(&mut updater, &write, false)[0],
                StatusCode::SessionExpired as u8
            );
            assert_eq!(
                response(&mut updater, &begin, false)[0],
                StatusCode::UserPresenceRequired as u8
            );
            assert_eq!(updater.backend.mutations, mutations);
            assert_eq!(updater.backend.slots, slots);
            let new_id = session_id(&response(&mut updater, &begin, true));
            assert_ne!(id, new_id);
            assert_eq!(updater.phase(), Phase::Erasing);
            assert_eq!(
                response(
                    &mut updater,
                    &session_request(Operation::Advance, id),
                    false
                )[0],
                StatusCode::SessionMismatch as u8
            );
        }
    }

    #[test]
    fn status_invalid_requests_and_polling_do_not_extend_idle_authority() {
        let (image, trust) = signed_image(4, b"next");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
        let id = session_id(&response(
            &mut updater,
            &begin_request(&image, 4, b"next"),
            true,
        ));
        erase_all(&mut updater, id);
        let mutations = updater.backend.mutations.clone();
        for time in [1, SESSION_IDLE_TIMEOUT_MS / 2, SESSION_IDLE_TIMEOUT_MS - 1] {
            updater.backend.now_ms = time;
            response(&mut updater, &[Operation::Info as u8], false);
            response(&mut updater, &session_request(Operation::Status, id), false);
            response(
                &mut updater,
                &session_request(Operation::Advance, id),
                false,
            );
            response(
                &mut updater,
                &session_request(Operation::Abort, id + 1),
                false,
            );
            response(&mut updater, &[255], false);
            updater.poll();
        }
        updater.backend.now_ms = SESSION_IDLE_TIMEOUT_MS;
        // No periodic poll is needed to protect the command path.
        assert_eq!(
            response(
                &mut updater,
                &session_request(Operation::Advance, id),
                false
            )[0],
            StatusCode::SessionExpired as u8
        );
        assert_eq!(updater.backend.mutations, mutations);
    }

    #[test]
    fn successful_progress_renews_idle_time_but_never_absolute_lifetime() {
        let (image, trust) = signed_image(4, b"next");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
        let id = session_id(&response(
            &mut updater,
            &begin_request(&image, 4, b"next"),
            true,
        ));
        erase_all(&mut updater, id);
        let mut offset = 0_u32;
        // Real accepted writes keep idle time live well beyond its initial deadline.
        for time in (60_000..SESSION_MAX_LIFETIME_MS).step_by(60_000) {
            updater.backend.now_ms = time;
            let mut write = session_request(Operation::Write, id);
            write.extend_from_slice(&offset.to_le_bytes());
            write.extend_from_slice(&image[offset as usize..offset as usize + 32]);
            assert_eq!(
                response(&mut updater, &write, false)[0],
                StatusCode::Ok as u8
            );
            offset += 32;
        }
        updater.backend.now_ms = SESSION_MAX_LIFETIME_MS - 1;
        updater.poll();
        assert_eq!(updater.phase(), Phase::Receiving);
        let mutations = updater.backend.mutations.clone();
        updater.backend.now_ms += 1;
        let mut write = session_request(Operation::Write, id);
        write.extend_from_slice(&offset.to_le_bytes());
        write.extend_from_slice(&image[offset as usize..offset as usize + 32]);
        assert_eq!(
            response(&mut updater, &write, false)[0],
            StatusCode::SessionExpired as u8
        );
        assert_eq!(updater.backend.mutations, mutations);
    }

    #[test]
    fn backwards_clock_and_u64_wrap_expire_live_sessions() {
        for (start, later, backwards) in [(100, 200, 199), (u64::MAX - 10, u64::MAX - 1, 0)] {
            let (image, trust) = signed_image(4, b"next");
            let mut backend = FakeBackend::new();
            backend.now_ms = start;
            let mut updater = UsbUpdater::new(backend, trust, "old", 4);
            let id = session_id(&response(
                &mut updater,
                &begin_request(&image, 4, b"next"),
                true,
            ));
            updater.backend.now_ms = later;
            updater.poll();
            assert_eq!(updater.phase(), Phase::Erasing);
            updater.backend.now_ms = backwards;
            assert_eq!(
                response(
                    &mut updater,
                    &session_request(Operation::Advance, id),
                    false
                )[0],
                StatusCode::SessionExpired as u8
            );
            assert!(updater.backend.mutations.is_empty());
        }
    }

    #[test]
    fn expiration_during_backend_work_prevents_following_mutations() {
        for operation in [Operation::Advance, Operation::Write] {
            let (image, trust) = signed_image(4, b"next");
            let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
            let id = session_id(&response(
                &mut updater,
                &begin_request(&image, 4, b"next"),
                true,
            ));
            let mut request = session_request(operation, id);
            if operation == Operation::Write {
                erase_all(&mut updater, id);
                request.extend_from_slice(&0_u32.to_le_bytes());
                request.extend_from_slice(&image[..32]);
            }
            let prior = updater.backend.mutations.len();
            updater.backend.operation_elapsed_ms = SESSION_IDLE_TIMEOUT_MS;
            assert_eq!(
                response(&mut updater, &request, false)[0],
                StatusCode::SessionExpired as u8
            );
            // A started bounded operation completes; no subsequent operation starts.
            assert_eq!(updater.backend.mutations.len(), prior + 1);
            assert_eq!(
                response(&mut updater, &request, false)[0],
                StatusCode::SessionExpired as u8
            );
            assert_eq!(updater.backend.mutations.len(), prior + 1);
            assert_eq!(updater.backend.layout.active_slot, 0);
        }
    }

    #[test]
    fn read_and_rsa_time_are_checked_again_before_activation() {
        for slow_rsa in [false, true] {
            let (image, trust) = signed_image(4, b"next");
            let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
            let id = session_id(&response(
                &mut updater,
                &begin_request(&image, 4, b"next"),
                true,
            ));
            erase_all(&mut updater, id);
            write_all(&mut updater, id, &image);
            if slow_rsa {
                updater.backend.rsa_elapsed_ms = SESSION_IDLE_TIMEOUT_MS;
            } else {
                updater.backend.operation_elapsed_ms = SESSION_IDLE_TIMEOUT_MS;
            }
            let mutations = updater.backend.mutations.clone();
            assert_eq!(
                verify_all(&mut updater, id),
                StatusCode::SessionExpired as u8
            );
            assert_eq!(updater.backend.mutations, mutations);
            assert_eq!(updater.backend.layout.active_slot, 0);
        }
    }

    #[test]
    fn activated_result_survives_deadlines_without_repeating_activation() {
        let (image, trust) = signed_image(4, b"next");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
        let id = session_id(&response(
            &mut updater,
            &begin_request(&image, 4, b"next"),
            true,
        ));
        erase_all(&mut updater, id);
        write_all(&mut updater, id, &image);
        assert_eq!(verify_all(&mut updater, id), StatusCode::Ok as u8);
        let mutations = updater.backend.mutations.clone();
        updater.backend.now_ms = SESSION_MAX_LIFETIME_MS * 2;
        updater.poll();
        assert_eq!(updater.phase(), Phase::Activated);
        assert_eq!(
            response(
                &mut updater,
                &session_request(Operation::Advance, id),
                false
            )[0],
            StatusCode::Ok as u8
        );
        assert_eq!(updater.backend.mutations, mutations);
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
    fn unknown_operations_cannot_add_a_raw_restore_path() {
        let (image, trust) = signed_image(1, b"1.2.3");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "1.0.0", 1);
        for with_session in [false, true] {
            if with_session {
                let reply = response(&mut updater, &begin_request(&image, 1, b"1.2.3"), true);
                erase_all(&mut updater, session_id(&reply));
            }
            let mutations = updater.backend.mutations.clone();
            let phase = updater.phase();
            for operation in 6..=u8::MAX {
                // Even claimed presence must not enable an unrecognized
                // maintenance operation or interpret its bytes as an address.
                let request = [operation, 0, 0, 0x3e, 0, 0xff, 0xff, 0xff, 0xff];
                for present in [false, true] {
                    assert_eq!(
                        response(&mut updater, &request, present)[0],
                        StatusCode::InvalidRequest as u8
                    );
                    assert_eq!(updater.phase(), phase);
                    assert_eq!(updater.backend.mutations, mutations);
                }
            }
        }
    }

    #[test]
    fn raw_flash_addresses_and_unapproved_writes_do_not_reach_the_backend() {
        let (image, trust) = signed_image(1, b"1.2.3");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "1.0.0", 1);
        let mut write = vec![Operation::Write as u8];
        write.extend_from_slice(&1_u32.to_le_bytes());
        write.extend_from_slice(&0_u32.to_le_bytes());
        write.extend_from_slice(&[0xa5; 32]);
        assert_eq!(
            response(&mut updater, &write, true)[0],
            StatusCode::InvalidState as u8
        );
        assert!(updater.backend.mutations.is_empty());

        let reply = response(&mut updater, &begin_request(&image, 1, b"1.2.3"), true);
        let id = session_id(&reply);
        erase_all(&mut updater, id);
        let mutations = updater.backend.mutations.clone();
        // Bootloader, table, metadata, application and FIDO-store absolute
        // addresses are not valid sequential offsets for this transfer.
        for address in [
            0x1000_u32,
            0xe000,
            0xf000,
            0x20000,
            0x200000,
            0x3e0000,
            u32::MAX,
        ] {
            write[1..5].copy_from_slice(&id.to_le_bytes());
            write[5..9].copy_from_slice(&address.to_le_bytes());
            assert_eq!(
                response(&mut updater, &write, false)[0],
                StatusCode::OutOfOrder as u8
            );
            assert_eq!(updater.backend.mutations, mutations);
            assert_eq!(updater.phase(), Phase::Receiving);
        }
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
    fn advertised_newer_epoch_cannot_hide_an_older_signed_descriptor() {
        let (image, trust) = signed_image(3, b"0.1.0");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "0.2.0", 4);
        let id = session_id(&response(
            &mut updater,
            &begin_request(&image, 4, b"0.1.0"),
            true,
        ));
        erase_all(&mut updater, id);
        write_all(&mut updater, id, &image);
        assert_eq!(verify_all(&mut updater, id), StatusCode::Rollback as u8);
        assert_eq!(updater.backend.layout.active_slot, 0);
        assert!(
            !updater
                .backend
                .mutations
                .iter()
                .any(|m| matches!(m, Mutation::Activate(..)))
        );
    }

    #[test]
    fn reset_at_each_transfer_boundary_preserves_the_active_image() {
        let (image, trust) = sized_signed_image(
            4,
            b"0.2.0",
            (VERIFY_STEP_SIZE * 2 + SIGNATURE_SECTOR_SIZE) as usize,
        );
        for active in 0..2 {
            let mut backend = FakeBackend::new();
            backend.layout = UpdateLayout {
                active_slot: active,
                active_sequence: u32::from(active) + 1,
                activation_entry: 1 - active,
            };
            let initial = backend.layout;
            let original = backend.slots[active as usize].clone();
            let mut updater = UsbUpdater::new(backend, trust, "0.1.0", 4);
            let begin = begin_request(&image, 4, b"0.2.0");
            let id = session_id(&response(&mut updater, &begin, true));
            let mut advance = vec![Operation::Advance as u8];
            advance.extend_from_slice(&id.to_le_bytes());
            let check_reset = |updater: &UsbUpdater<FakeBackend>| {
                assert_eq!(updater.backend.layout, initial);
                assert_eq!(updater.backend.slots[active as usize], original);
                let mut rebooted = UsbUpdater::new(updater.backend.clone(), trust, "0.1.0", 4);
                assert_eq!(rebooted.phase(), Phase::Idle);
                let mutations = rebooted.backend.mutations.len();
                assert_eq!(
                    response(&mut rebooted, &advance, false)[0],
                    StatusCode::InvalidState as u8
                );
                assert_eq!(
                    response(&mut rebooted, &begin, false)[0],
                    StatusCode::UserPresenceRequired as u8
                );
                assert_eq!(rebooted.backend.mutations.len(), mutations);
                assert_eq!(rebooted.backend.layout, initial);
            };
            check_reset(&updater);
            while updater.phase() == Phase::Erasing {
                assert_eq!(
                    response(&mut updater, &advance, false)[0],
                    StatusCode::Ok as u8
                );
                check_reset(&updater);
            }
            for (index, chunk) in image.chunks(MAX_WRITE_CHUNK).enumerate() {
                let mut write = vec![Operation::Write as u8];
                write.extend_from_slice(&id.to_le_bytes());
                write.extend_from_slice(&((index * MAX_WRITE_CHUNK) as u32).to_le_bytes());
                write.extend_from_slice(chunk);
                assert_eq!(
                    response(&mut updater, &write, false)[0],
                    StatusCode::Ok as u8
                );
                check_reset(&updater);
            }
            while matches!(updater.phase(), Phase::Receiving | Phase::Verifying) {
                assert_eq!(
                    response(&mut updater, &advance, false)[0],
                    StatusCode::Ok as u8
                );
                if updater.phase() != Phase::Activated {
                    check_reset(&updater);
                }
            }
            assert_eq!(updater.phase(), Phase::Activated);
            assert_eq!(updater.backend.layout.active_slot, 1 - active);
            assert_eq!(updater.backend.slots[active as usize], original);
        }
    }

    #[test]
    fn crc_matches_standard_esp_rom_seed_contract() {
        assert_eq!(esp_crc32_le(0, b"123456789"), 0xcbf4_3926);
    }

    fn session_request(operation: Operation, id: u32) -> Vec<u8> {
        let mut request = vec![operation as u8];
        request.extend_from_slice(&id.to_le_bytes());
        request
    }

    #[test]
    fn transport_resynchronization_preserves_session_until_vendor_abort() {
        use crate::ctaphid::{BROADCAST_CHANNEL, Command, CtapHid, DeviceVersion, Event};

        let packet = |channel: u32, command: Command, payload: &[u8]| {
            assert!(payload.len() <= 57);
            let mut packet = [0_u8; 64];
            packet[..4].copy_from_slice(&channel.to_be_bytes());
            packet[4] = 0x80 | command as u8;
            packet[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            packet[7..7 + payload.len()].copy_from_slice(payload);
            packet
        };
        for control in [Command::Cancel, Command::Init] {
            let mut transport = CtapHid::<1024>::new(
                DeviceVersion {
                    major: 0,
                    minor: 1,
                    build: 0,
                },
                0x0c,
            );
            transport.ingest(&packet(BROADCAST_CHANNEL, Command::Init, &[0x5a; 8]), 0);
            let init = transport.next_packet().unwrap();
            let channel = u32::from_be_bytes(init[15..19].try_into().unwrap());
            transport.packet_sent();
            let (image, trust) = signed_image(4, b"next");
            let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
            // Compose the real transport and updater. Presence is supplied by
            // the test; physical wait/cancellation has separate gate tests.
            let exchange = |transport: &mut CtapHid<1024>,
                            updater: &mut UsbUpdater<FakeBackend>,
                            request: &[u8],
                            present: bool| {
                assert!(matches!(
                    transport.ingest(&packet(channel, Command::Update, request), 10),
                    Event::Update { .. }
                ));
                let reply = response(updater, transport.request_payload().unwrap(), present);
                transport.reply_update(&reply).unwrap();
                while transport.next_packet().is_some() {
                    transport.packet_sent();
                }
                reply
            };
            let begin = begin_request(&image, 4, b"next");
            let id = session_id(&exchange(&mut transport, &mut updater, &begin, true));
            let control_payload: &[u8] = if control == Command::Init {
                &[0x33; 8]
            } else {
                &[]
            };
            assert_eq!(
                transport.ingest(&packet(channel, control, control_payload), 10),
                Event::None
            );
            while transport.next_packet().is_some() {
                transport.packet_sent();
            }
            assert_eq!(updater.phase(), Phase::Erasing);
            assert!(updater.backend.mutations.is_empty());
            assert_eq!(
                exchange(
                    &mut transport,
                    &mut updater,
                    &session_request(Operation::Advance, id),
                    false
                )[0],
                StatusCode::Ok as u8
            );
            assert_eq!(updater.phase(), Phase::Receiving);
            let mutations = updater.backend.mutations.clone();
            assert_eq!(
                exchange(
                    &mut transport,
                    &mut updater,
                    &session_request(Operation::Abort, id),
                    false
                )[0],
                StatusCode::Ok as u8
            );
            assert_eq!(
                exchange(
                    &mut transport,
                    &mut updater,
                    &session_request(Operation::Advance, id),
                    false
                )[0],
                StatusCode::InvalidState as u8
            );
            assert_eq!(
                exchange(&mut transport, &mut updater, &begin, false)[0],
                StatusCode::UserPresenceRequired as u8
            );
            assert_eq!(updater.backend.mutations, mutations);
            assert_eq!(updater.backend.layout.active_slot, 0);
            // A second approved session still expires across either transport
            // control operation, even when it arrives just before the deadline.
            let next_id = session_id(&exchange(&mut transport, &mut updater, &begin, true));
            updater.backend.now_ms = SESSION_IDLE_TIMEOUT_MS - 1;
            transport.ingest(&packet(channel, control, control_payload), 11);
            while transport.next_packet().is_some() {
                transport.packet_sent();
            }
            updater.poll();
            assert_eq!(updater.phase(), Phase::Erasing);
            updater.backend.now_ms += 1;
            assert_eq!(
                exchange(
                    &mut transport,
                    &mut updater,
                    &session_request(Operation::Advance, next_id),
                    false
                )[0],
                StatusCode::SessionExpired as u8
            );
            assert_eq!(updater.backend.mutations, mutations);
        }
    }

    #[test]
    fn descriptor_floor_and_host_claim_have_distinct_rejection_codes() {
        // Synthetic signature blocks exercise policy, not ROM RSA semantics.
        for (actual, claimed, version, expected) in [
            (3, 5, b"next".as_slice(), StatusCode::Rollback),
            (4, 5, b"next".as_slice(), StatusCode::VersionMismatch),
            (5, 4, b"next".as_slice(), StatusCode::VersionMismatch),
            (4, 4, b"wrong".as_slice(), StatusCode::VersionMismatch),
            (4, 4, b"next".as_slice(), StatusCode::Ok),
            (5, 5, b"next".as_slice(), StatusCode::Ok),
        ] {
            let (image, trust) = signed_image(actual, b"next");
            let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
            let id = session_id(&response(
                &mut updater,
                &begin_request(&image, claimed, version),
                true,
            ));
            erase_all(&mut updater, id);
            write_all(&mut updater, id, &image);
            assert_eq!(verify_all(&mut updater, id), expected as u8);
            assert_eq!(
                updater.phase() == Phase::Activated,
                expected == StatusCode::Ok
            );
            assert_eq!(
                updater.backend.layout.active_slot,
                u8::from(expected == StatusCode::Ok)
            );
        }
    }

    #[test]
    fn abort_each_uncommitted_phase_revokes_session_and_requires_new_presence() {
        for phase in [
            Phase::Erasing,
            Phase::Receiving,
            Phase::Verifying,
            Phase::Failed,
        ] {
            let (image, trust) = sized_signed_image(4, b"next", (VERIFY_STEP_SIZE * 2) as usize);
            let begin = begin_request(&image, 4, b"next");
            let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
            let id = session_id(&response(&mut updater, &begin, true));
            if phase != Phase::Erasing {
                erase_all(&mut updater, id);
            }
            if matches!(phase, Phase::Verifying | Phase::Failed) {
                write_all(&mut updater, id, &image);
                updater.backend.read_error = phase == Phase::Failed;
                response(
                    &mut updater,
                    &session_request(Operation::Advance, id),
                    false,
                );
            }
            assert_eq!(updater.phase(), phase);
            let mutations = updater.backend.mutations.clone();
            let slots = updater.backend.slots.clone();
            assert_eq!(
                response(
                    &mut updater,
                    &session_request(Operation::Abort, id + 1),
                    false
                )[0],
                StatusCode::SessionMismatch as u8
            );
            assert_eq!(updater.phase(), phase);
            assert_eq!(
                response(&mut updater, &session_request(Operation::Abort, id), false)[0],
                StatusCode::Ok as u8
            );
            assert_eq!(updater.phase(), Phase::Idle);
            for operation in [Operation::Advance, Operation::Status, Operation::Abort] {
                assert_eq!(
                    response(&mut updater, &session_request(operation, id), false)[0],
                    StatusCode::InvalidState as u8
                );
            }
            let mut write = session_request(Operation::Write, id);
            write.extend_from_slice(&0_u32.to_le_bytes());
            write.extend_from_slice(&image[..32]);
            assert_eq!(
                response(&mut updater, &write, false)[0],
                StatusCode::InvalidState as u8
            );
            assert_eq!(
                response(&mut updater, &begin, false)[0],
                StatusCode::UserPresenceRequired as u8
            );
            assert_eq!(updater.backend.mutations, mutations);
            assert_eq!(updater.backend.slots, slots);
            assert_eq!(updater.backend.layout.active_slot, 0);
            let new_id = session_id(&response(&mut updater, &begin, true));
            assert_ne!(new_id, id);
            assert_eq!(
                response(&mut updater, &write, false)[0],
                StatusCode::SessionMismatch as u8
            );
        }
    }

    #[test]
    fn session_id_wrap_skips_zero_and_rejects_the_previous_session() {
        let (image, trust) = signed_image(4, b"next");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
        updater.next_session_id = u32::MAX;
        let begin = begin_request(&image, 4, b"next");
        let old = session_id(&response(&mut updater, &begin, true));
        assert_eq!(old, u32::MAX);
        assert_eq!(
            response(&mut updater, &session_request(Operation::Abort, old), false)[0],
            StatusCode::Ok as u8
        );
        assert_eq!(session_id(&response(&mut updater, &begin, true)), 1);
        for id in [0, old] {
            assert_eq!(
                response(
                    &mut updater,
                    &session_request(Operation::Advance, id),
                    false
                )[0],
                StatusCode::SessionMismatch as u8
            );
        }
        assert!(updater.backend.mutations.is_empty());
    }

    #[test]
    fn full_slot_update_is_confined_aligned_and_activation_is_terminal() {
        let (image, trust) = sized_signed_image(4, b"next", OTA_SLOT_SIZE as usize);
        for active in 0..2 {
            let mut backend = FakeBackend::new();
            // Simulated slow backend: each erase/write/read/layout takes 100 ms.
            // Full-slot updates exceed the idle interval overall, but actual
            // progress keeps them live within the fixed absolute lifetime.
            backend.operation_elapsed_ms = 100;
            backend.layout = UpdateLayout {
                active_slot: active,
                active_sequence: u32::from(active) + 1,
                activation_entry: 1 - active,
            };
            let original = backend.slots[active as usize].clone();
            let mut updater = UsbUpdater::new(backend, trust, "old", 4);
            let id = session_id(&response(
                &mut updater,
                &begin_request(&image, 4, b"next"),
                true,
            ));
            erase_all(&mut updater, id);
            write_all(&mut updater, id, &image);
            assert_eq!(verify_all(&mut updater, id), StatusCode::Ok as u8);
            let mutations = updater.backend.mutations.clone();
            for mutation in &mutations {
                match *mutation {
                    Mutation::Erase(slot, offset, length) => {
                        assert_eq!(slot, 1 - active);
                        assert!(offset.is_multiple_of(4096) && length.is_multiple_of(4096));
                        assert!(length > 0 && offset + length <= OTA_SLOT_SIZE);
                    }
                    Mutation::Write(slot, offset, length) => {
                        assert_eq!(slot, 1 - active);
                        assert!(offset.is_multiple_of(32) && length.is_multiple_of(32));
                        assert!(length > 0 && length <= MAX_WRITE_CHUNK);
                        assert!(offset + length as u32 <= OTA_SLOT_SIZE);
                    }
                    Mutation::Activate(slot, _, _) => assert_eq!(slot, 1 - active),
                }
            }
            assert_eq!(
                mutations
                    .iter()
                    .filter(|m| matches!(m, Mutation::Activate(..)))
                    .count(),
                1
            );
            assert!(matches!(mutations.last(), Some(Mutation::Activate(..))));
            for _ in 0..3 {
                assert_eq!(
                    response(
                        &mut updater,
                        &session_request(Operation::Advance, id),
                        false
                    )[0],
                    StatusCode::Ok as u8
                );
            }
            assert_eq!(
                response(&mut updater, &session_request(Operation::Abort, id), false)[0],
                StatusCode::InvalidState as u8
            );
            assert_eq!(updater.backend.mutations, mutations);
            assert_eq!(updater.backend.slots[active as usize], original);
            assert_eq!(updater.backend.slots[(1 - active) as usize], image);
        }
    }

    #[test]
    fn rejected_writes_preserve_progress_and_flash_before_valid_continuation() {
        let (image, trust) = signed_image(4, b"next");
        let mut updater = UsbUpdater::new(FakeBackend::new(), trust, "old", 4);
        let id = session_id(&response(
            &mut updater,
            &begin_request(&image, 4, b"next"),
            true,
        ));
        erase_all(&mut updater, id);
        let write = |offset: u32, data: &[u8]| {
            let mut request = session_request(Operation::Write, id);
            request.extend_from_slice(&offset.to_le_bytes());
            request.extend_from_slice(data);
            request
        };
        assert_eq!(
            response(&mut updater, &write(0, &image[..32]), false)[0],
            StatusCode::Ok as u8
        );
        let mutations = updater.backend.mutations.clone();
        let slots = updater.backend.slots.clone();
        for request in [
            write(0, &image[..32]),
            write(64, &image[64..96]),
            write(u32::MAX, &image[..32]),
            write(32, &[]),
            write(32, &image[..31]),
            write(32, &image[..MAX_WRITE_CHUNK + 32]),
        ] {
            assert_ne!(
                response(&mut updater, &request, false)[0],
                StatusCode::Ok as u8
            );
            assert_eq!(updater.session.as_ref().unwrap().completed, 32);
            assert_eq!(updater.backend.mutations, mutations);
            assert_eq!(updater.backend.slots, slots);
        }
        assert_eq!(
            response(&mut updater, &write(32, &image[32..64]), false)[0],
            StatusCode::Ok as u8
        );
        assert_eq!(updater.session.as_ref().unwrap().completed, 64);
    }
}
