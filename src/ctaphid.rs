//! CTAP over USB HID message framing.
//!
//! This module owns the CTAPHID transport state only. It deliberately does not
//! implement authenticator, credential, cryptographic, or persistence logic.

use zeroize::Zeroize;

pub use crate::request_completion::ReplyError;

pub const PACKET_SIZE: usize = 64;
pub const MAX_MESSAGE_SIZE: usize = 1024;
pub const INIT_PAYLOAD_SIZE: usize = 57;
pub const CONT_PAYLOAD_SIZE: usize = 59;
pub const MAX_CTAPHID_MESSAGE_SIZE: usize = INIT_PAYLOAD_SIZE + 128 * CONT_PAYLOAD_SIZE;
pub const BROADCAST_CHANNEL: u32 = 0xffff_ffff;
pub const RESERVED_CHANNEL: u32 = 0;
pub const RECEIVE_TIMEOUT_MS: u32 = 550;
pub const CAPABILITY_WINK: u8 = 0x01;
pub const CAPABILITY_CBOR: u8 = 0x04;
pub const CAPABILITY_NMSG: u8 = 0x08;

const ERROR_CAPACITY: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    Ping = 0x01,
    Msg = 0x03,
    Lock = 0x04,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    Keepalive = 0x3b,
    Error = 0x3f,
    /// Solo2-compatible vendor opcode used as the Salpa update namespace.
    Update = 0x51,
}

impl Command {
    fn from_number(value: u8) -> Option<Self> {
        Some(match value {
            0x01 => Self::Ping,
            0x03 => Self::Msg,
            0x04 => Self::Lock,
            0x06 => Self::Init,
            0x08 => Self::Wink,
            0x10 => Self::Cbor,
            0x11 => Self::Cancel,
            0x3b => Self::Keepalive,
            0x3f => Self::Error,
            0x51 => Self::Update,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransportError {
    InvalidCommand = 0x01,
    InvalidLength = 0x03,
    InvalidSequence = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    InvalidChannel = 0x0b,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KeepaliveStatus {
    Processing = 0x01,
    UserPresenceNeeded = 0x02,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceVersion {
    pub major: u8,
    pub minor: u8,
    pub build: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    None,
    Cbor { channel: u32, length: usize },
    Update { channel: u32, length: usize },
    Cancelled { channel: u32 },
}

#[derive(Clone, Copy)]
struct ReceiveState {
    channel: u32,
    command: Command,
    length: usize,
    received: usize,
    next_sequence: u8,
    last_activity_ms: u32,
}

#[derive(Clone, Copy)]
struct AppRequest {
    channel: u32,
    command: Command,
    length: usize,
}

#[derive(Clone, Copy)]
struct TransmitState {
    channel: u32,
    command: Command,
    length: usize,
    offset: usize,
    next_sequence: u8,
}

#[derive(Clone, Copy)]
struct PendingError {
    channel: u32,
    error: TransportError,
}

/// Fixed-memory CTAPHID transport engine.
///
/// `N` is the maximum accepted CTAPHID message size and therefore also the
/// size of each request and response buffer.
pub struct CtapHid<const N: usize> {
    request: [u8; N],
    response: [u8; N],
    receive: Option<ReceiveState>,
    app_request: Option<AppRequest>,
    transmit: Option<TransmitState>,
    keepalive: Option<(u32, KeepaliveStatus)>,
    errors: [Option<PendingError>; ERROR_CAPACITY],
    last_channel: u32,
    version: DeviceVersion,
    capabilities: u8,
}

impl<const N: usize> CtapHid<N> {
    pub const fn new(version: DeviceVersion, capabilities: u8) -> Self {
        assert!(N >= 17, "CTAPHID buffer must fit an INIT response");
        assert!(
            N <= MAX_CTAPHID_MESSAGE_SIZE,
            "CTAPHID buffer exceeds the continuation sequence space"
        );
        Self {
            request: [0; N],
            response: [0; N],
            receive: None,
            app_request: None,
            transmit: None,
            keepalive: None,
            errors: [None; ERROR_CAPACITY],
            last_channel: RESERVED_CHANNEL,
            version,
            capabilities,
        }
    }

    /// Discard an untrustworthy USB transfer and any transaction it interrupted.
    /// No channel can be trusted in a truncated report.
    pub fn transport_error(&mut self) {
        self.abort_transaction();
        self.errors.fill(None);
    }

    pub fn ingest_report(&mut self, report: &[u8], now_ms: u32) -> (Event, bool) {
        let Ok(packet) = <&[u8; PACKET_SIZE]>::try_from(report) else {
            self.transport_error();
            return (Event::None, true);
        };
        self.ingest_with_interruption(packet, now_ms)
    }

    pub fn ingest(&mut self, packet: &[u8; PACKET_SIZE], now_ms: u32) -> Event {
        let channel = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);

        if packet[4] & 0x80 == 0 {
            return self.ingest_continuation(channel, packet, now_ms);
        }

        let command_number = packet[4] & 0x7f;
        let length = u16::from_be_bytes([packet[5], packet[6]]) as usize;
        let is_cancel = command_number == Command::Cancel as u8;

        if let Some(active_channel) = self.active_channel() {
            if is_cancel && channel != active_channel {
                return Event::None;
            }
            if channel != active_channel {
                self.queue_error(channel, TransportError::ChannelBusy);
                return Event::None;
            }
            if command_number == Command::Init as u8 {
                self.abort_transaction();
            } else if is_cancel {
                if length != 0 {
                    self.queue_error(channel, TransportError::InvalidLength);
                    return Event::None;
                }
                return if self.cancel_application_request() {
                    Event::Cancelled { channel }
                } else {
                    Event::None
                };
            } else {
                self.abort_transaction();
                self.queue_error(channel, TransportError::InvalidSequence);
                return Event::None;
            }
        }

        self.request.zeroize();

        let Some(command) = Command::from_number(command_number) else {
            self.queue_error(channel, TransportError::InvalidCommand);
            return Event::None;
        };
        if length > N {
            self.queue_error(channel, TransportError::InvalidLength);
            return Event::None;
        }
        if (command == Command::Init && length != 8) || (command == Command::Cancel && length != 0)
        {
            self.queue_error(channel, TransportError::InvalidLength);
            return Event::None;
        }

        let copied = length.min(INIT_PAYLOAD_SIZE);
        self.request[..copied].copy_from_slice(&packet[7..7 + copied]);
        if length > INIT_PAYLOAD_SIZE {
            self.receive = Some(ReceiveState {
                channel,
                command,
                length,
                received: INIT_PAYLOAD_SIZE,
                next_sequence: 0,
                last_activity_ms: now_ms,
            });
            Event::None
        } else {
            self.dispatch(channel, command, length)
        }
    }

    pub fn request_payload(&self) -> Option<&[u8]> {
        self.app_request
            .map(|request| &self.request[..request.length])
    }

    /// Ingest a report while an application may be waiting for user presence.
    /// The boolean reports both CANCEL and transport aborts, including INIT
    /// resynchronization, so neither can leave an application wait running.
    pub fn ingest_with_interruption(
        &mut self,
        packet: &[u8; PACKET_SIZE],
        now_ms: u32,
    ) -> (Event, bool) {
        let application_was_running = self.app_request.is_some();
        let event = self.ingest(packet, now_ms);
        let interrupted = (application_was_running && self.app_request.is_none())
            || matches!(event, Event::Cancelled { .. });
        (event, interrupted)
    }

    pub fn reply_cbor(&mut self, payload: &[u8]) -> Result<(), ReplyError> {
        self.reply(payload)
    }

    pub fn reply_update(&mut self, payload: &[u8]) -> Result<(), ReplyError> {
        self.reply(payload)
    }

    fn reply(&mut self, payload: &[u8]) -> Result<(), ReplyError> {
        let Some(request) = self.app_request.take() else {
            return Err(ReplyError::NoPendingRequest);
        };
        self.request.zeroize();
        if payload.len() > N {
            self.queue_error(request.channel, TransportError::InvalidLength);
            return Err(ReplyError::ResponseTooLong);
        }

        self.response.zeroize();
        self.response[..payload.len()].copy_from_slice(payload);
        self.start_transmit(request.channel, request.command, payload.len());
        Ok(())
    }

    /// Queue a CTAPHID_KEEPALIVE packet while a CBOR request is pending.
    pub fn keepalive(&mut self, status: KeepaliveStatus) -> bool {
        let Some(request) = self.app_request else {
            return false;
        };
        self.keepalive = Some((request.channel, status));
        true
    }

    pub fn expire(&mut self, now_ms: u32) {
        let Some(receive) = self.receive else {
            return;
        };
        if now_ms.wrapping_sub(receive.last_activity_ms) > RECEIVE_TIMEOUT_MS {
            self.receive = None;
            self.request.zeroize();
            self.queue_error(receive.channel, TransportError::Timeout);
        }
    }

    /// Build the next fixed-size HID input report without advancing state.
    pub fn next_packet(&self) -> Option<[u8; PACKET_SIZE]> {
        if let Some(error) = self.errors[0] {
            let mut packet = initial_packet(error.channel, Command::Error, 1);
            packet[7] = error.error as u8;
            return Some(packet);
        }
        if let Some((channel, status)) = self.keepalive {
            let mut packet = initial_packet(channel, Command::Keepalive, 1);
            packet[7] = status as u8;
            return Some(packet);
        }

        let transmit = self.transmit?;
        let mut packet = [0; PACKET_SIZE];
        packet[..4].copy_from_slice(&transmit.channel.to_be_bytes());
        if transmit.offset == 0 {
            packet[4] = transmit.command as u8 | 0x80;
            packet[5..7].copy_from_slice(&(transmit.length as u16).to_be_bytes());
            let count = transmit.length.min(INIT_PAYLOAD_SIZE);
            packet[7..7 + count].copy_from_slice(&self.response[..count]);
        } else {
            packet[4] = transmit.next_sequence;
            let count = (transmit.length - transmit.offset).min(CONT_PAYLOAD_SIZE);
            packet[5..5 + count]
                .copy_from_slice(&self.response[transmit.offset..transmit.offset + count]);
        }
        Some(packet)
    }

    /// Confirm that the packet returned by `next_packet` reached the USB host.
    pub fn packet_sent(&mut self) {
        if self.errors[0].is_some() {
            self.errors.rotate_left(1);
            self.errors[ERROR_CAPACITY - 1] = None;
            return;
        }
        if self.keepalive.take().is_some() {
            return;
        }

        let Some(mut transmit) = self.transmit else {
            return;
        };
        let count = if transmit.offset == 0 {
            transmit.length.min(INIT_PAYLOAD_SIZE)
        } else {
            (transmit.length - transmit.offset).min(CONT_PAYLOAD_SIZE)
        };
        transmit.offset += count;
        if transmit.offset >= transmit.length {
            self.transmit = None;
            self.response.zeroize();
        } else {
            if transmit.offset > INIT_PAYLOAD_SIZE {
                transmit.next_sequence = transmit.next_sequence.wrapping_add(1);
            }
            self.transmit = Some(transmit);
        }
    }

    fn ingest_continuation(
        &mut self,
        channel: u32,
        packet: &[u8; PACKET_SIZE],
        now_ms: u32,
    ) -> Event {
        let Some(mut receive) = self.receive else {
            return Event::None;
        };
        if channel != receive.channel {
            return Event::None;
        }
        if packet[4] != receive.next_sequence {
            self.receive = None;
            self.request.zeroize();
            self.queue_error(channel, TransportError::InvalidSequence);
            return Event::None;
        }

        let count = (receive.length - receive.received).min(CONT_PAYLOAD_SIZE);
        self.request[receive.received..receive.received + count]
            .copy_from_slice(&packet[5..5 + count]);
        receive.received += count;
        receive.next_sequence = receive.next_sequence.wrapping_add(1);
        receive.last_activity_ms = now_ms;

        if receive.received == receive.length {
            self.receive = None;
            self.dispatch(receive.channel, receive.command, receive.length)
        } else {
            self.receive = Some(receive);
            Event::None
        }
    }

    fn dispatch(&mut self, channel: u32, command: Command, length: usize) -> Event {
        if command == Command::Init {
            return self.dispatch_init(channel, length);
        }
        if channel == RESERVED_CHANNEL
            || channel == BROADCAST_CHANNEL
            || !self.is_allocated(channel)
        {
            self.request.zeroize();
            self.queue_error(channel, TransportError::InvalidChannel);
            return Event::None;
        }

        match command {
            Command::Ping => {
                self.response.zeroize();
                self.response[..length].copy_from_slice(&self.request[..length]);
                self.request.zeroize();
                self.start_transmit(channel, command, length);
            }
            Command::Cbor => {
                self.app_request = Some(AppRequest {
                    channel,
                    command,
                    length,
                });
                return Event::Cbor { channel, length };
            }
            Command::Update => {
                #[cfg(any(feature = "usb-signed-update", test))]
                {
                    self.app_request = Some(AppRequest {
                        channel,
                        command,
                        length,
                    });
                    return Event::Update { channel, length };
                }
                #[cfg(not(any(feature = "usb-signed-update", test)))]
                {
                    self.request.zeroize();
                    self.queue_error(channel, TransportError::InvalidCommand);
                }
            }
            Command::Cancel => self.request.zeroize(),
            Command::Init => unreachable!(),
            Command::Msg | Command::Lock | Command::Wink | Command::Keepalive | Command::Error => {
                self.request.zeroize();
                self.queue_error(channel, TransportError::InvalidCommand)
            }
        }
        Event::None
    }

    fn dispatch_init(&mut self, channel: u32, length: usize) -> Event {
        if channel == RESERVED_CHANNEL {
            self.request.zeroize();
            self.queue_error(channel, TransportError::InvalidChannel);
            return Event::None;
        }
        if length != 8 {
            self.request.zeroize();
            self.queue_error(channel, TransportError::InvalidLength);
            return Event::None;
        }

        let assigned = if channel == BROADCAST_CHANNEL {
            self.allocate_channel()
        } else if self.is_allocated(channel) {
            channel
        } else {
            self.request.zeroize();
            self.queue_error(channel, TransportError::InvalidChannel);
            return Event::None;
        };

        self.response.zeroize();
        self.response[..8].copy_from_slice(&self.request[..8]);
        self.response[8..12].copy_from_slice(&assigned.to_be_bytes());
        self.response[12] = 2;
        self.response[13] = self.version.major;
        self.response[14] = self.version.minor;
        self.response[15] = self.version.build;
        self.response[16] = self.capabilities;
        self.request.zeroize();
        self.start_transmit(channel, Command::Init, 17);
        Event::None
    }

    fn allocate_channel(&mut self) -> u32 {
        loop {
            self.last_channel = self.last_channel.wrapping_add(1);
            if self.last_channel != RESERVED_CHANNEL && self.last_channel != BROADCAST_CHANNEL {
                return self.last_channel;
            }
        }
    }

    fn is_allocated(&self, channel: u32) -> bool {
        channel != RESERVED_CHANNEL && channel != BROADCAST_CHANNEL && channel <= self.last_channel
    }

    fn active_channel(&self) -> Option<u32> {
        self.receive
            .map(|state| state.channel)
            .or_else(|| self.app_request.map(|request| request.channel))
            .or_else(|| self.transmit.map(|state| state.channel))
    }

    fn abort_transaction(&mut self) {
        self.request.zeroize();
        self.response.zeroize();
        self.receive = None;
        self.app_request = None;
        self.transmit = None;
        self.keepalive = None;
    }

    fn cancel_application_request(&mut self) -> bool {
        if self.app_request.is_none() {
            return false;
        }
        // CTAPHID_CANCEL has no response of its own. Keep the original
        // application request until it returns its cancellation response.
        self.keepalive = None;
        true
    }

    fn start_transmit(&mut self, channel: u32, command: Command, length: usize) {
        self.transmit = Some(TransmitState {
            channel,
            command,
            length,
            offset: 0,
            next_sequence: 0,
        });
    }

    fn queue_error(&mut self, channel: u32, error: TransportError) {
        if self
            .errors
            .iter()
            .flatten()
            .any(|pending| pending.channel == channel)
        {
            return;
        }
        if let Some(slot) = self.errors.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(PendingError { channel, error });
        }
    }
}

fn initial_packet(channel: u32, command: Command, length: usize) -> [u8; PACKET_SIZE] {
    let mut packet = [0; PACKET_SIZE];
    packet[..4].copy_from_slice(&channel.to_be_bytes());
    packet[4] = command as u8 | 0x80;
    packet[5..7].copy_from_slice(&(length as u16).to_be_bytes());
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_completion::{
        CborCompletion, ReplyDisposition, complete_cbor, complete_update,
    };

    const VERSION: DeviceVersion = DeviceVersion {
        major: 0,
        minor: 1,
        build: 0,
    };
    const CAPABILITIES: u8 = 0x0c;

    fn request_packet(channel: u32, command: Command, payload: &[u8]) -> [u8; PACKET_SIZE] {
        let mut packet = initial_packet(channel, command, payload.len());
        let count = payload.len().min(INIT_PAYLOAD_SIZE);
        packet[7..7 + count].copy_from_slice(&payload[..count]);
        packet
    }

    fn continuation_packet(channel: u32, sequence: u8, payload: &[u8]) -> [u8; PACKET_SIZE] {
        let mut packet = [0; PACKET_SIZE];
        packet[..4].copy_from_slice(&channel.to_be_bytes());
        packet[4] = sequence;
        packet[5..5 + payload.len()].copy_from_slice(payload);
        packet
    }

    fn allocate<const N: usize>(engine: &mut CtapHid<N>) -> u32 {
        let nonce = [0x5a; 8];
        assert_eq!(
            engine.ingest(&request_packet(BROADCAST_CHANNEL, Command::Init, &nonce), 0),
            Event::None
        );
        let response = engine.next_packet().unwrap();
        assert_eq!(&response[7..15], &nonce);
        assert_eq!(response[19], 2);
        assert_eq!(response[20], VERSION.major);
        assert_eq!(response[21], VERSION.minor);
        assert_eq!(response[22], VERSION.build);
        assert_eq!(response[23], CAPABILITIES);
        let channel = u32::from_be_bytes(response[15..19].try_into().unwrap());
        engine.packet_sent();
        channel
    }

    #[test]
    fn advertised_cbor_only_transport_rejects_msg() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITY_CBOR | CAPABILITY_NMSG);
        let channel = allocate(&mut engine);
        let mut packet = request_packet(channel, Command::Cbor, &[0]);
        packet[4] = 0x83; // CTAPHID_MSG
        assert_eq!(engine.ingest(&packet, 1), Event::None);
        let reply = engine.next_packet().unwrap();
        assert_eq!(reply[4], Command::Error as u8 | 0x80);
        assert_eq!(reply[7], TransportError::InvalidCommand as u8);
    }

    #[test]
    fn malformed_usb_reports_abort_without_poisoning_the_next_request() {
        for length in [0, 1, 63, 65] {
            for awaiting_presence in [false, true] {
                let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
                let channel = allocate(&mut engine);
                if awaiting_presence {
                    engine.ingest(&request_packet(channel, Command::Cbor, &[4]), 1);
                    engine.keepalive(KeepaliveStatus::UserPresenceNeeded);
                }
                assert_eq!(
                    engine.ingest_report(&[0; 65][..length], 2),
                    (Event::None, true)
                );
                assert!(engine.request_payload().is_none());
                assert!(engine.next_packet().is_none());
                assert_eq!(engine.reply_cbor(&[0]), Err(ReplyError::NoPendingRequest));
                let channel = allocate(&mut engine);
                let (event, interrupted) =
                    engine.ingest_report(&request_packet(channel, Command::Cbor, &[4]), 3);
                assert!(matches!(event, Event::Cbor { .. }));
                assert!(!interrupted);
                assert_eq!(engine.request_payload(), Some(&[4][..]));
                engine.reply_cbor(&[0]).unwrap();
                assert!(engine.next_packet().is_some());
            }
        }
    }

    #[test]
    fn broadcast_init_allocates_channel_and_echoes_nonce() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        assert_ne!(channel, RESERVED_CHANNEL);
        assert_ne!(channel, BROADCAST_CHANNEL);
        assert!(engine.next_packet().is_none());
    }

    #[test]
    fn init_on_allocated_channel_resynchronizes_without_reallocation() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        let nonce = [0x33; 8];
        engine.ingest(&request_packet(channel, Command::Init, &nonce), 10);
        let response = engine.next_packet().unwrap();
        assert_eq!(response[..4], channel.to_be_bytes());
        assert_eq!(&response[7..15], &nonce);
        assert_eq!(
            u32::from_be_bytes(response[15..19].try_into().unwrap()),
            channel
        );
    }

    #[test]
    fn fragmented_ping_is_reassembled_and_fragmented_back() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        let mut payload = [0_u8; 80];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte = index as u8;
        }

        engine.ingest(&request_packet(channel, Command::Ping, &payload), 10);
        assert!(engine.next_packet().is_none());
        engine.ingest(
            &continuation_packet(channel, 0, &payload[INIT_PAYLOAD_SIZE..]),
            11,
        );

        let first = engine.next_packet().unwrap();
        assert_eq!(first[4], Command::Ping as u8 | 0x80);
        assert_eq!(&first[7..], &payload[..INIT_PAYLOAD_SIZE]);
        engine.packet_sent();
        let second = engine.next_packet().unwrap();
        assert_eq!(second[4], 0);
        assert_eq!(&second[5..28], &payload[INIT_PAYLOAD_SIZE..]);
        assert!(second[28..].iter().all(|byte| *byte == 0));
        engine.packet_sent();
        assert!(engine.next_packet().is_none());
    }

    #[test]
    fn wrong_continuation_sequence_returns_error() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        engine.ingest(&request_packet(channel, Command::Ping, &[0xaa; 80]), 10);
        engine.ingest(&continuation_packet(channel, 1, &[0xbb; 23]), 11);
        let response = engine.next_packet().unwrap();
        assert_eq!(response[4], Command::Error as u8 | 0x80);
        assert_eq!(response[7], TransportError::InvalidSequence as u8);
    }

    #[test]
    fn fragmented_request_times_out() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        engine.ingest(&request_packet(channel, Command::Ping, &[0xaa; 80]), 10);
        engine.expire(10 + RECEIVE_TIMEOUT_MS + 1);
        let response = engine.next_packet().unwrap();
        assert_eq!(response[7], TransportError::Timeout as u8);
    }

    #[test]
    fn unallocated_channel_is_rejected() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        engine.ingest(&request_packet(42, Command::Ping, &[]), 0);
        let response = engine.next_packet().unwrap();
        assert_eq!(response[7], TransportError::InvalidChannel as u8);
    }

    #[test]
    fn cbor_request_can_receive_fragmented_reply() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        let request = [0x04];
        assert_eq!(
            engine.ingest(&request_packet(channel, Command::Cbor, &request), 10),
            Event::Cbor { channel, length: 1 }
        );
        assert_eq!(engine.request_payload(), Some(request.as_slice()));
        assert!(engine.keepalive(KeepaliveStatus::Processing));
        let keepalive = engine.next_packet().unwrap();
        assert_eq!(keepalive[4], Command::Keepalive as u8 | 0x80);
        assert_eq!(keepalive[7], KeepaliveStatus::Processing as u8);
        engine.packet_sent();

        let response = [0x5c; 80];
        engine.reply_cbor(&response).unwrap();
        let first = engine.next_packet().unwrap();
        assert_eq!(first[4], Command::Cbor as u8 | 0x80);
        engine.packet_sent();
        let second = engine.next_packet().unwrap();
        assert_eq!(second[4], 0);
        assert_eq!(&second[5..28], &response[INIT_PAYLOAD_SIZE..]);
    }

    #[test]
    fn update_vendor_request_and_reply_keep_the_vendor_opcode() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        let request = [1, 2, 3, 4];
        assert_eq!(
            engine.ingest(&request_packet(channel, Command::Update, &request), 10),
            Event::Update { channel, length: 4 }
        );
        assert_eq!(engine.request_payload(), Some(request.as_slice()));
        engine.reply_update(&[0xaa, 0x55]).unwrap();
        let response = engine.next_packet().unwrap();
        assert_eq!(response[..4], channel.to_be_bytes());
        assert_eq!(response[4], Command::Update as u8 | 0x80);
        assert_eq!(response[5..7], 2_u16.to_be_bytes());
        assert_eq!(response[7..9], [0xaa, 0x55]);
    }

    fn begin_update(engine: &mut CtapHid<128>, channel: u32) {
        use crate::usb_update::{Operation, PROTOCOL_VERSION, SIGNATURE_SECTOR_SIZE};

        let mut request = [0; 48];
        request[0] = Operation::Begin as u8;
        request[1] = PROTOCOL_VERSION;
        request[2..6].copy_from_slice(&(2 * SIGNATURE_SECTOR_SIZE).to_le_bytes());
        request[6..38].fill(0x5a);
        request[38..42].copy_from_slice(&1_u32.to_le_bytes());
        request[42] = 5;
        request[43..].copy_from_slice(b"1.2.3");
        assert_eq!(
            engine
                .ingest_with_interruption(&request_packet(channel, Command::Update, &request), 10,),
            (
                Event::Update {
                    channel,
                    length: request.len(),
                },
                false,
            )
        );
        assert!(engine.keepalive(KeepaliveStatus::UserPresenceNeeded));
    }

    #[test]
    fn update_presence_wait_is_interrupted_by_init_without_overwriting_init_reply() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        begin_update(&mut engine, channel);
        let nonce = [0x77; 8];
        assert_eq!(
            engine.ingest_with_interruption(&request_packet(channel, Command::Init, &nonce), 11),
            (Event::None, true)
        );
        assert!(engine.request_payload().is_none());
        let mut payload = [crate::usb_update::StatusCode::UserPresenceRequired as u8];
        assert_eq!(
            complete_update(&mut payload, |bytes| engine.reply_update(bytes)),
            Ok(ReplyDisposition::Discarded)
        );
        assert_eq!(payload, [0]);
        let response = engine.next_packet().unwrap();
        assert_eq!(response[4], Command::Init as u8 | 0x80);
        assert_eq!(&response[7..15], &nonce);
        engine.packet_sent();
        assert!(engine.next_packet().is_none());
        begin_update(&mut engine, channel);
    }

    #[test]
    fn malformed_init_still_interrupts_update_presence_wait() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        begin_update(&mut engine, channel);
        assert_eq!(
            engine.ingest_with_interruption(&request_packet(channel, Command::Init, &[0; 7]), 11),
            (Event::None, true)
        );
        assert!(engine.request_payload().is_none());
        let mut payload = [crate::usb_update::StatusCode::UserPresenceRequired as u8];
        assert_eq!(
            complete_update(&mut payload, |bytes| engine.reply_update(bytes)),
            Ok(ReplyDisposition::Discarded)
        );
        assert_eq!(payload, [0]);
        let response = engine.next_packet().unwrap();
        assert_eq!(response[4], Command::Error as u8 | 0x80);
        assert_eq!(response[7], TransportError::InvalidLength as u8);
        engine.packet_sent();
        assert!(engine.next_packet().is_none());
        begin_update(&mut engine, channel);
    }

    #[test]
    fn cancel_interrupts_update_presence_wait_and_preserves_vendor_reply() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        begin_update(&mut engine, channel);
        assert_eq!(
            engine.ingest_with_interruption(&request_packet(channel, Command::Cancel, &[]), 11),
            (Event::Cancelled { channel }, true)
        );
        assert!(engine.request_payload().is_some());
        assert!(engine.next_packet().is_none());
        let mut payload = [crate::usb_update::StatusCode::UserPresenceRequired as u8];
        assert_eq!(
            complete_update(&mut payload, |bytes| engine.reply_update(bytes)),
            Ok(ReplyDisposition::Queued)
        );
        assert_eq!(payload, [0]);
        let response = engine.next_packet().unwrap();
        assert_eq!(response[4], Command::Update as u8 | 0x80);
        assert_eq!(
            response[7],
            crate::usb_update::StatusCode::UserPresenceRequired as u8
        );
        engine.packet_sent();
        assert!(engine.next_packet().is_none());
        begin_update(&mut engine, channel);
    }

    #[test]
    fn unrelated_or_malformed_cancel_does_not_interrupt_update_presence_wait() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        let other_channel = allocate(&mut engine);
        begin_update(&mut engine, channel);
        for packet in [
            request_packet(other_channel, Command::Cancel, &[]),
            request_packet(channel, Command::Cancel, &[0]),
        ] {
            assert_eq!(
                engine.ingest_with_interruption(&packet, 11),
                (Event::None, false)
            );
            assert!(engine.request_payload().is_some());
        }
        let mut payload = [crate::usb_update::StatusCode::UserPresenceRequired as u8];
        assert_eq!(
            complete_update(&mut payload, |bytes| engine.reply_update(bytes)),
            Ok(ReplyDisposition::Queued)
        );
        assert_eq!(payload, [0]);
    }

    #[test]
    fn init_discards_successful_cbor_completion_without_confirming_image() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        engine.ingest(&request_packet(channel, Command::Cbor, &[0x04]), 10);
        let nonce = [0x77; 8];
        assert_eq!(
            engine.ingest_with_interruption(&request_packet(channel, Command::Init, &nonce), 11),
            (Event::None, true)
        );
        let mut payload = [0x00, 0xa0];
        assert_eq!(
            complete_cbor(true, &mut payload, |bytes| engine.reply_cbor(bytes)),
            Ok(CborCompletion::Interrupted)
        );
        assert_eq!(payload, [0; 2]);
        let response = engine.next_packet().unwrap();
        assert_eq!(response[4], Command::Init as u8 | 0x80);
        assert_eq!(&response[7..15], &nonce);
        engine.packet_sent();
        assert!(engine.next_packet().is_none());
    }

    #[test]
    fn cbor_buffers_are_zeroized_after_use() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        let request = [0xa5; 80];
        engine.ingest(&request_packet(channel, Command::Cbor, &request), 10);
        engine.ingest(
            &continuation_packet(channel, 0, &request[INIT_PAYLOAD_SIZE..]),
            11,
        );
        assert_eq!(engine.request_payload(), Some(request.as_slice()));

        let response = [0x5c; 80];
        engine.reply_cbor(&response).unwrap();
        assert!(engine.request.iter().all(|byte| *byte == 0));
        while engine.next_packet().is_some() {
            engine.packet_sent();
        }
        assert!(engine.response.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn cancel_preserves_application_request_for_keepalive_cancel_reply() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        engine.ingest(&request_packet(channel, Command::Cbor, &[0x04]), 10);
        assert!(engine.keepalive(KeepaliveStatus::UserPresenceNeeded));
        assert_eq!(
            engine.ingest(&request_packet(channel, Command::Cancel, &[]), 11),
            Event::Cancelled { channel }
        );
        assert_eq!(engine.request_payload(), Some([0x04].as_slice()));
        assert!(engine.next_packet().is_none());

        engine.reply_cbor(&[0x2d]).unwrap();
        let response = engine.next_packet().unwrap();
        assert_eq!(response[..4], channel.to_be_bytes());
        assert_eq!(response[4], Command::Cbor as u8 | 0x80);
        assert_eq!(response[5..7], 1_u16.to_be_bytes());
        assert_eq!(response[7], 0x2d);
    }

    #[test]
    fn invalid_cancel_does_not_discard_application_request() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        engine.ingest(&request_packet(channel, Command::Cbor, &[0x04]), 10);
        assert_eq!(
            engine.ingest(&request_packet(channel, Command::Cancel, &[0]), 11),
            Event::None
        );
        assert_eq!(engine.request_payload(), Some([0x04].as_slice()));
        let response = engine.next_packet().unwrap();
        assert_eq!(response[4], Command::Error as u8 | 0x80);
        assert_eq!(response[7], TransportError::InvalidLength as u8);
    }

    #[test]
    fn cancel_on_another_channel_is_ignored() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let active_channel = allocate(&mut engine);
        let other_channel = allocate(&mut engine);
        engine.ingest(&request_packet(active_channel, Command::Cbor, &[0x04]), 10);
        assert_eq!(
            engine.ingest(&request_packet(other_channel, Command::Cancel, &[]), 11),
            Event::None
        );
        assert_eq!(engine.request_payload(), Some([0x04].as_slice()));
        assert!(engine.next_packet().is_none());
    }

    #[test]
    fn init_resynchronization_discards_pending_application_request() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        engine.ingest(&request_packet(channel, Command::Cbor, &[0x04]), 10);
        let nonce = [0x77; 8];
        assert_eq!(
            engine.ingest(&request_packet(channel, Command::Init, &nonce), 11),
            Event::None
        );
        assert_eq!(engine.request_payload(), None);
        assert!(engine.request.iter().all(|byte| *byte == 0));
        let response = engine.next_packet().unwrap();
        assert_eq!(response[..4], channel.to_be_bytes());
        assert_eq!(response[4], Command::Init as u8 | 0x80);
        assert_eq!(&response[7..15], &nonce);
        assert_eq!(
            u32::from_be_bytes(response[15..19].try_into().unwrap()),
            channel
        );
    }

    #[test]
    fn spurious_continuation_is_ignored() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        engine.ingest(&continuation_packet(7, 0, &[1, 2, 3]), 0);
        assert!(engine.next_packet().is_none());
    }

    #[test]
    fn failed_fragmented_request_is_zeroized() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        engine.ingest(&request_packet(channel, Command::Ping, &[0xaa; 80]), 10);
        engine.ingest(&continuation_packet(channel, 1, &[0xbb; 23]), 11);
        assert!(engine.request.iter().all(|byte| *byte == 0));
    }

    #[test]
    #[should_panic(expected = "CTAPHID buffer must fit an INIT response")]
    fn rejects_a_transport_buffer_that_cannot_fit_init() {
        let _ = CtapHid::<16>::new(VERSION, CAPABILITIES);
    }

    #[test]
    #[should_panic(expected = "CTAPHID buffer exceeds the continuation sequence space")]
    fn rejects_a_transport_buffer_larger_than_the_protocol_sequence_space() {
        let _ = CtapHid::<{ MAX_CTAPHID_MESSAGE_SIZE + 1 }>::new(VERSION, CAPABILITIES);
    }

    #[test]
    fn deterministic_packet_stream_does_not_break_transport_invariants() {
        let mut engine = CtapHid::<128>::new(VERSION, CAPABILITIES);
        let channel = allocate(&mut engine);
        let mut state = 0x6d2b_79f5_u32;

        for step in 0..20_000_u32 {
            let mut packet = [0_u8; PACKET_SIZE];
            for byte in &mut packet {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            if step % 2 == 0 {
                packet[..4].copy_from_slice(&channel.to_be_bytes());
            }

            let event = engine.ingest(&packet, step);
            if matches!(event, Event::Cbor { .. }) {
                let _ = engine.reply_cbor(&[0x7f]);
            }
            if step % 3 == 0 && engine.next_packet().is_some() {
                engine.packet_sent();
            }
            engine.expire(step.wrapping_add(RECEIVE_TIMEOUT_MS + 1));

            assert!(
                engine
                    .request_payload()
                    .is_none_or(|payload| payload.len() <= 128)
            );
            assert!(engine.receive.is_none_or(|receive| {
                receive.received <= receive.length && receive.length <= 128
            }));
            assert!(engine.transmit.is_none_or(|transmit| {
                transmit.offset <= transmit.length && transmit.length <= 128
            }));
        }
    }
}
