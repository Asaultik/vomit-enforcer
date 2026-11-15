//! CTAP2 status codes: the first byte of every response.

pub const OK: u8 = 0x00;
pub const INVALID_COMMAND: u8 = 0x01;
pub const INVALID_PARAMETER: u8 = 0x02;
pub const INVALID_LENGTH: u8 = 0x03;
pub const CBOR_UNEXPECTED_TYPE: u8 = 0x11;
pub const INVALID_CBOR: u8 = 0x12;
pub const MISSING_PARAMETER: u8 = 0x14;
pub const CREDENTIAL_EXCLUDED: u8 = 0x19;
pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;
pub const UNSUPPORTED_OPTION: u8 = 0x2B;
pub const INVALID_OPTION: u8 = 0x2C;
pub const KEEPALIVE_CANCEL: u8 = 0x2D;
pub const NO_CREDENTIALS: u8 = 0x2E;
pub const NOT_ALLOWED: u8 = 0x30;
pub const PIN_INVALID: u8 = 0x31;
pub const PIN_BLOCKED: u8 = 0x32;
pub const PIN_AUTH_INVALID: u8 = 0x33;
pub const PIN_AUTH_BLOCKED: u8 = 0x34;
pub const PIN_NOT_SET: u8 = 0x35;
pub const PIN_REQUIRED: u8 = 0x36;
pub const PIN_POLICY_VIOLATION: u8 = 0x37;
/// Waiting for the user took too long.
pub const ACTION_TIMEOUT: u8 = 0x3A;
pub const INVALID_SUBCOMMAND: u8 = 0x3E;
pub const OTHER: u8 = 0x7F;
