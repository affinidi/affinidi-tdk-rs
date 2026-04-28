/*!
 * Error Code Registry for the Affinidi Messaging Mediator.
 *
 * All error codes are defined here as constants with documented semantics.
 * Use these constants instead of raw integers when constructing errors.
 *
 * ## Code Ranges
 *
 * | Range   | Category                  |
 * |---------|---------------------------|
 * | 1-9     | Infrastructure (database, config, version) |
 * | 10-13   | Configuration and initialization |
 * | 14      | Database operation error (generic) |
 * | 17-19   | Internal errors (parsing, version checks) |
 * | 25-26   | Authentication and session errors |
 * | 31-32   | Message validation (expiry, unpack) |
 * | 37      | Protocol/envelope errors |
 * | 44-45   | Authorization and ACL enforcement |
 * | 49-55   | Message Pickup protocol errors |
 * | 56-69   | Forwarding and routing errors |
 * | 71-73   | Direct delivery errors |
 * | 80-82   | ACL management errors |
 * | 90-94   | Advanced forwarding (queue, loops, streams) |
 */

// ── Infrastructure ──────────────────────────────────────────────────────

/// Database URL is invalid or malformed.
pub const DB_URL_INVALID: u16 = 1;

/// Could not read the database functions file (Lua scripts).
pub const DB_FUNCTIONS_FILE_ERROR: u16 = 2;

/// Could not open database connection for pub/sub.
pub const DB_PUBSUB_CONNECTION_ERROR: u16 = 4;

/// Could not get pub/sub receiver.
pub const DB_PUBSUB_RECEIVER_ERROR: u16 = 5;

/// Could not query database server info.
pub const DB_SERVER_INFO_ERROR: u16 = 6;

/// Could not parse database server version.
pub const DB_VERSION_PARSE_ERROR: u16 = 7;

/// Database version is incompatible.
pub const DB_VERSION_INCOMPATIBLE: u16 = 8;

/// Could not determine database version.
pub const DB_VERSION_UNKNOWN: u16 = 9;

/// Could not open database connection for blocking operations.
pub const DB_BLOCKING_CONNECTION_ERROR: u16 = 10;

/// Could not establish blocking database connection.
pub const DB_BLOCKING_ESTABLISH_ERROR: u16 = 11;

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration error (general: VTA startup, logging, parsing).
pub const CONFIG_ERROR: u16 = 12;

/// Could not set/get database SCHEMA_VERSION.
pub const DB_SCHEMA_VERSION_ERROR: u16 = 13;

/// Generic database operation error (Redis command failure).
/// This is the most common error code — used for all Redis operation failures.
pub const DB_OPERATION_ERROR: u16 = 14;

// ── Internal Errors ─────────────────────────────────────────────────────

/// Internal error (version parsing, schema state, unexpected state).
pub const INTERNAL_ERROR: u16 = 17;

/// Could not delete message — returned unexpected status.
pub const DB_DELETE_STATUS_ERROR: u16 = 18;

/// JSON serialization/deserialization error.
pub const PARSE_ERROR: u16 = 19;

/// Could not parse data from database response.
pub const DB_PARSE_ERROR: u16 = 21;

/// Could not parse message metadata from database.
pub const DB_METADATA_PARSE_ERROR: u16 = 22;

// ── Authentication ──────────────────────────────────────────────────────

/// DID is blocked — authentication denied.
pub const AUTH_DID_BLOCKED: u16 = 25;

/// Internal error parsing ACL hex string.
pub const ACL_PARSE_ERROR: u16 = 26;

// ── Message Validation ──────────────────────────────────────────────────

/// Message has expired (created_time too old for admin messages).
pub const MESSAGE_EXPIRED: u16 = 31;

/// Message unpack/decryption failed.
pub const MESSAGE_UNPACK_FAILED: u16 = 32;

// ── Protocol Errors ─────────────────────────────────────────────────────

/// Could not read DIDComm envelope or no protocol handler available.
pub const PROTOCOL_ERROR: u16 = 37;

// ── Authorization ───────────────────────────────────────────────────────

/// Sender DID is not authorized to send messages.
pub const AUTH_SEND_DENIED: u16 = 44;

/// Not authorized — general permission denied for operation.
pub const AUTH_PERMISSION_DENIED: u16 = 45;

// ── Message Pickup Protocol ─────────────────────────────────────────────

/// return_route header missing or incorrect.
pub const PICKUP_RETURN_ROUTE_ERROR: u16 = 49;

/// Anonymous message not allowed (from: header required).
pub const ANON_MESSAGE_ERROR: u16 = 50;

/// Invalid or missing to: header.
pub const INVALID_TO_HEADER: u16 = 51;

/// Recipient DID does not match session DID.
pub const SESSION_DID_MISMATCH: u16 = 52;

/// Limit must be between 1 and configured maximum.
pub const INVALID_LIMIT: u16 = 53;

/// Could not parse message body.
pub const MESSAGE_BODY_PARSE_ERROR: u16 = 54;

/// Could not send signal to streaming task.
pub const STREAMING_SIGNAL_ERROR: u16 = 55;

// ── Forwarding & Routing ────────────────────────────────────────────────

/// Forward message missing `next` field.
pub const FORWARD_MISSING_NEXT: u16 = 56;

/// Failed to parse forwarding message body.
pub const FORWARD_PARSE_ERROR: u16 = 57;

/// Recipient not accepting forwarded messages.
pub const FORWARD_RECIPIENT_DENIED: u16 = 58;

/// Missing attachments for forward message.
pub const FORWARD_MISSING_ATTACHMENTS: u16 = 59;

/// Sender not allowed to send forwarded messages.
pub const FORWARD_SENDER_DENIED: u16 = 60;

/// Sender queue is full (too many pending messages).
pub const SENDER_QUEUE_FULL: u16 = 61;

/// Recipient queue is full (too many pending messages).
pub const RECIPIENT_QUEUE_FULL: u16 = 62;

/// Too many attachments (exceeds configured limit).
pub const TOO_MANY_ATTACHMENTS: u16 = 63;

/// Mediator forwarding queue is at maximum capacity.
pub const FORWARD_QUEUE_FULL: u16 = 64;

/// Forward delay_milli field is invalid.
pub const FORWARD_INVALID_DELAY: u16 = 65;

/// Feature not yet supported (JWS/linked attachments).
pub const FEATURE_NOT_IMPLEMENTED: u16 = 66;

/// Invalid attachment data format.
pub const INVALID_ATTACHMENT: u16 = 67;

/// Failed to decode base64 attachment.
pub const ATTACHMENT_DECODE_ERROR: u16 = 68;

/// Recipient not accepting anonymous messages (ACL check).
pub const ANON_DELIVERY_DENIED: u16 = 69;

// ── Direct Delivery ─────────────────────────────────────────────────────

/// Mediator is not configured to accept direct delivery.
pub const DIRECT_DELIVERY_DISABLED: u16 = 71;

/// Direct delivery recipient is unknown.
pub const DIRECT_DELIVERY_UNKNOWN_RECIPIENT: u16 = 72;

/// Delivery blocked by access control list.
pub const ACCESS_LIST_DENIED: u16 = 73;

// ── ACL Management ──────────────────────────────────────────────────────

/// Non-admin account attempted ACL change without self-change permission.
pub const ACL_SELF_CHANGE_DENIED: u16 = 80;

/// Account message body could not be parsed (accounts protocol).
pub const ACCOUNT_PARSE_ERROR: u16 = 81;

/// ACL message body could not be parsed (ACLs protocol).
pub const ACL_MESSAGE_PARSE_ERROR: u16 = 82;

// ── Advanced Forwarding ─────────────────────────────────────────────────

/// Failed to enqueue message for remote forwarding.
pub const FORWARD_ENQUEUE_ERROR: u16 = 90;

/// Admin messages must include a created_time header.
pub const ADMIN_MISSING_CREATED_TIME: u16 = 91;

/// Access list batch must contain 1-100 entries.
pub const ACCESS_LIST_BATCH_SIZE_ERROR: u16 = 93;

/// Message exceeded maximum hop count (forwarding loop detected).
pub const FORWARD_LOOP_DETECTED: u16 = 94;

/// Tried to remove a protected account (Mediator or RootAdmin).
pub const PROTECTED_ACCOUNT_ERROR: u16 = 18;
