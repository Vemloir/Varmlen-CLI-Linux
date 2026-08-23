pub mod controller;
pub mod direct_dns;
pub mod dns;
pub mod lifecycle;
pub mod log_store;
pub mod nft;
pub mod protocol;
pub mod recovery;
pub mod server;
pub mod split;
pub mod state;
pub mod system;

#[cfg(test)]
mod tests {
    use crate::protocol::{
        decode_request_frame, encode_frame, validate_request, DaemonCommand, DaemonErrorCode,
        RequestEnvelope, MAX_FRAME_BYTES, PROTOCOL_VERSION,
    };
    use crate::server::parse_owner_uid;
    use crate::server::PeerPolicy;

    #[test]
    fn rejects_unknown_protocol_version() {
        let request = RequestEnvelope::new(PROTOCOL_VERSION + 1, 7, DaemonCommand::Status);
        assert_eq!(
            validate_request(&request),
            Err(DaemonErrorCode::UnsupportedVersion)
        );
    }

    #[test]
    fn peer_policy_accepts_only_configured_uid() {
        let policy = PeerPolicy::new(1000);
        assert!(policy.authorize(1000));
        assert!(!policy.authorize(1001));
        assert!(!policy.authorize(0));
    }

    #[test]
    fn protocol_frame_round_trips_with_operation_id() {
        let request = RequestEnvelope::new(PROTOCOL_VERSION, 41, DaemonCommand::Status);
        let bytes = encode_frame(&request).unwrap();
        let decoded = decode_request_frame(&bytes).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.operation_id, 41);
    }

    #[test]
    fn protocol_rejects_oversized_frame_before_json_parsing() {
        let bytes = vec![b' '; MAX_FRAME_BYTES + 1];
        assert_eq!(
            decode_request_frame(&bytes),
            Err(DaemonErrorCode::FrameTooLarge)
        );
    }

    #[test]
    fn daemon_owner_must_come_from_valid_pkexec_uid() {
        assert_eq!(parse_owner_uid(Some("1000")), Ok(1000));
        assert!(parse_owner_uid(Some("0")).is_err());
        assert!(parse_owner_uid(Some("../1000")).is_err());
        assert!(parse_owner_uid(None).is_err());
    }
}
