use affinidi_messaging_didcomm::Message;

pub fn get_thread_id(msg: &Message) -> Option<String> {
    msg.thid.clone().or_else(|| Some(msg.id.clone()))
}

pub fn get_parent_thread_id(msg: &Message) -> Option<String> {
    msg.pthid.clone().or_else(|| get_thread_id(msg))
}

pub fn new_message_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;

    fn build_msg(id: &str, thid: Option<&str>, pthid: Option<&str>) -> Message {
        let mut b = Message::build(id.into(), "test/type".into(), json!({}));
        if let Some(t) = thid {
            b = b.thid(t.into());
        }
        if let Some(p) = pthid {
            b = b.pthid(p.into());
        }
        b.finalize()
    }

    #[test]
    fn get_thread_id_returns_thid_when_present() {
        let m = build_msg("id1", Some("thread-1"), None);
        assert_eq!(get_thread_id(&m), Some("thread-1".into()));
    }

    #[test]
    fn get_thread_id_falls_back_to_id() {
        let m = build_msg("msg-42", None, None);
        assert_eq!(get_thread_id(&m), Some("msg-42".into()));
    }

    #[test]
    fn get_parent_thread_id_returns_pthid_when_present() {
        let m = build_msg("id1", None, Some("parent-1"));
        assert_eq!(get_parent_thread_id(&m), Some("parent-1".into()));
    }

    #[test]
    fn get_parent_thread_id_falls_back_to_thread_id() {
        let m = build_msg("id1", Some("thread-1"), None);
        assert_eq!(get_parent_thread_id(&m), Some("thread-1".into()));
    }

    #[test]
    fn get_parent_thread_id_falls_back_to_id() {
        let m = build_msg("msg-99", None, None);
        assert_eq!(get_parent_thread_id(&m), Some("msg-99".into()));
    }

    #[test]
    fn new_message_id_is_unique() {
        let ids: HashSet<String> = (0..100).map(|_| new_message_id()).collect();
        assert_eq!(ids.len(), 100);
    }

    #[test]
    fn new_message_id_is_valid_uuid() {
        let id = new_message_id();
        uuid::Uuid::parse_str(&id).expect("should be valid UUID");
    }
}
