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
