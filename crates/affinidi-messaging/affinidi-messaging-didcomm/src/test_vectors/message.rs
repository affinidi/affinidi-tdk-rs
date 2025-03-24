use crate::affinidi_messaging_didcomm::{Attachment, Message, MessageBuilder};

use super::common::{ALICE_DID, BOB_DID};
use lazy_static::lazy_static;
use serde_json::json;

lazy_static! {
    pub static ref MESSAGE_SIMPLE: Message = _message().finalize();
}

lazy_static! {
    pub static ref MESSAGE_MINIMAL: Message = Message::build(
        "1234567890".to_owned(),
        "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
        json!({}),
    )
    .finalize();
}

lazy_static! {
    pub static ref MESSAGE_FROM_PRIOR_FULL: Message = _message()
        .from_prior("eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2hLempIclpLcHhIcW1XOXgxQlZ4Z0taOW43TjFXWEUzalR0SkMyNlBZQVNwI3o2TWtoS3pqSHJaS3B4SHFtVzl4MUJWeGdLWjluN04xV1hFM2pUdEpDMjZQWUFTcCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtoS3pqSHJaS3B4SHFtVzl4MUJWeGdLWjluN04xV1hFM2pUdEpDMjZQWUFTcCIsInN1YiI6ImRpZDprZXk6YWxpY2UiLCJhdWQiOiIxMjMiLCJleHAiOjEyMzQsIm5iZiI6MTIzNDUsImlhdCI6MTIzNDU2LCJqdGkiOiJkZmcifQ.XF7C48Wbwgfrq5pdRDl7zxcGkEAJQ6TEDMMAMJ0UyIBafTnbLpkUnfMqt2dKmNLk5vAq0DKzrhTmiW1-BAVoBg".into())
        .finalize();
}

lazy_static! {
    pub static ref MESSAGE_FROM_PRIOR_MISMATCHED_SUB_AND_FROM: Message =
        Message::build(
            "1234567890".to_owned(),
            "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
            json!({"messagespecificattribute": "and its value"}),
        )
        .from(BOB_DID.to_owned())
        .to(ALICE_DID.to_owned())
        .created_time(1516269022)
        .expires_time(1516385931)
        .from_prior("eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2hLempIclpLcHhIcW1XOXgxQlZ4Z0taOW43TjFXWEUzalR0SkMyNlBZQVNwI3o2TWtoS3pqSHJaS3B4SHFtVzl4MUJWeGdLWjluN04xV1hFM2pUdEpDMjZQWUFTcCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtoS3pqSHJaS3B4SHFtVzl4MUJWeGdLWjluN04xV1hFM2pUdEpDMjZQWUFTcCIsInN1YiI6ImRpZDpleGFtcGxlOmFsaWNlIiwiYXVkIjoiMTIzIiwiZXhwIjoxMjM0LCJuYmYiOjEyMzQ1LCJpYXQiOjEyMzQ1NiwianRpIjoiZGZnIn0.XF7C48Wbwgfrq5pdRDl7zxcGkEAJQ6TEDMMAMJ0UyIBafTnbLpkUnfMqt2dKmNLk5vAq0DKzrhTmiW1-BAVoBg".into())
        .finalize();
}

lazy_static! {
    pub static ref MESSAGE_ATTACHMENT_BASE64: Message = _message()
        .attachment(
            Attachment::base64("qwerty".to_owned())
                .id("23".to_owned())
                .finalize(),
        )
        .finalize();
}

lazy_static! {
    pub static ref MESSAGE_ATTACHMENT_LINKS: Message = _message()
        .attachment(
            Attachment::links(
                ["1".to_owned(), "2".to_owned(), "3".to_owned()].into(),
                "qwerty".into(),
            )
            .id("23".to_owned())
            .finalize(),
        )
        .finalize();
}

lazy_static! {
    pub static ref MESSAGE_ATTACHMENT_JSON: Message = _message()
        .attachment(
            Attachment::json(json!({"foo": "bar", "links": [2, 3]}))
                .id("23".to_owned())
                .finalize(),
        )
        .finalize();
}

lazy_static! {
    pub static ref MESSAGE_ATTACHMENT_MULTI_1: Message = _message()
        .attachments(
            [
                Attachment::json(json!({"foo": "bar", "links": [2, 3]}))
                    .id("23".to_owned())
                    .finalize(),
                Attachment::base64("qwerty".to_owned())
                    .id("24".to_owned())
                    .finalize(),
                Attachment::links(
                    ["1".to_owned(), "2".to_owned(), "3".to_owned()].into(),
                    "qwerty".into(),
                )
                .id("25".to_owned())
                .finalize(),
            ]
            .into(),
        )
        .finalize();
}

lazy_static! {
    pub static ref MESSAGE_ATTACHMENT_MULTI_2: Message = _message()
        .attachments(
            [
                Attachment::links(
                    ["1".to_owned(), "2".to_owned(), "3".to_owned()].into(),
                    "qwerty".into(),
                )
                .id("23".to_owned())
                .finalize(),
                Attachment::base64("qwerty".to_owned())
                    .id("24".to_owned())
                    .finalize(),
                Attachment::links(
                    [
                        "1".to_owned(),
                        "2".to_owned(),
                        "3".to_owned(),
                        "4".to_owned(),
                    ]
                    .into(),
                    "qwerty2".into(),
                )
                .id("25".to_owned())
                .finalize(),
            ]
            .into(),
        )
        .finalize();
}

fn _message() -> MessageBuilder {
    Message::build(
        "1234567890".to_owned(),
        "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
        json!({"messagespecificattribute": "and its value"}),
    )
    .from(ALICE_DID.to_owned())
    .to(BOB_DID.to_owned())
    .created_time(1516269022)
    .expires_time(1516385931)
}
