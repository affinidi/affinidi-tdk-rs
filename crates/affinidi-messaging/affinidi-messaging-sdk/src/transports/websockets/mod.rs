/*!
Module for handling websocket connections to DIDComm Mediators

SDK --> Profile --> WebSocket --> Mediator

Roles:
   - SDK: The main SDK that the client interacts with
   - Profile: A DID profile that requires it's own connection to a mediator
   - WebSocket: WebSocket management + Profile Message Cache
   - Mediator: The DIDComm Mediator that the websocket connects to
*/

pub(crate) mod websocket;
pub(crate) mod ws_cache;
//pub(crate) mod ws_connection;
//pub mod ws_handler;
