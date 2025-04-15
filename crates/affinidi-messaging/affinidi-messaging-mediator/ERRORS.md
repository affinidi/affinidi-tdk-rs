# Affinidi Messaging - Error Handling Documentation

Where ever possible, the Mediator reports errors using the [DIDComm Problem Report](https://identity.foundation/didcomm-messaging/spec/#problem-reports) format.

There are scenarios where the Mediator will fail to handle a message, and will not generate a error. These are silent drops of the message flow, and occurs to protect
the privacy of the overall system. It is up to the higher-level protocols to determine how to handle a message that has not been delivered.

## REST API

When using the REST based API methods, each request will return with the status of the transaction.

**NOTE:** *It is possible for the Mediator to return a 2xx status response, but the action did not complete*

## WebSocket Interface

WebSocket usage is a little more complicated due to it's fire and forget nature. When an Error does occur for a transaction over WebSocket, you may get a DIDComm Problem Report message back.

How you choose to handle these is left to the client side on how to handle these errors.

## Error Codes

| Error Code | HTTP Status Code | DIDComm Problem Code | Retryable? | Cause |
| ---------: | :--------------: | :------------------- | :--------: | :---- |
|  0 | 500 | e.p.\<descriptor> | No | Internal Mediator Errors caused by Processors. Should not leak to end-clients |
|  1 | 500 | e.p.me.res.storage.url | No | Incorrect Mediator database URL in mediator configuration |
|  2 | 500 | e.p.me.res.storage.config | No | Mediator database configuration is invalid |
|  3 | 503 | e.p.me.res.storage.connection | Yes | A connection to the mediator database couldn't be made |
|  4 | 503 | e.p.me.res.storage.pubsub.connection | Yes | Couldn't open database connection for pubsub |
|  5 | 503 | e.p.me.res.storage.pubsub.connection.receiver | Yes | Couldn't get receiver for pubsub connection |
|  6 | 503 | e.p.me.res.storage.info | Yes | Querying database information failed |
|  7 | 500 | e.p.me.res.storage.version | No | Cannot parse the database server version |
|  8 | 500 | e.p.me.res.storage.version.incompatible | No | The database server version is incorrect |
|  9 | 500 | e.p.me.res.storage.version.unknown | No | Couldn't determine database server version |
| 10 | 503 | w.m.database.message.delete.error | No | An error occurred while requesting to delete a message from the database |
| 11 | 503 | w.m.database.message.delete.status | No | delete function returned successfully, but was not OK |
| 12 | NA  | e.p.me.config.initialization | No | Mediator configuration issue during startup initialization |
| 13 | NA  | e.p.me.res.storage.schema | No | Could not set the database schema version (occurs during startup) |
| 14 | 503 | w.m.me.res.storage.error | Yes | Database transaction failure |
| 15 | 400 | w.m.database.admin.accounts.add.limit | No | Maximum 100 admin accounts can be added at a time |
| 16 | 400 | w.m.database.admin.accounts.strip.limit | No | Maximum 100 admin accounts can be stripped at a time |
| 17 | 400 | w.m.me.res.storage.parse | No | Could not parse data correctly. Storage error |
| 18 | 400 | w.m.database.account.remove.protected | No | Tried to remove a protected account (Mediator, Root-Admin) |
| 19 | 400 | w.m.message.serialize | No | Can not serialize DIDComm Message |
| 20 | 500 | e.p.database.session.invalid.state | No | Session state is invalid (restart auth process) |
| 21 | NA  | e.p.database.stats.parse | No | Can't parse mediator statistics records from database |
| 22 | 500 | e.p.database.message.metadata | No | Can't parse message metadata in database |
| 23 | 500 | e.p.me.res.storage.pubsub.clean_start | No | Initial reset of pubsub system failed on startup |
| 24 | 400 | e.p.me.res.storage.pubsub.publish | No | Couldn't parse pubsub record correctly |
| 25 | 403 | e.p.authentication.blocked | No | DID has been blocked from connecting to the mediator |
| 26 | 500 | w.m.database.acl.get.parse | No | Could not parse DID ACL FLags correctly |
| 27 | 400 | w.m.database.acl.get_dids.limit | No | Max 100 DIDs at a time can be fetched |
| 28 | 400 | e.p.authentication.response.parse | No | Couldn't parse authentication response from client to challenge (restart auth process) |
| 29 | 400 | e.p.authentication.response.from | No | Authentication response message is missing the from header. From must be included |
| 30 | 400 | e.p.message.type.incorrect | No | DIDComm Message type is missing or incorrect |
| 31 | 400 | e.p.message.expired | No | DIDComm Message has expired (or is missing expires_time header where it is required) |
| 32 | 400 | e.p.message.unpack | No | DIDComm Message unpack from envelope failed |
| 33 | 400 | e.p.authentication.session.mismatch | No | DIDs do not match throughout the authentication process |
| 34 | 400 | e.p.authentication.session.invalid | No | Authentication session is invalid due to a client misconfiguration |
| 35 | 500 | e.p.authentication.session.access_token | No | Couldn't create JWT Access Token |
| 36 | 500 | e.p.authentication.session.refresh_token | No | Couldn't create JWT Refresh Token |
| 37 | 400 | e.p.message.envelope.read | No | Couldn't read message envelope |
| 38 | 400 | e.p.authentication.session.refresh_token.parse | No | Couldn't parse JWT refresh_token |
| 39 | 400 | e.p.message.from.missing | No | DIDComm message is missing a `from` header, required for this transaction |
| 40 | 403 | e.p.authorization.local | No | DID is not local to the mediator, delivery rejected |
| 41 | 400 | e.p.api.inbox_fetch.limit | No | Invalid number of messages requested to retrieve  (1 - 100)|
| 42 | 400 | e.p.api.inbox_fetch.start_id | No | Invalid start_id. Must be a UNIX EPOCH timestamp in milliseconds + `-(0-999)` |
| 43 | 400 | e.p.api.message_delete.limit | No | Invalid number of messages to delete. Max 100 |
| 44 | 403 | e.p.authorization.send | No | DID does have authorization to send messages |
| 45 | 403 | e.p.authorization.permission | No | DID does have permission to access the requested resource |
| 46 | 500 | e.p.oob.store | No | Could not store Out-Of-Band (OOB) invitation |
| 47 | 500 | e.p.message.pack | No | Couldn't pack DIDComm message |
| 48 | 500 | e.p.me.did.missing | No | Mediator DID Document configuration is missing |
| 49 | 400 | w.m.protocol.pickup.return_route | No | Message Pickup Protocol message missing or incorrect `return_route` field |
| 50 | 400 | w.m.message.anonymous | No | DIDComm message appears to be anonymous, yet this transaction will not allow for an anonymous message |
| 51 | 400 | w.m.message.to | No | There was a problem with the message to: header. |
| 52 | 403 | e.p.authorization.did.session_mismatch | No | Message DID and Session DID do not match for a transaction where they should be matching |
| 53 | 400 | w.m.protocol.pickup.delivery_request.limit | No | Limit must be between 1 and 100 |
| 54 | 400 | w.m.protocol.pickup.parse | No | Couldn't parse message body correctly |
| 55 | 500 | e.p.protocol.pickup.live_streaming | No | An error occurred with enabling/disabling live streaming |
| 56 | 400 | w.m.protocol.forwarding.next.missing | No | Forwarding message is missing next field |
| 57 | 400 | w.m.protocol.forwarding.parse | No | Couldn't parse forwarding message body |
| 58 | 403 | e.p.authorization.receive_forwarded | No | Recipient isn't accepting forwarded messages |
| 59 | 400 | w.m.protocol.forwarding.attachments.missing | No | There were no attachments for this forward message |
| 60 | 403 | e.p.authorization.send_forwarded | No | Sender isn't allowed to send forwarded messages |
| 61 | 503 | e.p.limits.queue.sender | Yes | Sender has too many messages waiting to be delivered |
| 62 | 503 | e.p.limits.queue.recipient | Yes | Recipient has too many messages waiting to be delivered |
| 63 | 400 | w.m.protocol.forwarding.attachments.too_many | No | Forwarded message has too many attachments |
| 64 | 503 | e.p.me.res.forwarding.queue.limit | Yes | Mediator forwarding queue is at max limit, try again later |
| 65 | 400 | w.m.protocol.forwarding.delay_milli | No | Forward delay_milli field isn't valid |
| 66 | 500 | e.p.me.not_implemented | No | Feature is not implemented by the mediator |
| 67 | 400 | w.m.protocol.forwarding.attachments.json.invalid | No | JSON schema for attachment is incorrect |
| 68 | 400 | w.m.protocol.forwarding.attachments.base64 | No | Couldn't decode base64 attachment |
| 69 | 403 | e.p.authorization.receive_anon | No | Recipient isn't accepting anonymous messages |
| 70 | 403 | w.m.protocol.forwarding.next.mediator.self | No | Forwarded next hop is the same mediator. Not allowed due to creating loops |
| 71 | 403 | w.m.direct_delivery.denied | No | Mediator is not accepting direct delivery of DIDComm messages. They must be wrapped in a forwarding envelope |
| 72 | 403 | w.m.direct_delivery.recipient.unknown | No | Direct Delivery Recipient is not known on this Mediator |
| 73 | 403 | e.p.authorization.access_list.denied | No | Delivery blocked due to ACLs (access_list denied) |
| 74 | 500 | e.p.did.resolve | Maybe | DID could not be resolved |
| 75 | 400 | e.p.message.recipients.missing | No | There are no recipients for this message |
| 76 | 400 | e.p.message.recipients.too_many | No | There are too many recipients for this message |
| 77 | 500 | e.p.me.storage.message.error | No | There was in internal error when storing the message |
| 78 | 500 | e.p.me.res.storage.pubsub.subscribe | Yes | Couldn't subscribe to pubsub channel |
