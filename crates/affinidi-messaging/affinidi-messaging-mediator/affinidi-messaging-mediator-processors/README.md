# Affinidi Messaging Processor

Tasks that can be run as a parallel task within the Mediator, or run externally as a stand-alone service.

This provides scalability by being able to distribute heavy tasks away from the core Mediator functionality

## Processors

### Message Expiry Cleanup

Cleans up expired messages by removing them from the database based on expiry headers

### Forwarding

Handles the routing/forwarding of a DIDComm message to a 3rd party Mediator/DIDComm-Agent **This is a work in progress**

## Crate Layout

As each processor can be either a binary or a library, the file layout can be confusing.

* src/lib - Contains the shared code for the library interfaces for each processor
  * src/lib/`processor` - contains specific code for each processor
* src/`processor` - contains the binary code to launch the processor as a standalone binary executable
* conf/`processor`.toml - contains the configuration for each processor
