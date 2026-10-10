# affinidi-messaging-mediator-common

Shared code for the Affinidi Messaging Mediator, its setup wizard, and its
processors:

- `types`: request and response types shared with clients. Take the crate
  with `default-features = false` to get only these.
- `store`: the `MediatorStore` storage trait and the Redis implementation.
- `secrets`: the `SecretStore` trait, the secret backends (`file://`,
  `keyring://`, AWS, GCP, Azure, Vault, `k8s://`), and the well-known entries
  the mediator keeps in them. See
  [docs/secrets-backend.md](../docs/secrets-backend.md).
- Errors, problem reports, and other helpers.

The `server` feature (default) enables everything above. The `secrets-*`
features enable the optional secret backends.
