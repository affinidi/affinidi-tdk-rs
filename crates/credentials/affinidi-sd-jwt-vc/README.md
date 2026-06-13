# affinidi-sd-jwt-vc

[![Crates.io](https://img.shields.io/crates/v/affinidi-sd-jwt-vc.svg)](https://crates.io/crates/affinidi-sd-jwt-vc)
[![Documentation](https://docs.rs/affinidi-sd-jwt-vc/badge.svg)](https://docs.rs/affinidi-sd-jwt-vc)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

> **⚠️ DEPRECATED — merged into [`affinidi-vc`](../affinidi-vc/).**
>
> SD-JWT VC is a credential format, so it now lives at `affinidi_vc::sd_jwt_vc`
> (in `affinidi-vc` 0.2+). This crate is a thin re-export kept for one release
> and will be removed. The public surface is unchanged — only the import path
> moved.

## Migrate

```toml
[dependencies]
- affinidi-sd-jwt-vc = "0.1"
+ affinidi-vc = "0.2"
```

```diff
- use affinidi_sd_jwt_vc::{SdJwtVc, issue, verify_temporal, SdJwtVcError};
+ use affinidi_vc::sd_jwt_vc::{SdJwtVc, issue, verify_temporal, SdJwtVcError};
```

See the [migration note](https://github.com/affinidi/affinidi-tdk-rs/blob/main/docs/migration/2026-06-sd-jwt-vc-merge.md).

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
