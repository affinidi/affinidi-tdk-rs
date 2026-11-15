# Affinidi CESR

## [0.1.8] - 2026-11-15

matter table matches keripy; number, tag and special codes (#1142)

**Wire-format change (R3.6).** Released as a patch: no signature changes,
nothing removed, and no caller in this workspace or affinidi-keri-rs uses a
corrected code. A 0.2 would also split the build: `affinidi-keri-core` on
crates.io requires affinidi-cesr 0.1 and exposes `CesrError` in its API.

- **Fixed:** fixed-size entries now match keripy `Matter.Sizes`
  (`src/keri/core/coring.py`, keripy `main` at `1625faf`):
  `J` is ECDSA_256k1_Seed (fs 44, was 24), `K` Ed448_Seed (fs 76, was 44),
  `L` X448 (fs 76, was 24), `1AAF` Tag4 (ss 4, was 0), `1AAH`
  X25519_Cipher_Salt (fs 100, was 92), and `1AAK`/`1AAL`/`1AAM` are
  Null/No/Yes (fs 4, no raw bytes; were 512-bit digests at fs 92). Text in
  the old sizes for these codes no longer parses, and keripy's now does.
- **Added:** the codes the table lacked: numbers `M` Short, `N` Big, `R`
  Tall, `S` Large, `T` Great, `U` Vast, `0H` Long; `O` X25519_Private, `P`
  X25519_Cipher_Seed, `Q` ECDSA_256r1_Seed, `a` Salt_256; labels `V` Label1
  (lead size 1) and `W` Label2; tags `X`/`Y`/`Z` (Tag3/7/11), `0J`–`0O`
  (Tag1/2/5/6/9/10), `1AAF` Tag4, `1AAN` Tag8; `b` GramHead; `1AAO` Escape,
  `1AAP` Empty; and the variable-size families `4C`–`9AAC`
  (X25519_Cipher), `4D`–`9AAD` (X25519_Cipher_QB64), `4E`–`9AAE`
  (X25519_Cipher_QB2), `4F`–`9AAF` (HPKEBase_Cipher) and `4H`–`9AAH`
  (Decimal). The table is checked against keripy's in a test.
- **Added: special soft values.** `Matter::with_soft(code, soft, raw)`
  builds a fixed-size code whose soft characters carry a value (the tags and
  GramHead), `Matter::soft()` returns it, and `from_qb64`/`from_qb2` read
  it, checking the `_` pre-pad of the odd-length tags.
  `tables::matter_xtra_size` gives that pre-pad size (keripy `xs`), and
  `CesrError::InvalidSoft` reports a missing or malformed soft value;
  `Matter::new` refuses a special code with it.
- **Fixed:** fixed-size encode and decode follow keripy's `_infil`/`_exfil`
  (pad `cs % 4` and the code's lead size), so codes with no raw bytes
  (`1AAK`, tags) and with a lead size (`V`) round-trip; the raw size is
  `(fs - hs - ss) * 3 / 4 - ls`. Encodings of the existing codes are
  unchanged. Tests use the vectors keripy's `test_coring.py` asserts.

## [0.1.7] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Workspace lints now include `unsafe_code = "deny"` (#1064).

## Changelog history

## [0.1.6] - 2026-11-15

variable-size primitives take their lead size from the code

**Behaviour change (R3.6)** (#1005). Released as a patch: it brings
variable-size primitives in line with the CESR spec and keripy, and no caller
in this workspace or affinidi-keri-rs uses a variable-size code.

- **Fixed:** the matter table gave lead size 0 to `5A`, `6A`, `5B`, `6B` and
  the big forms `8AAA`, `9AAA`, `8AAB`, `9AAB`. The lead size is part of the
  code: `4x`/`7AAx` 0, `5x`/`8AAx` 1, `6x`/`9AAx` 2 (keripy `StrB64_L0/L1/L2`,
  `Bytes_L0/L1/L2`). The comments ("String variable length base2", ...) are
  corrected too.
- **Fixed:** `Matter::from_qb64` / `from_qb2` remove exactly the code's lead
  bytes and refuse non-zero ones with `CesrError::NonCanonical`. They used to
  strip up to two leading zero bytes whatever the code said, so a raw value
  starting with `0x00` was silently shortened.
- **Changed:** `Matter::new` with a variable-size code picks the family
  member by lead size, as keripy does, and moves a value too long for a
  two-character count to the big form. `Matter::new("4B", <2 bytes>)` now has
  code `6B` (it emitted a `4B` that keripy reads as 3 bytes). `Matter::code()`
  returns the chosen code.
- The `matter` fuzz target now asserts the round trip for variable-size codes
  too.


## [0.1.5] - 2026-11-12

fixed-size primitives and indexed signatures refuse non-zero pad bits

A fixed-size primitive with a one- or two-character code has 2 or 4 pad bits
between the code and the raw bytes, and CESR requires them to be zero (keripy
refuses others with "non-zeroed prepad bits"). `Matter::from_qb64` and
`Matter::from_qb2` dropped those bits without looking at them. Up to 4 or 16
different texts therefore parsed to the same `Matter`, and `qb64()` gave back
only the canonical one. They now return the new `CesrError::NonCanonical`.
`Indexer::from_qb64` had the same gap for the 4 pad bits of `A`–`F` and
`2A`–`2F` signatures and now refuses them too. Codes whose code characters
fill whole bytes (`1AAA`…, `0A`/`0B` and `3A`/`3B` indexed signatures) have no
pad bits.

Decoding now zeroes the code characters before decoding, as keripy does,
and requires the bytes in front of the raw material to be zero.

Behaviour change (R3.6): a non-canonical text that used to parse is refused.
Encoders, this crate's included, never produce one, and every canonical text
parses to the same value as before. Variable-size primitives are unchanged
(their lead bytes are tracked separately). `CesrError` is `#[non_exhaustive]`,
so the new variant is additive. No new dependencies.

## [0.1.4] - 2026-11-10

indexed signature codes as keripy reads them

A fix to match keripy and the CESR specification. No signature's bytes change,
and no public signature changes; what `Indexer::ondex()` reports does, and
`Indexer::new` refuses a small both-lists code with an ondex that differs from
its index. A caller that relied on the swapped reading must change.


- **Both lists and current only were swapped.** `A`, `C`, `E`, `0A`, `2A`,
  `2C`, `2E`, `3A` mean the signing key is in both the current and the prior
  next-key list; `B`, `D`, `F`, `0B`, `2B`, `2D`, `2F`, `3B` mean current only
  (keripy `IndexedBothSigCodex` / `IndexedCurrentSigCodex`). This crate read
  them the other way round. The bytes of a signature do not change; what
  changes is `Indexer::ondex()`: `Some(index)` for `A`, `None` for `B`, and the
  encoded ondex for a big both-lists code.
- **Big indexed signatures parse.** Indexer codes have their own code lengths
  (keripy `Indexer.Bards`: `0`–`4` start two-character codes), and
  `Indexer::from_qb64` used the primitive table's, where `2…` is four
  characters, so every `2A…` was an unknown code. New `tables::indexer_hardage`.
- **The ondex is read and written as keripy does** (`tables::indexer_other_size`,
  keripy `os`): a big both-lists code carries its own ondex; a current-only
  code's ondex characters must be zero; a small both-lists code carries none,
  so `Indexer::new` refuses an ondex that differs from the index
  (`CesrError::InvalidIndex`, new). A current-only code carries none: one
  given to `Indexer::new` is dropped, as before.
- **Ed448 sizes** follow keripy: `0A`/`0B` are 156 characters, `3A`/`3B` 160.
- New `Indexer::is_current_only`, `tables::indexer_is_current_only`.

## [0.1.3] - 2026-06-16

guard qb64 parsers against non-ASCII input

- `Matter::from_qb64`, `Counter::from_qb64`, and `Indexer::from_qb64` now
  reject non-ASCII input up front (returning `CesrError::InvalidCharacter`)
  instead of panicking. qb64 is base64url (pure ASCII); the parsers slice the
  input on byte offsets derived from character counts, so a multi-byte UTF-8
  character could land mid-slice and panic with "byte index N is not a char
  boundary". Hardening only — no production caller is affected (the wire path
  uses the binary `from_qb2`). Patch bump; no behaviour change for ASCII input.

## [0.1.2] - 2026-06-14

non_exhaustive CesrError (W7 sweep)

- `CesrError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.
