// Credo interop harness for `affinidi-messaging-didcomm-v1`.
//
// Run via `run.mjs`, never directly — the native askar backend must be
// registered before any Credo module is evaluated. See `run.mjs`.
//
// Direction 1 (Credo -> Rust): drives a real Credo agent's
// `DidCommEnvelopeService.packMessage` and writes the envelopes to the crate's
// committed fixtures, which `tests/credo_interop.rs` then opens in CI.
//
// Direction 2 (Rust -> Credo): if `rust-envelopes.json` is present, opens each
// of this crate's envelopes with Credo's own decryption path.
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { Agent, Kms, TypedArrayEncoder } from '@credo-ts/core'
import { AskarModule, transformSeedToPrivateJwk } from '@credo-ts/askar'
import { DidCommEnvelopeService, DidCommModule } from '@credo-ts/didcomm'
import { agentDependencies } from '@credo-ts/node'
import { askar } from '@openwallet-foundation/askar-nodejs'

const BASIC_MESSAGE = 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message'

/** Committed fixtures consumed by the crate's `tests/credo_interop.rs`. */
const FIXTURES_PATH = new URL(
  '../../crates/messaging/affinidi-messaging-didcomm-v1/tests/fixtures/credo.json',
  import.meta.url
)
/**
 * Written by:
 *   cargo test -p affinidi-messaging-didcomm-v1 --test credo_interop \
 *       -- --ignored emit_envelopes_for_credo
 */
const RUST_ENVELOPES_PATH = new URL('./rust-envelopes.json', import.meta.url)
const RESULTS_PATH = new URL('./credo-unpack-results.json', import.meta.url)

const agent = new Agent({
  config: { label: 'v1-interop-fixtures' },
  dependencies: agentDependencies,
  modules: {
    askar: new AskarModule({ askar, store: { id: 'v1-fixtures', key: 'v1-fixtures-key' } }),
    didcomm: new DidCommModule({}),
  },
})
await agent.initialize()

const ctx = agent.context
const kms = ctx.dependencyManager.resolve(Kms.KeyManagementApi)
const svc = ctx.dependencyManager.resolve(DidCommEnvelopeService)

/** Import an Ed25519 key from a fixed seed, returning what both sides need. */
async function party(name, seedByte) {
  const { privateJwk } = transformSeedToPrivateJwk({
    seed: Buffer.alloc(32, seedByte),
    type: { kty: 'OKP', crv: 'Ed25519' },
  })
  const { keyId, publicJwk } = await kms.importKey({ privateJwk })
  const jwk = Kms.PublicJwk.fromUnknown(publicJwk)
  jwk.keyId = keyId

  return {
    name,
    keyId,
    jwk,
    // The OKP `d` parameter is the raw Ed25519 seed, which is what the Rust
    // side needs to reconstruct an identical identity.
    signingKeyHex: Buffer.from(privateJwk.d, 'base64url').toString('hex'),
    verkeyBase58: TypedArrayEncoder.toBase58(jwk.publicKey.publicKey),
  }
}

const alice = await party('alice', 1)
const bob = await party('bob', 2)
const mediator = await party('mediator', 3)
const everyone = [alice, bob, mediator]

/** Credo's packMessage takes a DidCommMessage; duck-type the one method it uses. */
const payload = (json) => ({ toJSON: () => json })

const plaintext = {
  '@type': BASIC_MESSAGE,
  '@id': '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
  '~thread': { thid: 'thread-1', pthid: 'parent-1' },
  '~l10n': { locale: 'en' },
  sent_time: '2026-08-08T00:00:00Z',
  content: 'Your hovercraft is full of eels.',
}

// No ~thread decorator at all, pinning the absent-vs-defaulted thid case.
const plaintextUnthreaded = {
  '@type': BASIC_MESSAGE,
  '@id': 'a4f1c0de-0000-4000-8000-000000000001',
  content: 'no thread decorator',
}

const cases = [
  {
    name: 'authcrypt_basic_message',
    description: 'authcrypt alice -> bob, full ~thread decorator',
    envelope: await svc.packMessage(ctx, payload(plaintext), {
      recipientKeys: [bob.jwk],
      routingKeys: [],
      senderKey: alice.jwk,
    }),
    expectedPlaintext: plaintext,
    senderVerkeyBase58: alice.verkeyBase58,
    recipientVerkeyBase58: bob.verkeyBase58,
  },
  {
    name: 'anoncrypt_basic_message',
    description: 'anoncrypt -> bob, no sender',
    envelope: await svc.packMessage(ctx, payload(plaintext), {
      recipientKeys: [bob.jwk],
      routingKeys: [],
      senderKey: null,
    }),
    expectedPlaintext: plaintext,
    senderVerkeyBase58: null,
    recipientVerkeyBase58: bob.verkeyBase58,
  },
  {
    name: 'authcrypt_no_thread_decorator',
    description: 'authcrypt alice -> bob, ~thread absent entirely',
    envelope: await svc.packMessage(ctx, payload(plaintextUnthreaded), {
      recipientKeys: [bob.jwk],
      routingKeys: [],
      senderKey: alice.jwk,
    }),
    expectedPlaintext: plaintextUnthreaded,
    senderVerkeyBase58: alice.verkeyBase58,
    recipientVerkeyBase58: bob.verkeyBase58,
  },
  {
    name: 'authcrypt_multi_recipient',
    description: 'authcrypt alice -> bob AND mediator',
    envelope: await svc.packMessage(ctx, payload(plaintext), {
      recipientKeys: [bob.jwk, mediator.jwk],
      routingKeys: [],
      senderKey: alice.jwk,
    }),
    expectedPlaintext: plaintext,
    senderVerkeyBase58: alice.verkeyBase58,
    recipientVerkeyBase58: bob.verkeyBase58,
  },
  {
    name: 'authcrypt_forwarded_via_mediator',
    description: 'routingKeys: anoncrypt forward to mediator wrapping authcrypt alice -> bob',
    envelope: await svc.packMessage(ctx, payload(plaintext), {
      recipientKeys: [bob.jwk],
      routingKeys: [mediator.jwk],
      senderKey: alice.jwk,
    }),
    expectedPlaintext: plaintext,
    senderVerkeyBase58: alice.verkeyBase58,
    recipientVerkeyBase58: bob.verkeyBase58,
    forwardedTo: bob.verkeyBase58,
    mediatorVerkeyBase58: mediator.verkeyBase58,
  },
]

/**
 * Open an envelope through Credo's decryption path, with the recipient key
 * supplied rather than looked up.
 *
 * A faithful transcription of `DidCommEnvelopeService`'s private
 * `decryptDidcommV1Message`, minus one step. The real method begins with
 * `extractOurRecipientKeyWithKeyId`, which searches the agent's *created DID
 * records* for one containing the recipient key. That lookup is wallet state
 * management rather than wire format, and a bare agent built from imported keys
 * does not satisfy it — Credo cannot open even its **own** envelopes here
 * without it (verified separately). Supplying the key skips exactly that step.
 *
 * Everything that constitutes interop still runs through Credo and askar: the
 * protected-header parse, the alg/enc checks, the authcrypt sender+iv
 * requirement, ECDH-HSALSA20 + XSALSA20-POLY1305 for the sealed sender and the
 * wrapped CEK, and C20P with the base64url header as AAD for the content.
 */
async function unpackWithKnownKey(encryptedMessage, candidates) {
  const header = JSON.parse(Buffer.from(encryptedMessage.protected, 'base64url').toString())

  if (header.alg !== 'Anoncrypt' && header.alg !== 'Authcrypt') {
    throw new Error(`Unsupported pack algorithm: ${header.alg}`)
  }
  if (header.enc !== 'xchacha20poly1305_ietf') {
    throw new Error(`Unsupported enc algorithm: ${header.enc}`)
  }

  let recipient = null
  let recipientParty = null
  for (const entry of header.recipients) {
    const match = candidates.find((p) => p.verkeyBase58 === entry.header.kid)
    if (match) {
      recipient = entry
      recipientParty = match
    }
  }
  if (!recipient) throw new Error('No corresponding recipient key found')

  if (header.alg === 'Authcrypt' && (!recipient.header.sender || !recipient.header.iv)) {
    throw new Error('Sender and iv header values are required for Authcrypt')
  }

  let senderPublicJwk
  if (recipient.header.sender) {
    const { data } = await kms.decrypt({
      key: { keyAgreement: { algorithm: 'ECDH-HSALSA20', keyId: recipientParty.keyId } },
      decryption: { algorithm: 'XSALSA20-POLY1305' },
      encrypted: Buffer.from(recipient.header.sender, 'base64url'),
    })
    senderPublicJwk = Kms.PublicJwk.fromPublicKey({
      crv: 'Ed25519',
      kty: 'OKP',
      publicKey: TypedArrayEncoder.fromBase58(TypedArrayEncoder.toUtf8String(data)),
    })
  }

  const { data: contentEncryptionKey } = await kms.decrypt({
    decryption: {
      algorithm: 'XSALSA20-POLY1305',
      iv: recipient.header.iv ? Buffer.from(recipient.header.iv, 'base64url') : undefined,
    },
    encrypted: Buffer.from(recipient.encrypted_key, 'base64url'),
    key: {
      keyAgreement: {
        algorithm: 'ECDH-HSALSA20',
        keyId: recipientParty.keyId,
        externalPublicJwk: senderPublicJwk?.convertTo(Kms.X25519PublicJwk).toJson(),
      },
    },
  })

  const { data: message } = await kms.decrypt({
    decryption: {
      algorithm: 'C20P',
      iv: Buffer.from(encryptedMessage.iv, 'base64url'),
      tag: Buffer.from(encryptedMessage.tag, 'base64url'),
      aad: Buffer.from(encryptedMessage.protected, 'utf8'),
    },
    key: { privateJwk: { kty: 'oct', k: Buffer.from(contentEncryptionKey).toString('base64url') } },
    encrypted: Buffer.from(encryptedMessage.ciphertext, 'base64url'),
  })

  return {
    plaintextMessage: JSON.parse(Buffer.from(message).toString()),
    senderVerkeyBase58: senderPublicJwk
      ? TypedArrayEncoder.toBase58(senderPublicJwk.publicKey.publicKey)
      : null,
    recipientVerkeyBase58: recipientParty.verkeyBase58,
  }
}

// Self-check: Credo must reopen its own output through this path, or a green
// result for the Rust envelopes below would prove nothing.
for (const item of cases) {
  const opened = await unpackWithKnownKey(item.envelope, everyone)
  const isForward = item.name === 'authcrypt_forwarded_via_mediator'
  const expected = isForward ? null : JSON.stringify(item.expectedPlaintext)
  if (expected && JSON.stringify(opened.plaintextMessage) !== expected) {
    throw new Error(`self-check failed for ${item.name}`)
  }
}
console.log('self-check: Credo reopened all of its own envelopes')

const fixtures = {
  generator: {
    credo: '0.6.3',
    askar: '0.4.3',
    note: 'Generated by interop/didcomm-v1 — do not hand-edit.',
  },
  parties: everyone.map((p) => ({
    name: p.name,
    signingKeyHex: p.signingKeyHex,
    verkeyBase58: p.verkeyBase58,
  })),
  cases,
}
writeFileSync(FIXTURES_PATH, `${JSON.stringify(fixtures, null, 2)}\n`)
console.log(`wrote ${cases.length} Credo-generated cases`)

// --- reverse direction: Credo opens envelopes this crate produced ------------

if (existsSync(RUST_ENVELOPES_PATH)) {
  const rust = JSON.parse(readFileSync(RUST_ENVELOPES_PATH, 'utf8'))
  const results = []

  for (const item of rust.cases) {
    try {
      const opened = await unpackWithKnownKey(item.envelope, everyone)
      results.push({ name: item.name, ok: true, ...opened })
    } catch (error) {
      results.push({ name: item.name, ok: false, error: String(error?.message ?? error) })
    }
  }

  writeFileSync(RESULTS_PATH, `${JSON.stringify({ results }, null, 2)}\n`)
  const failed = results.filter((r) => !r.ok)
  console.log(`Credo opened ${results.length - failed.length}/${results.length} Rust envelopes`)
  for (const item of results.filter((r) => r.ok)) {
    console.log(
      `  ok ${item.name}: sender=${item.senderVerkeyBase58 ?? '<anonymous>'} ` +
        `type=${item.plaintextMessage['@type']}`
    )
  }
  for (const item of failed) console.error(`  FAILED ${item.name}: ${item.error}`)
  if (failed.length) process.exitCode = 1
} else {
  console.log('no rust-envelopes.json — skipping the Rust -> Credo direction')
}

await agent.shutdown()
