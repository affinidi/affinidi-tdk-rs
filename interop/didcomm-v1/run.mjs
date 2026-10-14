// Entry point. Loads and registers the native askar backend BEFORE any Credo
// module is evaluated, then hands off to the generator.
//
// This two-stage load is not ceremony. Credo's ESM build imports `askar` as a
// named export from the CJS `askar-shared` package, and that binding is
// snapshotted when the module is first evaluated. `registerAskar` assigns to
// `exports.askar` at runtime, so registering *after* Credo has been imported
// leaves Credo holding `undefined` and failing deep inside the KMS with
// "Cannot read properties of undefined (reading 'keyGetJwkSecret')".
import { askar, registerAskar } from '@openwallet-foundation/askar-nodejs'

registerAskar({ askar })

await import('./generate.mjs')
