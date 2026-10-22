# Ant public source

This package contains the reviewed public boundary for Ant's Solana prediction-round protocol:

- `program/` is the native Solana program that records round state, sealed entries, settlement results, principal withdrawals, and SOL reward claims.
- `protocol/` is the shared binary codec and account decoder used by JavaScript clients and indexers.
- `wallet-client/` is a browser wallet module for configuration validation, network binding, sealed entry preparation, recovery-file acknowledgement, entry submission, and reveal submission.

The repository intentionally omits the private service, database schema and operations, provider configuration, signer material, local validator data, deployment records, and project automation. It contains no configured production program ID, ANT mint, administrator, agent, settlement authority, Pyth receiver policy, or RPC endpoint. Those identities are deployment-specific inputs that must be independently verified before a client is enabled.

Website: [meetant.fun](https://www.meetant.fun). Source: [MeetAnt/ant](https://github.com/MeetAnt/ant). X: [@MeetAntDotFun](https://x.com/MeetAntDotFun).

## Round mechanics

The program creates canonical PDAs for a single config, each round, each wallet's capsule, and each round vault authority. A round has an entry window, an observation boundary, a settlement deadline, a reveal window, and a claim window. Entries transfer ANT from the participant's supported SPL Token or Token-2022 account to the round vault and write a commitment plus bounded ciphertext into that wallet's capsule.

An entry commitment binds the program ID, network identity, mint, round ID, wallet, schema version, two forecast buckets, and a 32-byte salt. The ciphertext is stored separately from those plaintext answers. After the observation boundary, a participant reveals the answers and salt; the program checks the commitment before counting correct deposited weight. During normal operation, the participant can withdraw the original ANT deposit after observation. SOL rewards are funded before entry opens, split equally between the two questions, and distributed pro rata among correct revealed entries. Unclaimed rewards can be rolled into a later round after the claim window.

The protocol defines four return buckets for each SOL/USD and BTC/USD question: below -5%, -5% to below 0%, 0% to below 5%, and at least 5%. A missed settlement deadline permits deterministic cancellation of unresolved questions. The program records accepted oracle evidence in the round account.

## Sponsored Pyth observations

The selected production policy is `pyth-push` (mode 3). It reads two configured Pyth-sponsored source accounts, one for SOL/USD and one for BTC/USD. At entry close and observation end, a permissionless transaction captures a verified observation into a canonical Ant-owned checkpoint. Both publication and capture must occur within the fixed boundary through boundary + 120 seconds, inclusive. The program checks the pinned source address, receiver owner, feed ID, Full verification, positive price, confidence bound and supported exponent.

The first valid capture is immutable. It is the first observation accepted by the program, not a guarantee of the earliest published update or an exact-tick price; keeper timing can affect selection within the window. Settlement compares each asset's start and end checkpoints independently. A missed window cannot be repaired with a later price. That question remains unresolved until timeout cancellation at the settlement deadline. No paid historical-price subscription is required for this path; RPC availability, sponsored update availability, transaction fees and checkpoint rent still matter. Mode 2 historical pull settlement remains a separate codec and program path.

## Token identity

Initialization validates the actual mint and pins its token program. Mint and freeze authorities must be revoked. Supported Token-2022 mint extensions are self-referencing metadata with an immutable metadata pointer; token accounts may use immutable owner. Transfer fees, hooks, permanent delegates and other unsupported extensions are rejected. Each round records its own ANT vault and keeps its SOL rewards separate.

## Local operator trust

The selected operating model runs forecasting and operational workers locally. A trusted operator manages the forecast signing key; a matching signature identifies that key and is not hardware attestation. The public program checks signer identities and the on-chain rules. It does not prove the local worker's software or hardware integrity. Paid protected-runtime providers are optional, not a requirement of this deployment model.

## Source layout

```text
program/        Native Solana program, Cargo manifest, and locked dependency graph
protocol/       Node and browser codecs, PDA helpers, account decoders, and TypeScript types
wallet-client/  Browser-side wallet flow that imports the browser codec through @ant/protocol
```

`wallet-client` is deliberately a library module. A host application supplies its own user-facing interface and obtains a deployment-specific configuration from its own trusted service. Before it asks a wallet to connect, the client validates that configuration, pins the RPC genesis hash, checks canonical PDAs and token-account ownership, and requires a saved recovery file before an entry can be signed.

## Build and verification

Use Node 24 for the JavaScript packages. From this directory:

```sh
npm install
npm run test:protocol
```

The Solana program uses the dependency versions recorded in `program/Cargo.toml` and `program/Cargo.lock`. With the Solana SBF build tools installed, build from this repository:

```sh
cargo build-sbf --manifest-path program/Cargo.toml -- --locked
```

The program source in this package is the reviewed source to compare before a build. A compiled artifact, a local fixture identity, or a successful local simulation is not a deployment record.

## Integration inputs

A deploying integrator configures the following outside this package: the deployed program ID and executable bytecode hash; ANT mint and decimals; network identity and expected genesis hash; administrator, agent, and settlement authorities; the vault token accounts; Pyth receiver owner and exact feeds; the public RPC URL; and the production launch policy. The wallet client rejects malformed or mismatched values. These inputs remain unset here so the source can be reviewed without representing a particular deployment.

## License

No license file is included because no project license has been supplied for this source package. Do not assume a license grant until an owner selects and adds one.
