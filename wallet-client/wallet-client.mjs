import {
  PublicKey,
  SendTransactionError,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  Connection,
} from '@solana/web3.js';
import bs58 from 'bs58';
import {
  Buffer as TlockBuffer,
  HttpCachingChain,
  HttpChainClient,
  roundAt,
  timelockDecrypt,
  timelockEncrypt,
} from 'tlock-js';
import {decodeArmor} from 'tlock-js/age/armor.js';
import {
  CAPSULE_LEN,
  CONFIG_LEN,
  MAX_CIPHERTEXT,
  ROUND_LEN,
  SCHEMA_VERSION,
  TOKEN_PROGRAM_ID,
  capsuleCommitment,
  encodeClaim,
  encodeEnter,
  encodeReveal,
  encodeWithdraw,
  networkIdentity,
} from '@ant/protocol/browser';

export const MAX_TRANSACTION_BYTES = 1232;
export const ASSOCIATED_TOKEN_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
export const QUICKNET = Object.freeze({
  chainHash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
  publicKey: '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a',
  genesisTime: 1692803367,
  periodSeconds: 3,
  baseUrl: 'https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
});

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal: true});
const submittedTransactions = new WeakSet();
const RECOVERY_FORMAT = 'ant-capsule-recovery';

/** @typedef {'provider-unavailable'|'iframe-blocked'|'insecure-context'|'service-unavailable'|'configuration-invalid'|'wrong-network'|'wallet-mismatch'|'settlement-disabled'|'account-invalid'|'balance-insufficient'|'recovery-required'|'recovery-invalid'|'ciphertext-too-large'|'transaction-too-large'|'wallet-rejected'|'rpc-error'} ClientErrorCode */
/** @typedef {{state:'ready', wallet:string, network:string, genesisHash:string, config:object, provider:object, connection:object, drandClient:object}} ReadyClient */
/** @typedef {{state:'recovery-required', client:ReadyClient, recoveryFile:{name:string,type:string,bytes:Uint8Array,sha256:string}, draft:object}} RecoveryRequired */
/** @typedef {{state:'ready-to-sign', client:ReadyClient, recoveryReceipt:{sha256:string}, draft:object}} ReadyToSign */
/** @typedef {{state:'finalized'|'submitted', signature:string, slot:number|null, confirmationStatus:string|null, reconciled:boolean}} SubmissionState */

export class WalletClientError extends Error {
  /** @param {ClientErrorCode} code */
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'WalletClientError';
    this.code = code;
    this.details = details;
  }
}

const fail = (code, message, details) => { throw new WalletClientError(code, message, details); };
const bytes = value => value instanceof Uint8Array ? value : new Uint8Array(value);
const equalBytes = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
const hex = value => [...bytes(value)].map(value => value.toString(16).padStart(2, '0')).join('');
const fromHex = (value, name = 'hex value') => {
  if (typeof value !== 'string' || !/^[0-9a-f]+$/i.test(value) || value.length % 2) fail('recovery-invalid', `${name} is not valid hex`);
  return Uint8Array.from(value.match(/../g), pair => Number.parseInt(pair, 16));
};
const sha256 = async value => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(value)));
const publicKey = (value, name) => {
  try { return new PublicKey(value); }
  catch { return fail('configuration-invalid', `${name} is not a valid Solana public key`); }
};
const u64le = value => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
  return out;
};
const i64At = (data, offset) => new DataView(data.buffer, data.byteOffset, data.byteLength).getBigInt64(offset, true);
const u64At = (data, offset) => new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(offset, true);
const u32At = (data, offset) => new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(offset, true);
const asUnixSeconds = value => {
  const seconds = BigInt(value);
  if (seconds < 0n || seconds > BigInt(Number.MAX_SAFE_INTEGER)) fail('configuration-invalid', 'round timestamp is outside the supported range');
  return Number(seconds);
};

function assertBrowserSecurity(browser) {
  if (!browser) return;
  let framed = false;
  try { framed = browser.top !== browser.self; } catch { framed = true; }
  if (framed) fail('iframe-blocked', 'Wallet operations require a top-level browser window.');
  if (browser.isSecureContext !== true) fail('insecure-context', 'Wallet operations require a secure browser context.');
}

function assertQuicknetConfig(drand) {
  if (!drand?.activated) fail('configuration-invalid', 'Timelock encryption is not activated.');
  const actual = {
    chainHash: drand.chainHash,
    publicKey: drand.publicKey,
    genesisTime: Number(drand.genesisTime),
    periodSeconds: Number(drand.periodSeconds),
    baseUrl: String(drand.baseUrl || '').replace(/\/$/, ''),
  };
  for (const [key, expected] of Object.entries(QUICKNET)) {
    if (actual[key] !== expected) fail('configuration-invalid', `Pinned drand Quicknet ${key} does not match service configuration.`);
  }
  return actual;
}

function createQuicknetClient(drand) {
  const pinned = assertQuicknetConfig(drand);
  const options = {
    disableBeaconVerification: false,
    noCache: false,
    chainVerificationParams: {chainHash: pinned.chainHash, publicKey: pinned.publicKey},
  };
  const chain = new HttpCachingChain(pinned.baseUrl, options);
  return {client: new HttpChainClient(chain, options), info: {
    hash: pinned.chainHash,
    public_key: pinned.publicKey,
    genesis_time: pinned.genesisTime,
    period: pinned.periodSeconds,
    groupHash: '',
    schemeID: 'bls-unchained-g1-rfc9380',
    metadata: {beaconID: 'quicknet'},
  }};
}

async function fetchConfig(fetchImpl) {
  let response;
  try { response = await fetchImpl('/v1/config', {headers: {accept: 'application/json'}}); }
  catch (error) { fail('service-unavailable', 'Ant configuration could not be loaded.', {cause: error?.message}); }
  if (!response.ok) fail('service-unavailable', `Ant configuration returned HTTP ${response.status}.`);
  const body = await response.json();
  if (!body?.data || typeof body.data !== 'object') fail('service-unavailable', 'Ant configuration response is malformed.');
  return body.data;
}

/** Connects an injected wallet, verifies the service identity, and binds the RPC to its genesis hash before any account read or transaction. */
export async function connectProvider({
  provider = globalThis.window?.solana,
  fetchImpl = globalThis.fetch?.bind(globalThis),
  ConnectionClass = Connection,
  browser = globalThis.window,
  commitment = 'finalized',
} = {}) {
  assertBrowserSecurity(browser);
  if (!provider?.connect) fail('provider-unavailable', 'No compatible Solana wallet provider is available.');
  if (!fetchImpl) fail('service-unavailable', 'Fetch is unavailable.');
  const config = await fetchConfig(fetchImpl);
  if (config.schemaVersion !== SCHEMA_VERSION || !config.programId || !config.mint || config.tokenDecimals === null) {
    fail('configuration-invalid', 'Ant program, mint, and token decimals must be configured before wallet use.', {missing: config.readiness?.missing});
  }
  if (!config.publicRpcUrl || !config.expectedGenesisHash) fail('configuration-invalid', 'A credential-free RPC URL and pinned genesis hash are required.');
  let rpcUrl;
  try { rpcUrl = new URL(config.publicRpcUrl); } catch { fail('configuration-invalid', 'The public RPC URL is invalid.'); }
  const loopbackHttp = rpcUrl.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(rpcUrl.hostname) && config.network !== 'mainnet-beta';
  if ((rpcUrl.protocol !== 'https:' && !loopbackHttp) || rpcUrl.username || rpcUrl.password || rpcUrl.search || rpcUrl.hash) {
    fail('configuration-invalid', 'The browser RPC URL must be credential-free HTTPS, except loopback HTTP on a non-mainnet network.');
  }
  const expectedNetworkIdentity = await networkIdentity(config.network);
  if (hex(expectedNetworkIdentity) !== config.networkIdentity) fail('configuration-invalid', 'The service network identity is not canonical.');
  publicKey(config.programId, 'programId');
  publicKey(config.mint, 'mint');
  publicKey(config.tokenProgram, 'tokenProgram');
  if (config.tokenProgram !== TOKEN_PROGRAM_ID) fail('configuration-invalid', 'Only the pinned legacy SPL Token program is supported.');
  const drand = createQuicknetClient(config.drand);
  const connection = new ConnectionClass(config.publicRpcUrl, commitment);
  let genesisHash;
  try { genesisHash = await connection.getGenesisHash(); }
  catch (error) { fail('rpc-error', 'The Solana RPC genesis hash could not be read.', {cause: error?.message}); }
  if (genesisHash !== config.expectedGenesisHash) fail('wrong-network', 'The configured Solana RPC belongs to a different network.', {expected: config.expectedGenesisHash, actual: genesisHash});
  let connected;
  try { connected = await provider.connect(); }
  catch (error) { fail('wallet-rejected', 'Wallet connection was rejected.', {cause: error?.message}); }
  const walletKey = connected?.publicKey ?? provider.publicKey;
  if (!walletKey) fail('provider-unavailable', 'The wallet did not provide a public key.');
  const wallet = publicKey(walletKey, 'wallet').toBase58();
  return Object.freeze({state: 'ready', wallet, network: config.network, genesisHash, config, provider, connection, drandClient: drand.client, drandInfo: drand.info});
}

const pda = {
  config(programId) { return PublicKey.findProgramAddressSync([encoder.encode('config')], programId)[0]; },
  round(programId, roundId) { return PublicKey.findProgramAddressSync([encoder.encode('round'), u64le(roundId)], programId)[0]; },
  capsule(programId, roundId, wallet) { return PublicKey.findProgramAddressSync([encoder.encode('capsule'), u64le(roundId), wallet.toBytes()], programId)[0]; },
  vaultAuthority(programId, roundId) { return PublicKey.findProgramAddressSync([encoder.encode('vault-authority'), u64le(roundId)], programId)[0]; },
  associatedToken(owner, mint, tokenProgram) {
    return PublicKey.findProgramAddressSync([owner.toBytes(), tokenProgram.toBytes(), mint.toBytes()], publicKey(ASSOCIATED_TOKEN_PROGRAM_ID, 'associated token program'))[0];
  },
};

function decodeProgramConfig(info, programId) {
  if (!info || !info.owner.equals(programId)) fail('account-invalid', 'The protocol config account is missing or has the wrong owner.');
  const data = bytes(info.data);
  if (data.length !== CONFIG_LEN || data[0] !== 1 || data[1] !== 1) fail('account-invalid', 'The protocol config account has an unsupported layout.');
  return {networkIdentity: data.slice(5, 37), mint: new PublicKey(data.slice(37, 69)), settlementMode: data[165]};
}

function decodeRoundAccount(info, programId, expectedRoundId) {
  if (!info || !info.owner.equals(programId)) fail('account-invalid', 'The round account is missing or has the wrong owner.');
  const data = bytes(info.data);
  if (data.length !== ROUND_LEN || data[0] !== 2 || u64At(data, 2) !== BigInt(expectedRoundId)) fail('account-invalid', 'The round account has an unsupported identity or layout.');
  return {
    config: new PublicKey(data.slice(10, 42)),
    depositVault: new PublicKey(data.slice(42, 74)),
    entryOpensAt: i64At(data, 106),
    entryClosesAt: i64At(data, 114),
    observationEndsAt: i64At(data, 122),
    revealEndsAt: i64At(data, 138),
    claimEndsAt: i64At(data, 146),
  };
}

function decodeTokenAccount(info, tokenProgram) {
  if (!info || !info.owner.equals(tokenProgram)) fail('account-invalid', 'The token account is missing or has the wrong token program.');
  const data = bytes(info.data);
  if (data.length !== 165 || data[108] !== 1 || u32At(data, 72) !== 0 || u32At(data, 129) !== 0) fail('account-invalid', 'The token account must be initialized without delegate or close authority.');
  return {mint: new PublicKey(data.slice(0, 32)), owner: new PublicKey(data.slice(32, 64)), amount: u64At(data, 64)};
}

function validateMint(info, tokenProgram, decimals) {
  if (!info || !info.owner.equals(tokenProgram)) fail('account-invalid', 'The mint is missing or owned by the wrong token program.');
  const data = bytes(info.data);
  if (data.length !== 82 || data[45] !== 1 || data[44] !== decimals || u32At(data, 0) !== 0 || u32At(data, 46) !== 0) {
    fail('account-invalid', 'The mint layout or decimals do not match configuration.');
  }
}

async function readEntryAccounts(client, roundId, depositBaseUnits) {
  const programId = publicKey(client.config.programId, 'programId');
  const mint = publicKey(client.config.mint, 'mint');
  const tokenProgram = publicKey(client.config.tokenProgram, 'tokenProgram');
  const wallet = publicKey(client.wallet, 'wallet');
  const configAddress = pda.config(programId);
  const roundAddress = pda.round(programId, roundId);
  const capsuleAddress = pda.capsule(programId, roundId, wallet);
  const vaultAuthority = pda.vaultAuthority(programId, roundId);
  const source = pda.associatedToken(wallet, mint, tokenProgram);
  const vault = pda.associatedToken(vaultAuthority, mint, tokenProgram);
  let infos;
  try { infos = await client.connection.getMultipleAccountsInfo([configAddress, roundAddress, capsuleAddress, source, vault, mint], 'finalized'); }
  catch (error) { fail('rpc-error', 'Protocol accounts could not be read.', {cause: error?.message}); }
  const config = decodeProgramConfig(infos[0], programId);
  const round = decodeRoundAccount(infos[1], programId, roundId);
  if (infos[2]) fail('account-invalid', 'A capsule already exists for this wallet and round.');
  const sourceState = decodeTokenAccount(infos[3], tokenProgram);
  const vaultState = decodeTokenAccount(infos[4], tokenProgram);
  validateMint(infos[5], tokenProgram, client.config.tokenDecimals);
  const expectedIdentity = fromHex(client.config.networkIdentity, 'networkIdentity');
  if (!equalBytes(config.networkIdentity, expectedIdentity) || !config.mint.equals(mint)) fail('wrong-network', 'On-chain protocol configuration does not match the service network and mint.');
  if (client.network === 'mainnet-beta' && (client.config.settlementMode !== 'pyth' || config.settlementMode !== 2)) {
    fail('settlement-disabled', 'On-chain mainnet settlement mode does not match the enabled production Pyth mode.', {serviceMode: client.config.settlementMode, onchainMode: config.settlementMode});
  }
  if (!round.config.equals(configAddress) || !round.depositVault.equals(vault)) fail('account-invalid', 'Round vault configuration does not match canonical addresses.');
  if (!sourceState.mint.equals(mint) || !sourceState.owner.equals(wallet) || !vaultState.mint.equals(mint) || !vaultState.owner.equals(vaultAuthority)) fail('account-invalid', 'Token account mint or authority is invalid.');
  if (sourceState.amount < depositBaseUnits) fail('balance-insufficient', 'The connected wallet does not hold enough ANT for this deposit.', {available: sourceState.amount.toString(), required: depositBaseUnits.toString()});
  let solBalance, rent;
  try { [solBalance, rent] = await Promise.all([client.connection.getBalance(wallet, 'finalized'), client.connection.getMinimumBalanceForRentExemption(CAPSULE_LEN, 'finalized')]); }
  catch (error) { fail('rpc-error', 'Wallet SOL balance or capsule rent could not be read.', {cause: error?.message}); }
  if (solBalance <= rent) fail('balance-insufficient', 'The connected wallet needs enough SOL for capsule rent and transaction fees.', {lamports: solBalance, minimumRent: rent});
  return {programId, mint, tokenProgram, wallet, configAddress, roundAddress, capsuleAddress, vaultAuthority, source, vault, round, solBalance, rent};
}

function requireFundedNetworkReady(client) {
  if (client.network === 'mainnet-beta' && (client.config.productionSettlementEnabled !== true || client.config.publicLaunch !== true)) {
    fail('settlement-disabled', 'Funded mainnet entry is disabled until production settlement and public launch are activated.');
  }
}

function compactPreimage(answers, salt) {
  const out = new Uint8Array(36);
  new DataView(out.buffer).setUint16(0, SCHEMA_VERSION, true);
  out.set(answers, 2);
  out.set(salt, 4);
  return out;
}

function parseCompactPreimage(value) {
  const data = bytes(value);
  if (data.length !== 36 || new DataView(data.buffer, data.byteOffset, data.byteLength).getUint16(0, true) !== SCHEMA_VERSION || data[2] > 3 || data[3] > 3) {
    fail('recovery-invalid', 'The decrypted capsule preimage is invalid.');
  }
  return {answers: [data[2], data[3]], salt: data.slice(4)};
}

function unarmor(armored) {
  const binary = decodeArmor(armored);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

const binaryString = value => [...bytes(value)].map(value => String.fromCharCode(value)).join('');

function recoveryDocument({client, roundId, answers, salt, commitment, drandRound}) {
  return {
    format: RECOVERY_FORMAT,
    version: 1,
    schemaVersion: SCHEMA_VERSION,
    network: client.network,
    genesisHash: client.genesisHash,
    networkIdentity: client.config.networkIdentity,
    programId: client.config.programId,
    mint: client.config.mint,
    roundId: String(roundId),
    wallet: client.wallet,
    answers,
    salt: hex(salt),
    commitment: hex(commitment),
    drand: {chainHash: QUICKNET.chainHash, round: drandRound},
  };
}

function recoveryBytes(document) { return encoder.encode(`${JSON.stringify(document)}\n`); }

async function unsignedTransaction(client, instruction) {
  let lifetime;
  try { lifetime = await client.connection.getLatestBlockhash('finalized'); }
  catch (error) { fail('rpc-error', 'A recent Solana blockhash could not be read.', {cause: error?.message}); }
  const transaction = new Transaction({feePayer: publicKey(client.wallet, 'wallet'), recentBlockhash: lifetime.blockhash}).add(instruction);
  const serialized = transaction.serialize({requireAllSignatures: false, verifySignatures: false});
  if (serialized.length > MAX_TRANSACTION_BYTES) fail('transaction-too-large', `The transaction is ${serialized.length} bytes; Solana permits at most ${MAX_TRANSACTION_BYTES}.`, {bytes: serialized.length});
  return {transaction, lifetime, bytes: serialized.length};
}

/** Creates a canonical commitment, genuine Quicknet ciphertext, recovery file, and unsigned atomic SPL deposit transaction. */
export async function prepareCapsule(client, {roundId, answers, depositBaseUnits}) {
  if (client?.state !== 'ready') fail('configuration-invalid', 'A ready wallet client is required.');
  requireFundedNetworkReady(client);
  const id = BigInt(roundId);
  const deposit = BigInt(depositBaseUnits);
  if (id < 0n || deposit <= 0n) fail('configuration-invalid', 'Round and deposit must be positive integers.');
  if (!Array.isArray(answers) || answers.length !== 2 || answers.some(value => !Number.isInteger(value) || value < 0 || value > 3)) fail('configuration-invalid', 'Answers must contain two bucket values from 0 through 3.');
  const accounts = await readEntryAccounts(client, id, deposit);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const identity = fromHex(client.config.networkIdentity, 'networkIdentity');
  const commitment = await capsuleCommitment({programId: accounts.programId, networkIdentity: identity, mint: accounts.mint, roundId: id, wallet: accounts.wallet, answers, salt});
  const unlockTime = (asUnixSeconds(accounts.round.observationEndsAt) + QUICKNET.periodSeconds) * 1000;
  const drandRound = roundAt(unlockTime, client.drandInfo);
  let armored;
  try { armored = await timelockEncrypt(drandRound, TlockBuffer.from(compactPreimage(answers, salt)), client.drandClient); }
  catch (error) { fail('rpc-error', 'Quicknet timelock encryption failed.', {cause: error?.message}); }
  const ciphertext = unarmor(armored);
  if (ciphertext.length > MAX_CIPHERTEXT) fail('ciphertext-too-large', `The genuine Quicknet ciphertext is ${ciphertext.length} bytes, above the protocol limit of ${MAX_CIPHERTEXT}.`, {bytes: ciphertext.length, limit: MAX_CIPHERTEXT});
  const instructionData = await encodeEnter({depositBaseUnits: deposit, commitment, ciphertext});
  const instruction = new TransactionInstruction({programId: accounts.programId, keys: [
    {pubkey: accounts.wallet, isSigner: true, isWritable: true},
    {pubkey: accounts.configAddress, isSigner: false, isWritable: false},
    {pubkey: accounts.roundAddress, isSigner: false, isWritable: true},
    {pubkey: accounts.capsuleAddress, isSigner: false, isWritable: true},
    {pubkey: accounts.source, isSigner: false, isWritable: true},
    {pubkey: accounts.vault, isSigner: false, isWritable: true},
    {pubkey: accounts.mint, isSigner: false, isWritable: false},
    {pubkey: accounts.tokenProgram, isSigner: false, isWritable: false},
    {pubkey: SystemProgram.programId, isSigner: false, isWritable: false},
  ], data: instructionData});
  const unsigned = await unsignedTransaction(client, instruction);
  let fee;
  try { fee = (await client.connection.getFeeForMessage(unsigned.transaction.compileMessage(), 'finalized'))?.value; }
  catch (error) { fail('rpc-error', 'The capsule transaction fee could not be estimated.', {cause: error?.message}); }
  if (!Number.isSafeInteger(fee) || fee < 0) fail('rpc-error', 'The capsule transaction fee estimate is unavailable.');
  if (accounts.solBalance < accounts.rent + fee) fail('balance-insufficient', 'The connected wallet needs enough SOL for capsule rent and the estimated fee.', {lamports: accounts.solBalance, minimumRent: accounts.rent, estimatedFee: fee});
  const document = recoveryDocument({client, roundId: id, answers, salt, commitment, drandRound});
  const fileBytes = recoveryBytes(document);
  const recoveryHash = hex(await sha256(fileBytes));
  return /** @type {RecoveryRequired} */ ({
    state: 'recovery-required',
    client,
    recoveryFile: {name: `ant-round-${id}-${client.wallet.slice(0, 8)}.recovery.json`, type: 'application/json', bytes: fileBytes, sha256: recoveryHash},
    draft: {roundId: id.toString(), wallet: client.wallet, commitment: hex(commitment), ciphertext, drandRound, instruction, minimumRent: accounts.rent, transactionBytes: unsigned.bytes},
  });
}

/** Verifies that the exact recovery bytes presented for saving are the bytes prepared before signature. */
export async function acknowledgeRecoveryFile(prepared, savedBytes) {
  if (prepared?.state !== 'recovery-required') fail('recovery-required', 'A prepared recovery file is required before signing.');
  const digest = hex(await sha256(savedBytes));
  if (digest !== prepared.recoveryFile.sha256 || !equalBytes(bytes(savedBytes), prepared.recoveryFile.bytes)) fail('recovery-invalid', 'The saved recovery file does not match this capsule.');
  return /** @type {ReadyToSign} */ ({state: 'ready-to-sign', client: prepared.client, recoveryReceipt: {sha256: digest}, draft: prepared.draft});
}

/** Starts a browser download, then returns a state which can be passed to enterCapsule. */
export async function downloadRecoveryFile(prepared, browser = globalThis.window) {
  if (prepared?.state !== 'recovery-required') fail('recovery-required', 'A prepared recovery file is required before signing.');
  if (!browser?.document || !browser?.URL || typeof Blob === 'undefined') fail('recovery-required', 'The recovery file must be saved in a browser before signing.');
  const url = browser.URL.createObjectURL(new Blob([prepared.recoveryFile.bytes], {type: prepared.recoveryFile.type}));
  try {
    const anchor = browser.document.createElement('a');
    anchor.href = url;
    anchor.download = prepared.recoveryFile.name;
    anchor.rel = 'noopener';
    anchor.click();
  } finally { browser.URL.revokeObjectURL(url); }
  return acknowledgeRecoveryFile(prepared, prepared.recoveryFile.bytes);
}

async function submitWalletTransaction(client, transaction, lifetime) {
  if (submittedTransactions.has(transaction)) fail('rpc-error', 'This exact transaction was already submitted; reconcile its signature instead of retrying.');
  submittedTransactions.add(transaction);
  if (typeof client.provider.signTransaction !== 'function') fail('provider-unavailable', 'The wallet must support signing before direct RPC submission so ambiguous sends can be reconciled safely.');
  const requestedMessage = transaction.serializeMessage();
  let signed, wire, signature;
  try {
    signed = await client.provider.signTransaction(transaction);
  } catch (error) {
    if (error instanceof WalletClientError) throw error;
    fail('wallet-rejected', 'The wallet rejected the transaction signature request.', {cause: error?.message});
  }
  if (typeof signed?.serializeMessage !== 'function' || !equalBytes(bytes(signed.serializeMessage()), bytes(requestedMessage))) fail('wallet-mismatch', 'The wallet returned a signature for a different transaction message.');
  wire = signed.serialize();
  if (wire.length > MAX_TRANSACTION_BYTES) fail('transaction-too-large', `The signed transaction is ${wire.length} bytes; Solana permits at most ${MAX_TRANSACTION_BYTES}.`);
  const signatureBytes = signed.signatures?.[0]?.signature ?? signed.signature;
  if (!signatureBytes || signatureBytes.length !== 64) fail('wallet-rejected', 'The wallet did not attach the required payer signature.');
  signature = bs58.encode(signatureBytes);
  try {
    const rpcSignature = await client.connection.sendRawTransaction(wire, {skipPreflight: false, maxRetries: 0});
    if (rpcSignature !== signature) fail('rpc-error', 'The RPC returned a signature that does not match the signed transaction.', {expected: signature, actual: rpcSignature});
  } catch (sendError) {
    if (sendError instanceof WalletClientError) throw sendError;
    return reconcileSignature(client, signature, true, sendError, sendError instanceof SendTransactionError);
  }
  try {
    const confirmation = await client.connection.confirmTransaction({...lifetime, signature}, 'finalized');
    if (confirmation?.value?.err) fail('rpc-error', 'The transaction finalized with an error.', {signature, error: confirmation.value.err});
    return /** @type {SubmissionState} */ ({state: 'finalized', signature, slot: confirmation?.context?.slot ?? null, confirmationStatus: 'finalized', reconciled: false});
  } catch (confirmationError) {
    if (confirmationError instanceof WalletClientError) throw confirmationError;
    return reconcileSignature(client, signature, false, confirmationError);
  }
}

async function reconcileSignature(client, signature, submissionUncertain, originalError, definitiveSendFailure = false) {
  let status = null;
  try { status = (await client.connection.getSignatureStatuses([signature], {searchTransactionHistory: true}))?.value?.[0] ?? null; }
  catch { /* Preserve the exact signed signature and return an honest unresolved state. */ }
  if (status?.err) fail('rpc-error', 'The signed transaction failed.', {signature, error: status.err});
  if (status?.confirmationStatus === 'finalized') return {state: 'finalized', signature, slot: status.slot ?? null, confirmationStatus: status.confirmationStatus, reconciled: true, submissionUncertain: false};
  if (definitiveSendFailure && !status) fail('rpc-error', 'The RPC rejected the signed transaction before submission.', {signature, definitive: true, error: originalError?.transactionError ?? originalError?.message ?? null});
  return {state: 'submitted', signature, slot: status?.slot ?? null, confirmationStatus: status?.confirmationStatus ?? null, reconciled: true, submissionUncertain, originalError: originalError?.message ?? null};
}

/** Signs and sends only after the separate recovery-file state transition. */
export async function enterCapsule(ready) {
  if (ready?.state !== 'ready-to-sign') fail('recovery-required', 'Download and verify the recovery file before signing the deposit.');
  if (ready.draft.wallet !== ready.client.wallet) fail('wallet-mismatch', 'The connected wallet does not match the prepared capsule.');
  const fresh = await unsignedTransaction(ready.client, ready.draft.instruction);
  let fee, solBalance;
  try {
    [fee, solBalance] = await Promise.all([
      ready.client.connection.getFeeForMessage(fresh.transaction.compileMessage(), 'finalized').then(result => result?.value),
      ready.client.connection.getBalance(publicKey(ready.client.wallet, 'wallet'), 'finalized'),
    ]);
  } catch (error) { fail('rpc-error', 'Fresh transaction fee and wallet balance could not be checked before signing.', {cause: error?.message}); }
  if (!Number.isSafeInteger(fee) || fee < 0) fail('rpc-error', 'The fresh transaction fee estimate is unavailable.');
  if (solBalance < ready.draft.minimumRent + fee) fail('balance-insufficient', 'The connected wallet no longer has enough SOL for capsule rent and the current fee.', {lamports: solBalance, minimumRent: ready.draft.minimumRent, estimatedFee: fee});
  return submitWalletTransaction(ready.client, fresh.transaction, fresh.lifetime);
}

export function parseRecoveryFile(input) {
  let value;
  try { value = JSON.parse(typeof input === 'string' ? input : decoder.decode(bytes(input))); }
  catch { fail('recovery-invalid', 'The recovery file is not valid UTF-8 JSON.'); }
  if (value?.format !== RECOVERY_FORMAT || value.version !== 1 || value.schemaVersion !== SCHEMA_VERSION || !Array.isArray(value.answers) || value.answers.length !== 2 || value.answers.some(answer => !Number.isInteger(answer) || answer < 0 || answer > 3)) fail('recovery-invalid', 'The recovery file has an unsupported format.');
  const salt = fromHex(value.salt, 'recovery salt');
  const commitment = fromHex(value.commitment, 'recovery commitment');
  if (salt.length !== 32 || commitment.length !== 32) fail('recovery-invalid', 'Recovery salt and commitment must be 32 bytes.');
  return {...value, salt, commitment};
}

async function validateRecoveredDomain(client, recovered, {roundId, wallet = client.wallet, commitment} = {}) {
  const expectedRound = String(roundId ?? recovered.roundId);
  const expectedWallet = publicKey(wallet, 'wallet').toBase58();
  const fieldsMatch = recovered.network === client.network && recovered.genesisHash === client.genesisHash && recovered.networkIdentity === client.config.networkIdentity && recovered.programId === client.config.programId && recovered.mint === client.config.mint && recovered.roundId === expectedRound && recovered.wallet === expectedWallet && recovered.drand?.chainHash === QUICKNET.chainHash;
  if (!fieldsMatch) fail('wallet-mismatch', 'The recovery file belongs to a different network, program, round, mint, or wallet.');
  const canonical = await capsuleCommitment({programId: publicKey(recovered.programId, 'programId'), networkIdentity: fromHex(recovered.networkIdentity, 'networkIdentity'), mint: publicKey(recovered.mint, 'mint'), roundId: BigInt(recovered.roundId), wallet: publicKey(recovered.wallet, 'wallet'), answers: recovered.answers, salt: recovered.salt});
  if (!equalBytes(canonical, recovered.commitment) || commitment && hex(canonical) !== String(commitment).toLowerCase()) fail('recovery-invalid', 'The recovery file commitment does not match its contents.');
  return recovered;
}

/** Decrypts a public on-chain capsule after Quicknet emits its target beacon and checks its canonical commitment. */
export async function recoverCapsule(client, {ciphertext, roundId, wallet = client.wallet, commitment}) {
  let plain;
  try { plain = await timelockDecrypt(binaryString(ciphertext), client.drandClient); }
  catch (error) { fail('recovery-invalid', 'The capsule could not be decrypted from the verified Quicknet beacon.', {cause: error?.message}); }
  const recovered = parseCompactPreimage(plain);
  const canonical = await capsuleCommitment({programId: publicKey(client.config.programId, 'programId'), networkIdentity: fromHex(client.config.networkIdentity, 'networkIdentity'), mint: publicKey(client.config.mint, 'mint'), roundId: BigInt(roundId), wallet: publicKey(wallet, 'wallet'), answers: recovered.answers, salt: recovered.salt});
  if (hex(canonical) !== String(commitment).toLowerCase()) fail('recovery-invalid', 'Decrypted capsule commitment does not match the on-chain capsule.');
  return {state: 'recovered', roundId: String(roundId), wallet: publicKey(wallet, 'wallet').toBase58(), answers: recovered.answers, salt: recovered.salt, commitment: hex(canonical)};
}

async function actionAccounts(client, roundId) {
  const programId = publicKey(client.config.programId, 'programId');
  const wallet = publicKey(client.wallet, 'wallet');
  const mint = publicKey(client.config.mint, 'mint');
  const tokenProgram = publicKey(client.config.tokenProgram, 'tokenProgram');
  return {programId, wallet, mint, tokenProgram, configAddress: pda.config(programId), roundAddress: pda.round(programId, roundId), capsuleAddress: pda.capsule(programId, roundId, wallet), vaultAuthority: pda.vaultAuthority(programId, roundId)};
}

/** Reveals from either the saved recovery file or a successfully decrypted on-chain ciphertext. */
export async function revealCapsule(client, {roundId, recoveryFile, ciphertext, commitment}) {
  const id = BigInt(roundId);
  let recovered;
  if (recoveryFile !== undefined) {
    recovered = await validateRecoveredDomain(client, parseRecoveryFile(recoveryFile), {roundId: id, commitment});
  } else if (ciphertext !== undefined && commitment) {
    recovered = await recoverCapsule(client, {ciphertext, roundId: id, commitment});
  } else fail('recovery-required', 'A matching recovery file or decryptable on-chain capsule is required.');
  const accounts = await actionAccounts(client, id);
  const instruction = new TransactionInstruction({programId: accounts.programId, keys: [
    {pubkey: accounts.configAddress, isSigner: false, isWritable: false},
    {pubkey: accounts.roundAddress, isSigner: false, isWritable: true},
    {pubkey: accounts.capsuleAddress, isSigner: false, isWritable: true},
  ], data: encodeReveal({answers: recovered.answers, salt: recovered.salt})});
  const unsigned = await unsignedTransaction(client, instruction);
  return submitWalletTransaction(client, unsigned.transaction, unsigned.lifetime);
}

export async function withdrawPrincipal(client, {roundId}) {
  const id = BigInt(roundId);
  const accounts = await actionAccounts(client, id);
  const vault = pda.associatedToken(accounts.vaultAuthority, accounts.mint, accounts.tokenProgram);
  const destination = pda.associatedToken(accounts.wallet, accounts.mint, accounts.tokenProgram);
  const instruction = new TransactionInstruction({programId: accounts.programId, keys: [
    {pubkey: accounts.wallet, isSigner: true, isWritable: false},
    {pubkey: accounts.configAddress, isSigner: false, isWritable: false},
    {pubkey: accounts.roundAddress, isSigner: false, isWritable: false},
    {pubkey: accounts.capsuleAddress, isSigner: false, isWritable: true},
    {pubkey: vault, isSigner: false, isWritable: true},
    {pubkey: destination, isSigner: false, isWritable: true},
    {pubkey: accounts.mint, isSigner: false, isWritable: false},
    {pubkey: accounts.vaultAuthority, isSigner: false, isWritable: false},
    {pubkey: accounts.tokenProgram, isSigner: false, isWritable: false},
  ], data: encodeWithdraw()});
  const unsigned = await unsignedTransaction(client, instruction);
  return submitWalletTransaction(client, unsigned.transaction, unsigned.lifetime);
}

export async function claimReward(client, {roundId}) {
  const id = BigInt(roundId);
  const accounts = await actionAccounts(client, id);
  const instruction = new TransactionInstruction({programId: accounts.programId, keys: [
    {pubkey: accounts.wallet, isSigner: true, isWritable: true},
    {pubkey: accounts.roundAddress, isSigner: false, isWritable: true},
    {pubkey: accounts.capsuleAddress, isSigner: false, isWritable: true},
  ], data: encodeClaim()});
  const unsigned = await unsignedTransaction(client, instruction);
  return submitWalletTransaction(client, unsigned.transaction, unsigned.lifetime);
}
