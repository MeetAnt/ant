import {createHash} from 'node:crypto';

export const SCHEMA_VERSION=1;
export const MAX_CIPHERTEXT=512;
export const CONFIG_LEN=272;
export const ROUND_LEN=374;
export const CAPSULE_LEN=642;
export const TOKEN_PROGRAM_ID='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const INSTRUCTION=Object.freeze({initialize:0,createRound:1,fund:2,enter:3,settleLocalFixture:4,cancelTimeout:5,reveal:6,withdraw:7,claim:8,rollover:9,settlePyth:10});
export const BUCKET=Object.freeze({belowMinus5:0,minus5To0:1,zeroTo5:2,atLeast5:3,canceled:255});
export const ANT_ERRORS=Object.freeze({1:'invalid instruction',2:'invalid account',3:'missing signature',4:'wrong authority',5:'invalid state',6:'deadline',7:'replay',8:'invalid commitment',9:'arithmetic',10:'production settlement disabled',11:'invalid token'});
const DOMAIN=Buffer.from('ant-capsule-v1');
const asBuffer=value=>Buffer.from(value?.toBytes?.()??value);
const as32=(value,name='value')=>{const b=asBuffer(value);if(b.length!==32)throw Error(`${name} must be 32 bytes`);return b;};
const u16=value=>{const b=Buffer.alloc(2);b.writeUInt16LE(Number(value));return b;};
const u64=value=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(value));return b;};
const i64=value=>{const b=Buffer.alloc(8);b.writeBigInt64LE(BigInt(value));return b;};
const instruction=(tag,...parts)=>Buffer.concat([Buffer.from([tag]),...parts]);
const keyAt=(d,at)=>Buffer.from(d.subarray(at,at+32));
const hex=b=>Buffer.from(b).toString('hex');

export function encodeInitialize({networkIdentity,mint,agentAuthority,settlementAuthority,settlementMode,oracleOwner,solFeedId,btcFeedId,oracleMaxGapSeconds,oracleMaxConfidenceBps}){
  if(![0,1,2].includes(settlementMode))throw Error('settlementMode must be disabled(0), local-fixture(1), or pyth(2)');
  const base=[as32(networkIdentity,'networkIdentity'),as32(mint,'mint'),as32(agentAuthority,'agentAuthority'),as32(settlementAuthority,'settlementAuthority'),Buffer.from([settlementMode])];
  if(settlementMode===2){const gap=BigInt(oracleMaxGapSeconds);const bps=Number(oracleMaxConfidenceBps);if(gap<=0n||bps<1||bps>1000)throw Error('invalid Pyth gap or confidence bound');base.push(as32(oracleOwner,'oracleOwner'),as32(solFeedId,'solFeedId'),as32(btcFeedId,'btcFeedId'),u64(gap),u16(bps));}
  return instruction(0,...base);
}
export function encodeCreateRound({id,entryOpensAt,entryClosesAt,observationEndsAt,settlementDeadline,revealEndsAt,claimEndsAt,forecastCommitment}){
  return instruction(1,u64(id),i64(entryOpensAt),i64(entryClosesAt),i64(observationEndsAt),i64(settlementDeadline),i64(revealEndsAt),i64(claimEndsAt),as32(forecastCommitment,'forecastCommitment'));
}
export const encodeFund=amount=>instruction(2,u64(amount));
export function encodeEnter({depositBaseUnits,commitment,ciphertext}){const c=asBuffer(ciphertext);if(!c.length||c.length>MAX_CIPHERTEXT)throw Error(`ciphertext must be 1..${MAX_CIPHERTEXT} bytes`);const h=createHash('sha256').update(c).digest();return instruction(3,u64(depositBaseUnits),as32(commitment,'commitment'),h,u16(c.length),c);}
export const encodeSettleLocalFixture=(solBucket,btcBucket)=>{if(solBucket>3||btcBucket>3)throw Error('fixture buckets must be 0..3');return instruction(4,Buffer.from([solBucket,btcBucket]));};
export const encodeCancelTimeout=()=>instruction(5);
export function encodeReveal({answers,salt,schemaVersion=SCHEMA_VERSION}){if(answers?.length!==2||answers.some(v=>v<0||v>3))throw Error('answers must contain two buckets 0..3');return instruction(6,u16(schemaVersion),Buffer.from(answers),as32(salt,'salt'));}
export const encodeWithdraw=()=>instruction(7);
export const encodeClaim=()=>instruction(8);
export const encodeRollover=()=>instruction(9);
export const encodeSettlePyth=()=>instruction(10);

export function capsuleCommitment({programId,networkIdentity,mint,roundId,wallet,answers,salt,schemaVersion=SCHEMA_VERSION}){
  if(answers?.length!==2||answers.some(v=>v<0||v>3))throw Error('answers must contain two buckets 0..3');
  return createHash('sha256').update(Buffer.concat([DOMAIN,as32(programId,'programId'),as32(networkIdentity,'networkIdentity'),as32(mint,'mint'),u64(roundId),as32(wallet,'wallet'),u16(schemaVersion),Buffer.from(answers),as32(salt,'salt')])).digest();
}
export const networkIdentity=label=>createHash('sha256').update(`ant-network:${label}`).digest();
export function bucketForReturn(base,end){base=BigInt(base);end=BigInt(end);if(base<=0n||end<=0n)throw Error('prices must be positive');const scaled=(end-base)*100n;return scaled < -5n*base?0:scaled<0n?1:scaled<5n*base?2:3;}
export function statusForRound(round,now=Math.floor(Date.now()/1000)){now=BigInt(now);if(round.rolled||now>=round.claimEndsAt)return'closed';if(now>=round.revealEndsAt)return'claiming';if(now>=round.observationEndsAt&&round.settledMask===3)return'revealing';if(now>=round.observationEndsAt)return'awaiting-settlement';if(now>=round.entryClosesAt)return'observing';if(now>=round.entryOpensAt)return'accepting';return'prepared';}

export function decodeConfig(data){const d=asBuffer(data);if(d.length!==CONFIG_LEN||d[0]!==1||d[1]!==1)throw Error('invalid config account');const mode=d[165];if(mode>2)throw Error('invalid settlement mode');return{schemaVersion:d.readUInt16LE(3),networkIdentity:hex(d.subarray(5,37)),mint:keyAt(d,37),administrator:keyAt(d,69),agentAuthority:keyAt(d,101),settlementAuthority:keyAt(d,133),settlementMode:['disabled','local-fixture','pyth'][mode],productionSettlementEnabled:mode===2,oracleOwner:mode===2?keyAt(d,166):null,oracleFeedIds:mode===2?{solUsd:hex(d.subarray(198,230)),btcUsd:hex(d.subarray(230,262))}:null,oracleMaxGapSeconds:mode===2?d.readBigUInt64LE(262):null,oracleMaxConfidenceBps:mode===2?d.readUInt16LE(270):null};}
export function decodeRound(data){const d=asBuffer(data);if(d.length!==ROUND_LEN||d[0]!==2)throw Error('invalid round account');const acceptedPrices=Array.from({length:4},(_,i)=>({price:d.readBigInt64LE(230+i*8),confidence:d.readBigUInt64LE(262+i*8),exponent:d.readInt32LE(294+i*4),publishTime:d.readBigInt64LE(310+i*8),prevPublishTime:d.readBigInt64LE(342+i*8)})),hasOracleEvidence=d.subarray(198,230).some(Boolean);const r={id:d.readBigUInt64LE(2),config:keyAt(d,10),depositVault:keyAt(d,42),forecastCommitment:hex(d.subarray(74,106)),entryOpensAt:d.readBigInt64LE(106),entryClosesAt:d.readBigInt64LE(114),observationEndsAt:d.readBigInt64LE(122),settlementDeadline:d.readBigInt64LE(130),revealEndsAt:d.readBigInt64LE(138),claimEndsAt:d.readBigInt64LE(146),rewardPoolLamports:d.readBigUInt64LE(154),rewardPaidLamports:d.readBigUInt64LE(162),totalDepositedBaseUnits:d.readBigUInt64LE(170),questions:[{asset:'SOL/USD',resultBucket:d[196]&1?d[194]:null,totalCorrectWeight:d.readBigUInt64LE(178)},{asset:'BTC/USD',resultBucket:d[196]&2?d[195]:null,totalCorrectWeight:d.readBigUInt64LE(186)}],settledMask:d[196],rolled:d[197]!==0,oracleEvidenceHash:hasOracleEvidence?hex(d.subarray(198,230)):null,acceptedOraclePrices:hasOracleEvidence?acceptedPrices.map((p,i)=>d[194+(i>>1)]===255?null:p):null};return{...r,status:statusForRound(r)};}
export function decodeCapsule(data){const d=asBuffer(data);if(d.length!==CAPSULE_LEN||d[0]!==3)throw Error('invalid capsule account');const n=d.readUInt16LE(114);if(n>MAX_CIPHERTEXT)throw Error('invalid capsule ciphertext length');return{roundId:d.readBigUInt64LE(2),wallet:keyAt(d,10),commitment:hex(d.subarray(42,74)),ciphertextHash:hex(d.subarray(74,106)),depositedBaseUnits:d.readBigUInt64LE(106),ciphertext:Buffer.from(d.subarray(116,116+n)),revealed:d[628]!==0,answers:d[628]?[d[629],d[630]]:null,principalWithdrawn:d[631]!==0,rewardClaimed:d[632]!==0,rewardPaidLamports:d.readBigUInt64LE(633)};}
