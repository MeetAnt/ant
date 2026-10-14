// Browser-safe wallet codecs. Hashing is async because WebCrypto is async.
export const SCHEMA_VERSION=1,MAX_CIPHERTEXT=512,CONFIG_LEN=272,ROUND_LEN=374,CAPSULE_LEN=642,TOKEN_PROGRAM_ID='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const enc=new TextEncoder(),DOMAIN=enc.encode('ant-capsule-v1');
const bytes=value=>value instanceof Uint8Array?value:new Uint8Array(value?.toBytes?.()??value);
const fixed32=(value,name)=>{const b=bytes(value);if(b.length!==32)throw Error(`${name} must be 32 bytes`);return b;};
const concat=(...parts)=>{const size=parts.reduce((n,p)=>n+p.length,0),out=new Uint8Array(size);let at=0;for(const p of parts){out.set(p,at);at+=p.length;}return out;};
const le=(value,size,signed=false)=>{const b=new ArrayBuffer(size),v=new DataView(b);if(size===2)v.setUint16(0,Number(value),true);else if(signed)v.setBigInt64(0,BigInt(value),true);else v.setBigUint64(0,BigInt(value),true);return new Uint8Array(b);};
const sha256=async value=>new Uint8Array(await crypto.subtle.digest('SHA-256',value));
export async function networkIdentity(label){return sha256(enc.encode(`ant-network:${label}`));}
export async function capsuleCommitment({programId,networkIdentity,mint,roundId,wallet,answers,salt,schemaVersion=SCHEMA_VERSION}){if(answers?.length!==2||answers.some(v=>v<0||v>3))throw Error('answers must contain two buckets 0..3');return sha256(concat(DOMAIN,fixed32(programId,'programId'),fixed32(networkIdentity,'networkIdentity'),fixed32(mint,'mint'),le(roundId,8),fixed32(wallet,'wallet'),le(schemaVersion,2),Uint8Array.from(answers),fixed32(salt,'salt')));}
export async function encodeEnter({depositBaseUnits,commitment,ciphertext}){const c=bytes(ciphertext);if(!c.length||c.length>MAX_CIPHERTEXT)throw Error(`ciphertext must be 1..${MAX_CIPHERTEXT} bytes`);return concat(Uint8Array.of(3),le(depositBaseUnits,8),fixed32(commitment,'commitment'),await sha256(c),le(c.length,2),c);}
export function encodeReveal({answers,salt,schemaVersion=SCHEMA_VERSION}){if(answers?.length!==2||answers.some(v=>v<0||v>3))throw Error('answers must contain two buckets 0..3');return concat(Uint8Array.of(6),le(schemaVersion,2),Uint8Array.from(answers),fixed32(salt,'salt'));}
export const encodeWithdraw=()=>Uint8Array.of(7);export const encodeClaim=()=>Uint8Array.of(8);
