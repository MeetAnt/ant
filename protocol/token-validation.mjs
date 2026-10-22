// Browser-safe validation shared with operators. Keep in sync with core token_extensions.
export const TOKEN_2022_PROGRAM_ID='TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const LEGACY='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const supportedTokenProgram=id=>id===LEGACY||id===TOKEN_2022_PROGRAM_ID;
const equal=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
function extensions(data,owner,mint){
 const d=new Uint8Array(data),base=mint?82:165;
 if(!supportedTokenProgram(owner)||d.length<base)throw Error('Unsupported token program or base layout');
 if(owner===LEGACY){if(d.length!==base)throw Error('Legacy token extensions forbidden');return d;}
 if(d.length===base)return d;
 if(d.length<166||d[165]!== (mint?1:2)||(mint&&d.slice(82,165).some(Boolean)))throw Error('Invalid Token-2022 account type or padding');
 const view=new DataView(d.buffer,d.byteOffset,d.byteLength),seen=new Set();
 for(let at=166;at<d.length;){if(d.slice(at).every(v=>v===0))break;if(d.length-at<4)throw Error('Truncated token extension');const type=view.getUint16(at,true),length=view.getUint16(at+2,true);at+=4;if(length>d.length-at||seen.has(type))throw Error('Invalid or duplicate token extension');seen.add(type);const value=d.slice(at,at+length);if(mint){if(!((type===18&&length===64&&value.slice(0,32).every(v=>v===0)||type===19&&length>=80)&&equal(value.slice(32,64),mint)))throw Error('Unsupported mint extension or external metadata pointer');}else if(type!==7||length!==0)throw Error('Unsupported token account extension');at+=length;}
 return d;
}
export function validateMintBytes(data,owner,mint,decimals){
 if(!mint||mint.length!==32)throw Error('Exact mint public key required');const d=extensions(data,owner,mint),v=new DataView(d.buffer,d.byteOffset,d.byteLength);
 if(d[45]!==1||v.getUint32(0,true)!==0||v.getUint32(46,true)!==0||decimals!==undefined&&d[44]!==decimals)throw Error('Unsupported mint authority, freeze authority, initialization or decimals');return {decimals:d[44],tokenProgram:owner};
}
export function validateTokenAccountBytes(data,owner){const d=extensions(data,owner,null),v=new DataView(d.buffer,d.byteOffset,d.byteLength);if(d[108]!==1||v.getUint32(72,true)!==0||v.getUint32(129,true)!==0)throw Error('Token account must have no delegate or close authority');return {mint:d.slice(0,32),owner:d.slice(32,64),amount:v.getBigUint64(64,true)};}
