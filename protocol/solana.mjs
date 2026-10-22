import {PublicKey} from '@solana/web3.js';
const le64=value=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(value));return b;};
export const configPda=programId=>PublicKey.findProgramAddressSync([Buffer.from('config')],new PublicKey(programId));
export const roundPda=(programId,id)=>PublicKey.findProgramAddressSync([Buffer.from('round'),le64(id)],new PublicKey(programId));
export const capsulePda=(programId,id,wallet)=>PublicKey.findProgramAddressSync([Buffer.from('capsule'),le64(id),new PublicKey(wallet).toBuffer()],new PublicKey(programId));
export const vaultAuthorityPda=(programId,id)=>PublicKey.findProgramAddressSync([Buffer.from('vault-authority'),le64(id)],new PublicKey(programId));

export const checkpointPda=(programId,roundId,question,boundary)=>{if(![0,1].includes(question)||![0,1].includes(boundary))throw Error('Invalid checkpoint identity');return PublicKey.findProgramAddressSync([Buffer.from('checkpoint'),le64(roundId),Buffer.from([question,boundary])],new PublicKey(programId));};
