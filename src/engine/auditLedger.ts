/**
 * AWM Nexus — Audit Core & Cryptographic Ledger
 * Immutable tamper-evident hash-chained ledger preserving the provenance of all pentest operations
 */

import { AuditBlock } from '../types';
import { syncSha256 } from './cryptoUtils';

export class AuditLedger {
  private chain: AuditBlock[] = [];

  constructor() {
    this.initGenesisBlock();
  }

  private initGenesisBlock() {
    const timestamp = '2026-08-01T00:00:00.000Z';
    const prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
    const payloadStr = JSON.stringify({ message: 'AWM Nexus Root Genesis Ledger Sealed' });
    const hash = syncSha256(`0:${prevHash}:${timestamp}:SYSTEM_CORE:GENESIS:TENANT-AWM-01:ENG-2026-001:${payloadStr}`);

    const genesisBlock: AuditBlock = {
      index: 0,
      timestamp,
      prevHash,
      hash,
      actor: 'SYSTEM_CORE',
      action: 'GENESIS',
      tenantId: 'TENANT-AWM-01',
      engagementId: 'eng-2026-001',
      details: { message: 'AWM Nexus Root Genesis Ledger Sealed' },
      signature: syncSha256(`SIG:${hash}:SYSTEM_KEY`)
    };

    this.chain.push(genesisBlock);
  }

  public appendBlock(
    actor: string,
    action: string,
    tenantId: string,
    engagementId: string,
    target?: string,
    details: Record<string, unknown> = {}
  ): AuditBlock {
    const lastBlock = this.chain[this.chain.length - 1];
    const index = this.chain.length;
    const timestamp = new Date().toISOString();
    const prevHash = lastBlock.hash;
    const clonedDetails = JSON.parse(JSON.stringify(details));
    const payloadStr = JSON.stringify(clonedDetails);

    const hash = syncSha256(
      `${index}:${prevHash}:${timestamp}:${actor}:${action}:${tenantId}:${engagementId}:${target || ''}:${payloadStr}`
    );

    const signature = syncSha256(`SIG:${hash}:${actor}`);

    const newBlock: AuditBlock = {
      index,
      timestamp,
      prevHash,
      hash,
      actor,
      action,
      tenantId,
      engagementId,
      target,
      details: clonedDetails,
      signature
    };

    this.chain.push(newBlock);
    return newBlock;
  }

  public getBlocks(): AuditBlock[] {
    return [...this.chain];
  }

  public getChain(): AuditBlock[] {
    return this.getBlocks();
  }

  public getBlock(index: number): AuditBlock | undefined {
    return this.chain[index];
  }

  /**
   * Verifies the cryptographic chain integrity from Genesis to the latest block
   */
  public verifyChainIntegrity(): {
    isValid: boolean;
    blocksCount: number;
    tamperedIndex?: number;
    error?: string;
  } {
    for (let i = 0; i < this.chain.length; i++) {
      const block = this.chain[i];

      if (i === 0) {
        if (block.prevHash !== '0000000000000000000000000000000000000000000000000000000000000000') {
          return { isValid: false, blocksCount: this.chain.length, tamperedIndex: 0, error: 'Genesis prevHash is invalid.' };
        }
      } else {
        const prevBlock = this.chain[i - 1];
        if (block.prevHash !== prevBlock.hash) {
          return {
            isValid: false,
            blocksCount: this.chain.length,
            tamperedIndex: i,
            error: `Chain broken at block #${i}: prevHash mismatch.`
          };
        }

        const payloadStr = JSON.stringify(block.details);
        const expectedHash = syncSha256(
          `${block.index}:${block.prevHash}:${block.timestamp}:${block.actor}:${block.action}:${block.tenantId}:${block.engagementId}:${block.target || ''}:${payloadStr}`
        );

        if (block.hash !== expectedHash) {
          return {
            isValid: false,
            blocksCount: this.chain.length,
            tamperedIndex: i,
            error: `Block #${i} hash mismatch: recalculation does not match stored block hash.`
          };
        }
      }
    }

    return {
      isValid: true,
      blocksCount: this.chain.length
    };
  }
}

export const auditLedger = new AuditLedger();
