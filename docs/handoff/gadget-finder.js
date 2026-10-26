import { notImplemented } from './contracts.js';

/**
 * Find gadget *candidates* by decoding bytes in executable ranges only.
 * The result is never proof that a gadget is reachable or bypasses mitigations.
 */
export class GadgetFinder {
  /**
   * @param {object} request
   * @param {import('./contracts.js').TargetImage} request.image
   * @param {Array<{fileOffset:number, size:number, virtualAddress:string}>} request.executableRanges
   * @param {(fileOffset:number, length:number) => Promise<Uint8Array>} request.readBytes
   * @param {import('./contracts.js').InstructionDecoder} request.decoder
   * @param {number} [request.maxInstructionsPerGadget]
   * @param {number} [request.maxResults]
   * @returns {Promise<Array<{
   *   imageOffset: string,
   *   sequence: string[],
   *   category: 'register_setup' | 'stack_pivot' | 'syscall' | 'indirect_branch',
   *   constraints: string[],
   *   evidence: import('./contracts.js').EvidenceRef[]
   * }>>}
   */
  async find(_request) {
    // Re-decode each candidate from its start byte (x86) or aligned word
    // (AArch64); reject cross-section sequences and invalid instructions.
    // For PIE/ASLR, image offsets are not runtime addresses. Account for
    // CET/BTI/PAC and other landing constraints before suggesting a chain.
    return notImplemented('GadgetFinder.find');
  }
}
