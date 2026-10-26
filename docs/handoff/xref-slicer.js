import { notImplemented } from './contracts.js';

/**
 * Find *observed* direct calls to symbols; do not infer reachability or
 * attacker control from an import or a short instruction window.
 */
export class XrefSlicer {
  /**
   * @param {object} request
   * @param {import('./contracts.js').TargetImage} request.image
   * @param {AsyncIterable<import('./contracts.js').DecodedInstruction>} request.instructions
   * @param {import('./contracts.js').SymbolResolver} request.symbolResolver
   * @param {ReadonlySet<string>} request.sinks - Exact normalized symbol names.
   * @param {number} [request.maxInstructions] - Work budget, not a silent truncation.
   * @returns {Promise<Array<{
   *   caller: string | null,
   *   callAddress: string,
   *   callee: string | null,
   *   kind: 'direct_call' | 'indirect_call' | 'tail_call',
   *   stackFrameBytes: number | null,
   *   bufferArgument: import('./contracts.js').Observation,
   *   evidence: import('./contracts.js').EvidenceRef[]
   * }>>}
   */
  async traceCalls(_request) {
    // First resolve symbols/PLT or Mach-O stubs, then attach decoded call sites.
    // An unresolved indirect call is not a confirmed call to a particular sink.
    return notImplemented('XrefSlicer.traceCalls');
  }
}
