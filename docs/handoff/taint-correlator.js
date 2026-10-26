import { notImplemented } from './contracts.js';

/**
 * Follow data from an input source to a sink through explicit def-use edges.
 * Co-occurrence in a binary or function is not a data-flow path.
 */
export class TaintCorrelator {
  /**
   * @param {object} request
   * @param {import('./contracts.js').TargetImage} request.image
   * @param {import('./contracts.js').DefUseGraph} request.defUseGraph
   * @param {Array<{address:string, outputNodeId:string}>} request.sources
   * @param {Array<{address:string, argumentNodeId:string}>} request.sinks
   * @param {Array<{address:string, effect:string}>} [request.barriers] - Checks or sanitizers.
   * @param {number} [request.maxHops] - Interprocedural budget.
   * @returns {Array<{
   *   sourceAddress: string,
   *   sinkAddress: string,
   *   status: 'observed' | 'candidate' | 'unknown',
   *   path: string[],
   *   evidence: import('./contracts.js').EvidenceRef[],
   *   missingEvidence: string[]
   * }>}
   */
  correlate(_request) {
    // Preserve ABI, aliasing, branch conditions, bounds checks and sanitizers.
    // "Observed" requires a path into the relevant sink argument (e.g. rdi/x0),
    // not merely two imported symbols in one caller.
    return notImplemented('TaintCorrelator.correlate');
  }
}
