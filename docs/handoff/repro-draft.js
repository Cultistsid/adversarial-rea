import { notImplemented } from './contracts.js';

/**
 * Produce a reviewable reproduction plan, not a ready-to-run exploit.
 * No trigger, payload or offset is filled in without observed supporting data.
 */
export class ReproDraft {
  /**
   * @param {object} request
   * @param {import('./contracts.js').TargetImage} request.image
   * @param {import('./contracts.js').Observation} request.finding
   * @param {{inputDigest:string, outcome:string, evidence:import('./contracts.js').EvidenceRef[]} | null} request.observedTrigger
   * @param {{bytes:number, evidence:import('./contracts.js').EvidenceRef[]} | null} request.controlOffset
   * @param {'local_review'} request.mode
   * @returns {{status:'draft' | 'blocked', markdown:string, missingEvidence:string[]}}
   */
  draft(_request) {
    // A prologue's stack allocation is NOT the offset to saved control data.
    // Unknown mitigations, offsets, targets and triggers stay as TODOs. Drafts
    // are inert and have no network, subprocess or payload delivery behavior.
    return notImplemented('ReproDraft.draft');
  }
}
