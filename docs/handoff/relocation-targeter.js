import { notImplemented } from './contracts.js';

/**
 * Report relocation targets and protection status, not write primitives.
 * Different object formats must be inspected with format-specific providers.
 */
export class RelocationTargeter {
  /**
   * @param {object} request
   * @param {import('./contracts.js').TargetImage} request.image
   * @param {object[]} request.relocations - Parsed relocation and binding records.
   * @param {object[]} request.segments - Load-time segment permissions.
   * @param {object} [request.runtimePermissions] - Optional measured page permissions.
   * @returns {Array<{
   *   symbol: string,
   *   slotOffset: string,
   *   format: 'elf_got' | 'macho_lazy_pointer' | 'pe_iat',
   *   writable: 'yes' | 'no' | 'unknown',
   *   evidence: import('./contracts.js').EvidenceRef[]
   * }>}
   */
  inspect(_request) {
    // ELF: account for DT_BIND_NOW, GNU_RELRO range and loader state.
    // Mach-O lazy pointers and PE IAT are distinct; never apply ELF RELRO.
    // Writability alone does not imply an attacker-controlled write.
    return notImplemented('RelocationTargeter.inspect');
  }
}
