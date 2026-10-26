/**
 * Design-only types shared by the proposed analysis modules. These modules are
 * intentionally outside src/ and are not part of the running MCP server.
 *
 * @typedef {'elf' | 'macho' | 'pe'} NativeFormat
 * @typedef {'x86_64' | 'aarch64'} Architecture
 * @typedef {'observed' | 'candidate' | 'unknown'} FindingStatus
 *
 * @typedef {object} TargetImage
 * @property {string} path
 * @property {string} sha256 - Hash of the exact bytes used for every observation.
 * @property {NativeFormat} format
 * @property {Architecture} arch
 *
 * @typedef {object} EvidenceRef
 * @property {string} id - Stable ID for referencing the observation in a report.
 * @property {string} targetSha256
 * @property {string} provider - Tool and version, e.g. "llvm-objdump 19".
 * @property {'virtual_address' | 'file_offset' | 'symbol' | 'runtime'} kind
 * @property {string} location - Hex address, offset, or exact symbol name.
 * @property {string} detail - The bounded observation; never a guess.
 * @property {boolean} truncated - True if extraction hit an explicit budget.
 *
 * @typedef {object} Observation
 * @property {string} id
 * @property {FindingStatus} status
 * @property {string} description
 * @property {EvidenceRef[]} evidence
 * @property {string[]} missingEvidence - Facts needed before claiming a vuln.
 *
 * @typedef {object} DecodedInstruction
 * @property {string} address - Address relative to the image load base.
 * @property {number} fileOffset
 * @property {string} section
 * @property {string} mnemonic
 * @property {string[]} operands
 * @property {number} size
 *
 * @typedef {object} SymbolResolver
 * @property {(instruction: DecodedInstruction) => ({symbol: string, evidence: EvidenceRef[]} | null)} resolveCallTarget
 *
 * @typedef {object} InstructionDecoder
 * @property {(bytes: Uint8Array, imageOffset: string, arch: Architecture) => DecodedInstruction[]} decode
 *
 * @typedef {object} DefUseGraph
 * @property {(nodeId: string) => Array<{nodeId:string, evidence: EvidenceRef[]}>} predecessors
 */

export function notImplemented(component) {
  throw new Error(`Not implemented: ${component} is a design-only handoff`);
}
