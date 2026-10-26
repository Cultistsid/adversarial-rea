// Only bounded, non-truncated records in the local ledger can promote a claim.
export function localEvidenceRecord(id, analysis) {
  const sha256 = analysis?.target?.sha256;
  const ledger = analysis?.evidence;
  if (!/^[0-9a-f]{64}$/i.test(sha256 || '') || typeof id !== 'string' ||
      !id || id.length > 128 || !Array.isArray(ledger)) return null;
  return ledger.find(record => record.id === id && record.target_sha256 === sha256 &&
    record.status === 'observed' && record.truncated === false &&
    typeof record.provider === 'string' && record.provider.length > 0 &&
    typeof record.provider_version === 'string' && record.provider_version.length > 0 &&
    typeof record.location === 'string' && record.location.length > 0 &&
    typeof record.detail === 'string' && record.detail.length <= 256 &&
    ['call-site', 'def-use', 'trace', 'gadget', 'relocation'].includes(record.location_kind)
  ) || null;
}

export function isVerifiedFinding(finding, analysis) {
  const ids = finding?.evidence_ids;
  if (finding?.status !== 'observed' || typeof finding.id !== 'string' ||
      !Array.isArray(ids) || ids.length === 0) return false;
  const records = ids.map(id => localEvidenceRecord(id, analysis));
  return records.every(Boolean) && records.some(record =>
    record.location_kind === 'def-use' || record.location_kind === 'trace'
  );
}
