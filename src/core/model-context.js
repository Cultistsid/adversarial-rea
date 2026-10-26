// Only bounded structural facts cross the remote reasoning boundary.
export function summarizeBinaryForPrompt(data) {
  const categories = {};
  for (const entry of data.strings || []) {
    const category = entry.category || 'unknown';
    categories[category] = (categories[category] || 0) + 1;
  }
  const imports = (data.imports || []).slice(0, 50)
    .map(s => (s.name || '').slice(0, 128))
    .filter(name => /^[A-Za-z0-9_.$@+-]+$/.test(name));
  return `BINARY STRUCTURE (unverified as vulnerability evidence):
- Type: ${data.target.type}, Size: ${data.target.size} bytes
- Security: ${JSON.stringify(data.security)}
- Imports (${data.imports.length} total): ${imports.join(', ')}
- String categories (values withheld): ${JSON.stringify(categories)}
- Sections: ${(data.sections || []).slice(0, 30).map(s => `${s.name}(${s.size}b)`).join(', ')}
- Extraction warnings: ${(data.warnings || []).length}; truncated: ${JSON.stringify(data.truncated || {})}
An import, string category, or mitigation flag alone does not establish a vulnerable call site or exploit primitive.`;
}

export function redactSensitive(text) {
  return String(text ?? '')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, '[REDACTED KEY]')
    .replace(/\b(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi, '$1=[REDACTED]')
    .replace(/\bsk-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED]');
}
