// Returns predictable test data so unit tests don't need real binaries
export const mockAnalysisResult = {
  target: { path: '/test/sample', name: 'sample', size: 12345, type: 'macho' },
  security: { pie: true, nx: true, canary: true, relro: 'full', stripped: false, fortify: true },
  symbols: [
    { address: '100000abc', type: 'T', name: '_main', imported: false, exported: true },
    { address: null, type: 'U', name: '_strcpy', imported: true, exported: false },
    { address: null, type: 'U', name: '_malloc', imported: true, exported: false },
    { address: null, type: 'U', name: '_free', imported: true, exported: false }
  ],
  strings: [
    { value: 'password123', interesting: true, category: 'credential_related' },
    { value: 'https://example.com/api', interesting: true, category: 'url' },
    { value: '/etc/passwd', interesting: true, category: 'path' },
    { value: 'SELECT * FROM users', interesting: true, category: 'sql' },
    { value: 'libfoo.dylib', interesting: false, category: 'library_reference' }
  ],
  imports: [
    { address: null, type: 'U', name: '_strcpy', imported: true, exported: false },
    { address: null, type: 'U', name: '_malloc', imported: true, exported: false }
  ],
  exports: [
    { address: '100000abc', type: 'T', name: '_main', imported: false, exported: true }
  ],
  functions: [
    { address: '100000abc', type: 'T', name: '_main', imported: false, exported: true }
  ],
  sections: [
    { name: '__TEXT', size: 4096, address: '100000000' },
    { name: '__DATA', size: 2048, address: '100001000' }
  ]
};

// Minimal BinaryAnalyzer stand-in: every analyze() call resolves to the fixture above.
export class MockBinaryAnalyzer {
  constructor(config = {}) {
    this.config = config;
    this.tools = { objdump: true, nm: true, strings: true, file: true, otool: true };
  }

  async analyze() {
    return structuredClone(mockAnalysisResult);
  }

  async disassemble() {
    return { functions: [], raw: '0000000100000abc <_main>:\n  push rbp\n  mov rbp, rsp\n' };
  }
}

export default MockBinaryAnalyzer;
