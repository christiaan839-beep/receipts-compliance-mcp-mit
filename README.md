# receipts-compliance-mcp-mit

A local MCP server and Claude Desktop Extension. It verifies signed AI-agent receipt bundles and turns a set of receipts into auditor-ready Markdown reports. It runs offline; receipts are never uploaded.

## Tools

| Tool | Output |
|---|---|
| `verify_manifest` | Checks a `MANIFEST.signed.json` against an Ed25519 public key (PEM). Does not check the ML-DSA-65 half of a v3 signature. |
| `build_annex_iv` | EU AI Act Annex IV technical documentation |
| `build_iso_42001` | ISO/IEC 42001:2023 AI management system report |
| `build_iso_23894` | ISO/IEC 23894:2023 AI risk management report |
| `build_nist_ai_rmf` | NIST AI RMF 1.0 profile |
| `build_soc2_evidence` | SOC 2 Trust Service Criteria evidence binder |
| `build_gdpr_dpia` | GDPR Article 35 DPIA and Article 30 Records of Processing |
| `build_hipaa_security` | HIPAA Security Rule evidence binder |
| `build_eu_cra` | EU Cyber Resilience Act report |
| `create_constitution`, `build_constitution_audit` | Sign an AI constitution; audit receipts against it |

Sections that need operator narrative are left as marked stubs. The reports are evidence summaries, not legal advice or a certification.

## Install

Download `receipts-compliance.mcpb` from a release and open it in Claude Desktop. To build it yourself:

```bash
npm install
npm run pack:mcpb
```

## Develop

```bash
npm test          # vitest
npm run typecheck
npm run build     # bundles dist/server.js
```

Receipts are JSON objects with `verdictId`, `overall` (`pass`, `warn` or `block`) and `issuedAt`; see `src/types.ts`.

## Licence

MIT. See `LICENSE`.
