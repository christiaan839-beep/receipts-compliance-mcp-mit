#!/usr/bin/env node
/**
 * receipts-compliance-mcp
 *
 * Model Context Protocol server exposing Sovereign Matrix compliance
 * exporters + receipt verification as callable tools to any MCP-
 * compatible client (Claude Code, Cursor, Zed, Continue, etc.).
 *
 * Wire format: JSON-RPC 2.0 over stdio per the MCP specification
 * (https://spec.modelcontextprotocol.io/specification/2025-03-26/).
 *
 * Tools exposed:
 *   verify_manifest       - verify a signed receipt bundle manifest (Ed25519)
 *   build_annex_iv        - generate an EU AI Act Annex IV report
 *   build_iso_42001       - generate an ISO/IEC 42001:2023 report
 *   build_nist_ai_rmf     - generate a NIST AI RMF 1.0 profile
 *   build_soc2_evidence   - generate a SOC 2 evidence binder
 *   build_gdpr_dpia       - generate a GDPR Article 35 DPIA + Article 30 RoPA
 *   build_hipaa_security  - generate a HIPAA Security Rule evidence binder
 *   build_iso_23894       - generate an ISO/IEC 23894:2023 AI risk-management report
 *   build_eu_cra          - generate an EU Cyber Resilience Act compliance report
 *   build_constitution_audit - audit a receipt set against a signed constitution
 *
 * Zero runtime dependencies: the server speaks the MCP wire format directly.
 */

import { verifyManifest, type BundleManifest } from "./verify.js";
import {
  buildAnnexIv,
  toMarkdown as annexIvMarkdown,
} from "./exporters/annex-iv.js";
import {
  buildIso42001,
  toMarkdown as isoMarkdown,
} from "./exporters/iso-42001.js";
import {
  buildNistAiRmf,
  toMarkdown as rmfMarkdown,
} from "./exporters/nist-ai-rmf.js";
import {
  buildSoc2Report,
  toMarkdown as soc2Markdown,
} from "./exporters/soc2-evidence.js";
import {
  buildDpia,
  toMarkdown as dpiaMarkdown,
} from "./exporters/gdpr-dpia.js";
import {
  buildHipaaSecurity,
  toMarkdown as hipaaMarkdown,
} from "./exporters/hipaa-security.js";
import {
  buildIso23894,
  toMarkdown as iso23894Markdown,
} from "./exporters/iso-23894.js";
import {
  buildEuCra,
  toMarkdown as craMarkdown,
} from "./exporters/eu-cra.js";
import {
  buildConstitution,
  auditAgainstConstitution,
  toMarkdown as constitutionMarkdown,
} from "./exporters/ai-constitution.js";

// ─── MCP protocol types (subset we need) ─────────────────────────

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id?: number | string;
  result?: unknown;
  error?: { code: number; message: string };
}

interface McpTool {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
}

interface CallToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

// ─── Tool registry ───────────────────────────────────────────────

const TOOLS: McpTool[] = [
  {
    name: "verify_manifest",
    description:
      "Verify a signed receipt bundle manifest (MANIFEST.signed.json) against an Ed25519 public key. Recomputes the manifest hash and checks the signature. Use before building a report from a receipt set you did not produce yourself. Does not check the ML-DSA-65 half of a v3 signature.",
    inputSchema: {
      type: "object",
      properties: {
        manifest: {
          type: "object",
          description: "The parsed MANIFEST.signed.json object.",
        },
        publicKeyPem: {
          type: "string",
          description: "PEM-encoded Ed25519 public key (SPKI).",
        },
      },
      required: ["manifest", "publicKeyPem"],
    },
  },
  {
    name: "build_annex_iv",
    description:
      "Build an EU AI Act Annex IV technical-documentation report from a set of VAOS receipts. Article 11 of Regulation (EU) 2024/1689 requires this for every high-risk AI system. Returns Markdown ready to file with the EU AI Office.",
    inputSchema: {
      type: "object",
      properties: {
        system: {
          type: "object",
          description:
            "SystemDescription per Annex IV §0 (name, identifier, riskCategory, provider, intendedPurpose, placedOnMarketAt, etc.).",
        },
        receipts: {
          type: "array",
          description:
            "Array of VAOS Guardian receipts spanning the reporting window (typically 90 days for post-market monitoring).",
        },
        nextReportDue: {
          type: "string",
          description: "ISO 8601 date when the next PMM report is due.",
        },
        operatorActions: {
          type: "array",
          description:
            "Optional list of operator actions taken in response to anomalies (each item is a one-line string).",
        },
      },
      required: ["system", "receipts"],
    },
  },
  {
    name: "build_iso_42001",
    description:
      "Build an ISO/IEC 42001:2023 AI management system (AIMS) report from a set of VAOS receipts. Covers clauses 4-10 + the 38-control Annex A matrix. Returns Markdown ready to hand to your certification body (BSI, TÜV SÜD, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        scope: {
          type: "object",
          description:
            "AimsScope: organizationName, scopeStatement, aiSystemRole, certificationBody, lastInternalAudit, nextManagementReview.",
        },
        receipts: { type: "array", description: "VAOS receipts." },
        retentionDays: {
          type: "number",
          description:
            "Documented-information retention window in days. Defaults to 365.",
        },
        operatorActions: { type: "array", description: "Optional." },
      },
      required: ["scope", "receipts"],
    },
  },
  {
    name: "build_nist_ai_rmf",
    description:
      "Build a NIST AI RMF 1.0 profile (GOVERN / MAP / MEASURE / MANAGE) from a set of VAOS receipts. The de-facto US federal AI risk-management standard. Returns Markdown with per-subcategory evidence counts and trustworthy-AI characteristic coverage.",
    inputSchema: {
      type: "object",
      properties: {
        scope: {
          type: "object",
          description:
            "RmfProfileScope: systemName, lifecycleStage (design/development/deployment/operation/monitoring/decommissioning), organizationalRole, profileType (current/target/both), intendedUse, riskTolerance (low/medium/high).",
        },
        receipts: { type: "array", description: "VAOS receipts." },
        maturityOverrides: {
          type: "object",
          description:
            "Optional map of subcategory id → maturity level 0-4 (per RMF Playbook self-assessment scale).",
        },
        functionNarratives: {
          type: "object",
          description:
            "Optional operator narratives per function (keys: GOVERN, MAP, MEASURE, MANAGE).",
        },
      },
      required: ["scope", "receipts"],
    },
  },
  {
    name: "build_soc2_evidence",
    description:
      "Build a SOC 2 evidence binder mapped to AICPA Trust Service Criteria (2017) — security (CC1-CC9), availability (A1), processing integrity (PI1), confidentiality (C1), privacy (P-series). Each criterion gets a receipt-derived evidence count + days-of-coverage metric. Returns Markdown to walk into the audit kickoff with.",
    inputSchema: {
      type: "object",
      properties: {
        scope: {
          type: "object",
          description:
            "Soc2Scope: organizationName, auditPeriodStart, auditPeriodEnd, inScope (categories), serviceAuditor, servicesDescription.",
        },
        receipts: { type: "array", description: "VAOS receipts." },
        controlOwners: {
          type: "object",
          description:
            "Optional map of criterion id → control owner string (for RACI).",
        },
        coverageThresholdDays: {
          type: "number",
          description:
            "Days-of-coverage threshold below which a criterion is flagged as a gap. Default 30.",
        },
      },
      required: ["scope", "receipts"],
    },
  },
  {
    name: "build_gdpr_dpia",
    description:
      "Build a GDPR Article 35 DPIA + Article 30 RoPA report from operator-declared processing activities + a VAOS receipt set. Returns Markdown ready for the DPO + supervisory authority. High-residual-risk activities automatically flagged for Article 36 prior consultation.",
    inputSchema: {
      type: "object",
      properties: {
        controller: {
          type: "object",
          description:
            "ControllerIdentity: name, address, email, dpoName, dpoEmail, euRepresentative.",
        },
        activities: {
          type: "array",
          description:
            "Array of ProcessingActivity records per Article 30(1): id, name, purpose, dataSubjectCategories, dataCategories, specialCategories, recipients, transfers, retention, securityMeasures, legalBasis.",
        },
        risks: {
          type: "object",
          description:
            "Map of activity id → risk assessment (necessityProportionality, risks[], mitigations[], residualRisk, priorConsultationRequired). Activities without an entry are auto-flagged as high-risk.",
        },
        receipts: { type: "array", description: "VAOS receipts." },
      },
      required: ["controller", "activities", "risks", "receipts"],
    },
  },
  {
    name: "build_hipaa_security",
    description:
      "Build a HIPAA Security Rule (45 CFR § 164.308-318) evidence binder from a set of VAOS receipts. Maps every implementation specification to receipt-derived evidence. REQUIRED specifications without evidence are surfaced as findings; ADDRESSABLE specifications can be marked alternative-implemented with an operator note.",
    inputSchema: {
      type: "object",
      properties: {
        scope: {
          type: "object",
          description:
            "HipaaScope: organizationName, organizationType (covered-entity/business-associate/both), ephiCategoriesDescription, auditPeriodStart, auditPeriodEnd, securityOfficial, privacyOfficial.",
        },
        receipts: { type: "array", description: "VAOS receipts." },
        implementationStatus: {
          type: "object",
          description:
            "Optional map of specification id → { status, note }. status ∈ implemented / alternative-implemented / not-implemented / not-applicable.",
        },
      },
      required: ["scope", "receipts"],
    },
  },
  {
    name: "build_iso_23894",
    description:
      "Build an ISO/IEC 23894:2023 AI risk-management report from operator-declared risk scenarios + a VAOS receipt set. Computes inherent + residual risk per scenario via the 5×5 likelihood × impact matrix, attenuated by receipt evidence count. Returns auditor-ready Markdown.",
    inputSchema: {
      type: "object",
      properties: {
        scope: {
          type: "object",
          description:
            "RiskMgmtScope: organizationName, systemName, lifecyclePhase (inception/design/development/verification-validation/deployment/operation-monitoring/re-evaluation/retirement), policyVersion, periodStart, periodEnd.",
        },
        scenarios: {
          type: "array",
          description:
            "Array of RiskScenario: { id, description, source, likelihood (rare/unlikely/possible/likely/almost-certain), impact (negligible/minor/moderate/major/catastrophic), characteristic, treatment (avoid/reduce/share/accept), treatmentDescription, evidencePackPrefixes }.",
        },
        receipts: { type: "array", description: "VAOS receipts." },
      },
      required: ["scope", "scenarios", "receipts"],
    },
  },
  {
    name: "build_eu_cra",
    description:
      "Build an EU Cyber Resilience Act (Regulation (EU) 2024/2847) compliance report from a VAOS receipt set. Maps every Annex I essential cybersecurity requirement + Article 13/14 obligation to receipt-derived evidence. Surfaces open findings.",
    inputSchema: {
      type: "object",
      properties: {
        scope: {
          type: "object",
          description:
            "CraScope: manufacturer, productName, productIdentifier, category (default/important-class-I/important-class-II/critical), intendedUse, placedOnMarketAt, authorisedRepresentative.",
        },
        receipts: { type: "array", description: "VAOS receipts." },
        implementationStatus: {
          type: "object",
          description:
            "Optional map of requirement id → { status: compliant/alternative-measure/not-applicable/open, note }.",
        },
        residualRisks: {
          type: "array",
          description: "Operator-declared residual cybersecurity risks.",
        },
      },
      required: ["scope", "receipts"],
    },
  },
  {
    name: "build_constitution_audit",
    description:
      "Audit a VAOS receipt set against a signed AI constitution. The constitution is a content-addressed (SHA-256) document of inviolable rules; receipts commit to its hash. This tool surfaces every receipt that violated a constitutional article, ranked by severity. Use it when you want to prove (or disprove) an autonomous agent followed its policy.",
    inputSchema: {
      type: "object",
      properties: {
        constitution: {
          type: "object",
          description:
            "A SignedConstitution returned by buildConstitution(). Must include articles + hash + signedAt + name + signedBy. Use the create_constitution tool below if you need to sign one first.",
        },
        receipts: {
          type: "array",
          description:
            "VAOS receipts whose canonical projection may include the constitution hash.",
        },
      },
      required: ["constitution", "receipts"],
    },
  },
  {
    name: "create_constitution",
    description:
      "Sign a new AI constitution. Returns a SignedConstitution whose `hash` field is the content-addressed identifier. Every receipt produced under this constitution should commit to this hash. The constitution itself is byte-deterministic — anyone can re-derive the hash given the same articles + name + signedBy.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Human-readable constitution name.",
        },
        signedBy: {
          type: "string",
          description: "Operator identifier (org legal name).",
        },
        preamble: {
          type: "string",
          description: "Optional opening explaining the purpose.",
        },
        articles: {
          type: "array",
          description:
            "Array of ConstitutionArticle: { id, title, text, severity (advisory/warning/blocking), measurableCondition (optional { pack, ruleId }), citations (optional string[]) }.",
        },
      },
      required: ["name", "signedBy", "articles"],
    },
  },
];

// ─── Tool implementations ────────────────────────────────────────

function ok(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}

function err(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

async function callTool(
  name: string,
  args: Record<string, unknown>,
): Promise<CallToolResult> {
  try {
    switch (name) {
      case "verify_manifest": {
        const result = verifyManifest(
          args.manifest as BundleManifest,
          String(args.publicKeyPem ?? ""),
        );
        return result.ok
          ? ok(JSON.stringify(result, null, 2))
          : err(JSON.stringify(result, null, 2));
      }
      case "build_annex_iv": {
        const report = buildAnnexIv({
          system: args.system as Parameters<typeof buildAnnexIv>[0]["system"],
          receipts: args.receipts as Parameters<
            typeof buildAnnexIv
          >[0]["receipts"],
          nextReportDue: args.nextReportDue as string | undefined,
          operatorActions: args.operatorActions as string[] | undefined,
        });
        return ok(annexIvMarkdown(report));
      }
      case "build_iso_42001": {
        const report = buildIso42001({
          scope: args.scope as Parameters<typeof buildIso42001>[0]["scope"],
          receipts: args.receipts as Parameters<
            typeof buildIso42001
          >[0]["receipts"],
          retentionDays: args.retentionDays as number | undefined,
          operatorActions: args.operatorActions as string[] | undefined,
        });
        return ok(isoMarkdown(report));
      }
      case "build_nist_ai_rmf": {
        const report = buildNistAiRmf({
          scope: args.scope as Parameters<typeof buildNistAiRmf>[0]["scope"],
          receipts: args.receipts as Parameters<
            typeof buildNistAiRmf
          >[0]["receipts"],
          maturityOverrides: args.maturityOverrides as Parameters<
            typeof buildNistAiRmf
          >[0]["maturityOverrides"],
          functionNarratives: args.functionNarratives as Parameters<
            typeof buildNistAiRmf
          >[0]["functionNarratives"],
        });
        return ok(rmfMarkdown(report));
      }
      case "build_soc2_evidence": {
        const report = buildSoc2Report({
          scope: args.scope as Parameters<typeof buildSoc2Report>[0]["scope"],
          receipts: args.receipts as Parameters<
            typeof buildSoc2Report
          >[0]["receipts"],
          controlOwners: args.controlOwners as
            | Record<string, string>
            | undefined,
          coverageThresholdDays: args.coverageThresholdDays as
            | number
            | undefined,
        });
        return ok(soc2Markdown(report));
      }
      case "build_gdpr_dpia": {
        const report = buildDpia({
          controller: args.controller as Parameters<
            typeof buildDpia
          >[0]["controller"],
          activities: args.activities as Parameters<
            typeof buildDpia
          >[0]["activities"],
          risks: args.risks as Parameters<typeof buildDpia>[0]["risks"],
          receipts: args.receipts as Parameters<
            typeof buildDpia
          >[0]["receipts"],
        });
        return ok(dpiaMarkdown(report));
      }
      case "build_hipaa_security": {
        const report = buildHipaaSecurity({
          scope: args.scope as Parameters<
            typeof buildHipaaSecurity
          >[0]["scope"],
          receipts: args.receipts as Parameters<
            typeof buildHipaaSecurity
          >[0]["receipts"],
          implementationStatus: args.implementationStatus as Parameters<
            typeof buildHipaaSecurity
          >[0]["implementationStatus"],
        });
        return ok(hipaaMarkdown(report));
      }
      case "build_iso_23894": {
        const report = buildIso23894({
          scope: args.scope as Parameters<typeof buildIso23894>[0]["scope"],
          scenarios: args.scenarios as Parameters<
            typeof buildIso23894
          >[0]["scenarios"],
          receipts: args.receipts as Parameters<
            typeof buildIso23894
          >[0]["receipts"],
        });
        return ok(iso23894Markdown(report));
      }
      case "build_eu_cra": {
        const report = buildEuCra({
          scope: args.scope as Parameters<typeof buildEuCra>[0]["scope"],
          receipts: args.receipts as Parameters<
            typeof buildEuCra
          >[0]["receipts"],
          implementationStatus: args.implementationStatus as Parameters<
            typeof buildEuCra
          >[0]["implementationStatus"],
          residualRisks: args.residualRisks as string[] | undefined,
        });
        return ok(craMarkdown(report));
      }
      case "build_constitution_audit": {
        const audit = auditAgainstConstitution({
          constitution: args.constitution as Parameters<
            typeof auditAgainstConstitution
          >[0]["constitution"],
          receipts: args.receipts as Parameters<
            typeof auditAgainstConstitution
          >[0]["receipts"],
        });
        return ok(constitutionMarkdown(audit));
      }
      case "create_constitution": {
        const c = buildConstitution({
          name: args.name as string,
          signedBy: args.signedBy as string,
          preamble: args.preamble as string | undefined,
          articles: args.articles as Parameters<
            typeof buildConstitution
          >[0]["articles"],
        });
        return ok(JSON.stringify(c, null, 2));
      }
      default:
        return err(`Unknown tool: ${name}`);
    }
  } catch (e) {
    return err(`Tool error: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── JSON-RPC dispatcher ────────────────────────────────────────

async function handleRequest(req: JsonRpcRequest): Promise<JsonRpcResponse> {
  const id = req.id;
  switch (req.method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-03-26",
          serverInfo: {
            name: "receipts-compliance-mcp",
            version: "0.1.0",
          },
          capabilities: {
            tools: {},
          },
        },
      };
    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: TOOLS },
      };
    case "tools/call": {
      const params = (req.params ?? {}) as {
        name: string;
        arguments?: Record<string, unknown>;
      };
      const result = await callTool(params.name, params.arguments ?? {});
      return { jsonrpc: "2.0", id, result };
    }
    case "ping":
      return { jsonrpc: "2.0", id, result: {} };
    default:
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: -32601,
          message: `Method not found: ${req.method}`,
        },
      };
  }
}

// ─── stdio transport ────────────────────────────────────────────

function writeResponse(res: JsonRpcResponse): void {
  process.stdout.write(JSON.stringify(res) + "\n");
}

let buffer = "";

process.stdin.setEncoding("utf-8");
process.stdin.on("data", async (chunk) => {
  buffer += chunk;
  let nl: number;
  while ((nl = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    try {
      const req = JSON.parse(line) as JsonRpcRequest;
      if (req.id === undefined) continue; // notification: no response
      writeResponse(await handleRequest(req));
    } catch (e) {
      writeResponse({
        jsonrpc: "2.0",
        error: {
          code: -32700,
          message: `Parse error: ${e instanceof Error ? e.message : String(e)}`,
        },
      });
    }
  }
});

process.stdin.on("end", () => {
  process.exit(0);
});

// Surface fatal errors on stderr so the host MCP client can show them.
process.on("uncaughtException", (err) => {
  process.stderr.write(`fatal: ${err.message}\n`);
  process.exit(1);
});
