/** A single signed receipt as the exporters read it. Extra fields are allowed. */
export interface ReceiptRecord {
  verdictId: string;
  overall: "pass" | "warn" | "block";
  issuedAt: string;
  agentSlug?: string;
  tokenId?: string;
  pack?: string;
  ruleCount?: number;
  signature?: string;
  contentHash?: string;
  [key: string]: unknown;
}
