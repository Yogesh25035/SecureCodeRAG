export interface AnalysisResult {
  finding_id: string;
  project_id: string;
  file: string;
  function?: string;
  line_start: number;
  line_end?: number;
  severity: string;
  category: string;
  title: string;
  finding: string;
  evidence: string;
  root_cause?: string;
  rule?: string;
  source: string;
  confidence: number;
  diagnostic_message?: string;
  evidence_status: "CONFIRMED" | "LIKELY" | "INSUFFICIENT_CONTEXT" | string;
  explanation_quality?: number;
  status: string;
}

export function normalizeFinding(finding: AnalysisResult): AnalysisResult {
  const severity = String(finding.severity || "INFO").toUpperCase();
  const allowed = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  return {
    ...finding,
    severity: allowed.includes(severity) ? severity : "INFO",
    confidence: Number.isFinite(Number(finding.confidence))
      ? Number(finding.confidence)
      : 0,
    evidence_status: finding.evidence_status || "INSUFFICIENT_CONTEXT",
  };
}

export function normalizeAnalysisResponse(response: AnalysisResponse): AnalysisResponse {
  return {
    ...response,
    vulnerabilities: (response.vulnerabilities || []).map(normalizeFinding),
  };
}

export interface AnalysisResponse {
  vulnerabilities: AnalysisResult[];
  total_vulnerabilities: number;
  summary?: string;
  status?: string;
  warnings?: string[];
}