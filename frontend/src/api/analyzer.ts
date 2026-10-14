import { normalizeAnalysisResponse, type AnalysisResponse } from "../types/analysis";

const API_BASE = "/api";

export async function analyzeCode(
  code: string,
  projectId?: string,
  language?: string,
  filePath?: string
): Promise<AnalysisResponse> {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code,
      project_id: projectId,
      ...(language ? { language } : {}),
      ...(filePath ? { file_path: filePath } : {})
    })
  });

  if (!res.ok) {
    throw new Error("Failed to analyze code");
  }

  return normalizeAnalysisResponse(await res.json());
}
