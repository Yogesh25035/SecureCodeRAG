import type { AnalysisResult, AnalysisResponse } from "../types/analysis";
import { ShieldAlert, ShieldCheck, CheckCircle, AlertTriangle, FileDown } from "lucide-react";
import VulnerabilityList from "./VulnerabilityList";
import ExplanationPanel from "./ExplanationPanel";
import styles from "./AnalysisResults.module.css";

interface Props {
  results: AnalysisResult[];
  isLoading: boolean;
  response?: AnalysisResponse | null;
  projectId?: string;
}

export default function AnalysisResults({ results, isLoading, response, projectId }: Props) {

  const handleDownloadReport = async (format: "html" | "json") => {
    if (!projectId) return;
    try {
      const res = await fetch(`/api/reports/${projectId}?format=${format}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token") || ""}`,
        },
      });
      if (!res.ok) throw new Error("Report generation failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `report_${projectId}.${format === "json" ? "json" : "html"}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to download report", err);
    }
  };

  if (isLoading) {
    return (
      <div className={styles.loading}>
        <div className={styles.spinner}></div>
        <p>Analyzing your code for vulnerabilities...</p>
        <span className={styles.subtext}>This may take a few seconds</span>
      </div>
    );
  }

  if (results.length === 0) {
    if (response?.status === "PARTIAL" && response.warnings && response.warnings.length > 0) {
      return (
        <div className={styles.noVulnerabilities}>
          <AlertTriangle size={64} style={{ color: "orange" }} />
          <h3>Partial Analysis</h3>
          <p>Analysis completed but some tools failed.</p>
          <div className={styles.tips} style={{ textAlign: "left", marginTop: "1rem" }}>
            <h4>Warnings:</h4>
            <ul>
              {response.warnings.map((w, i) => <li key={i}>{w}</li>)}
            </ul>
          </div>
        </div>
      );
    }
    return (
      <div className={styles.noVulnerabilities}>
        <ShieldCheck size={64} className={styles.successIcon} />
        <h3>No Vulnerabilities Detected</h3>
        <p>Your code appears to be secure based on our analysis.</p>
        <div className={styles.tips}>
          <h4><CheckCircle size={16} /> Security Tips</h4>
          <ul>
            <li>Continue following secure coding practices</li>
            <li>Keep dependencies up to date</li>
            <li>Perform regular security audits</li>
          </ul>
        </div>
      </div>
    );
  }

  const criticalCount = results.filter(r => r.severity?.toLowerCase() === "critical").length;
  const highCount = results.filter(r => r.severity?.toLowerCase() === "high").length;
  const mediumCount = results.filter(r => r.severity?.toLowerCase() === "medium").length;
  const lowCount = results.filter(r => r.severity?.toLowerCase() === "low").length;
  const infoCount = results.filter(r => r.severity?.toLowerCase() === "info").length;
  const confirmedCount = results.filter(r => r.evidence_status === "CONFIRMED").length;


  return (
    <div className={styles.container}>
      {response?.status === "PARTIAL" && response.warnings && response.warnings.length > 0 && (
        <div className={styles.warningsBanner} style={{ backgroundColor: "#fffae6", color: "#8a6d3b", padding: "10px", borderRadius: "4px", marginBottom: "20px", border: "1px solid #faebcc" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", fontWeight: "bold" }}>
            <AlertTriangle size={20} />
            Partial Analysis (Some tools failed)
          </div>
          <ul style={{ margin: "10px 0 0 28px", padding: 0 }}>
            {response.warnings.map((w, i) => <li key={i}>{w}</li>)}
          </ul>
        </div>
      )}
      <div className={styles.summary}>
        <div className={styles.summaryHeader}>
          <ShieldAlert size={24} />
          <h3>Analysis Summary</h3>
        </div>
        <div className={styles.stats}>
          <div className={`${styles.stat} ${styles.critical}`}>
            <span className={styles.statCount}>{criticalCount}</span>
            <span className={styles.statLabel}>Critical</span>
          </div>
          <div className={`${styles.stat} ${styles.high}`}>
            <span className={styles.statCount}>{highCount}</span>
            <span className={styles.statLabel}>High</span>
          </div>
          <div className={`${styles.stat} ${styles.medium}`}>
            <span className={styles.statCount}>{mediumCount}</span>
            <span className={styles.statLabel}>Medium</span>
          </div>
          <div className={`${styles.stat} ${styles.low}`}>
            <span className={styles.statCount}>{lowCount}</span>
            <span className={styles.statLabel}>Low</span>
          </div>
          <div className={`${styles.stat} ${styles.info}`}>
            <span className={styles.statCount}>{infoCount}</span>
            <span className={styles.statLabel}>Informational</span>
          </div>
        </div>
        <div style={{ marginTop: "0.75rem", color: "#cbd5e1", fontSize: "0.9rem" }}>
          Confirmed security vulnerabilities: <strong>{confirmedCount}</strong>
        </div>
        {projectId && (
          <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.75rem" }}>
            <button
              onClick={() => handleDownloadReport("html")}
              style={{ display: "flex", alignItems: "center", gap: "0.4rem", padding: "0.4rem 0.8rem", borderRadius: "6px", border: "1px solid #555", background: "#2a2a3e", color: "#e0e0e0", cursor: "pointer", fontSize: "0.85rem" }}
            >
              <FileDown size={16} /> HTML Report
            </button>
            <button
              onClick={() => handleDownloadReport("json")}
              style={{ display: "flex", alignItems: "center", gap: "0.4rem", padding: "0.4rem 0.8rem", borderRadius: "6px", border: "1px solid #555", background: "#2a2a3e", color: "#e0e0e0", cursor: "pointer", fontSize: "0.85rem" }}
            >
              <FileDown size={16} /> JSON Report
            </button>
          </div>
        )}
      </div>

      <div className={styles.resultsContent}>
        <VulnerabilityList results={results} />
        <ExplanationPanel results={results} />
      </div>
    </div>
  );
}