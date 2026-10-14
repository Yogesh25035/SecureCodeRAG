import { useState } from "react";
import { analyzeCode } from "../api/analyzer";
import type { AnalysisResult } from "../types/analysis";
import { Shield, Search, Loader2, Trash2, ShieldCheck, History } from "lucide-react";

import CodeEditor from "../components/CodeEditor";
import Modal from "../components/Modal";
import AnalysisResults from "../components/AnalysisResults";
import Toast from "../components/Toast";
import AuditLog from "../components/AuditLog";
import RepositoryUploader from "../components/RepositoryUploader";

import styles from "./AnalyzerPage.module.css";

interface ToastMessage {
  id: number;
  type: "success" | "error" | "info";
  message: string;
}

export default function AnalyzerPage() {
  const [code, setCode] = useState("");
  const [projectId, setProjectId] = useState<string | undefined>();
  const [filePath, setFilePath] = useState<string | undefined>();
  const [language, setLanguage] = useState<string>("python");
  const [results, setResults] = useState<AnalysisResult[]>([]);
  const [analysisResponse, setAnalysisResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [showAudit, setShowAudit] = useState(false);

  const addToast = (message: string, type: "success" | "error" | "info" = "info") => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, type, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  };

  const removeToast = (id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  async function handleAnalyze() {
    if (!code.trim()) {
      addToast("Please enter code to analyze", "error");
      return;
    }

    setLoading(true);
    setIsModalOpen(true);
    setResults([]);
    setAnalysisResponse(null);

    try {
      const data = await analyzeCode(code, projectId, language, filePath);
      const safeResults = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
      setResults(safeResults);
      setAnalysisResponse(data);

      if (safeResults.length === 0) {
        if (data?.status === "PARTIAL") {
          addToast("Analysis partially failed. See warnings.", "info");
        } else {
          addToast("No vulnerabilities detected!", "success");
        }
      } else {
        addToast(`Found ${safeResults.length} vulnerability(ies)`, "info");
      }
    } catch (err) {
      addToast("Analysis failed. Please try again.", "error");
      setIsModalOpen(false);
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  const handleClear = () => {
    setCode("");
    setProjectId(undefined);
    setFilePath(undefined);
    setLanguage("python");
    setResults([]);
    addToast("Code cleared", "info");
  };

  const detectLanguage = (path?: string): string => {
    if (!path) return "python";
    const ext = path.split(".").pop()?.toLowerCase();
    switch (ext) {
      case "c": return "c";
      case "cpp": case "cc": case "cxx": case "hpp": case "h": return "cpp";
      case "py": return "python";
      case "js": case "jsx": return "javascript";
      case "ts": case "tsx": return "typescript";
      case "java": return "java";
      case "go": return "go";
      case "rs": return "rust";
      default: return "python";
    }
  };

  const handleFileSelect = (selectedCode: string, pId: string, path: string) => {
    setCode(selectedCode);
    setProjectId(pId);
    setFilePath(path);
    const detected = detectLanguage(path);
    setLanguage(detected);
    addToast(`File loaded: ${path} (${detected})`, "success");
  };

  const handleCloseModal = () => {
    if (!loading) {
      setIsModalOpen(false);
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.headerContent}>
          <div className={styles.logo}>
            <Shield size={40} className={styles.logoIcon} />
            <h1>SecureCodeRAG</h1>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <p className={styles.subtitle}>
              AI-Powered Security Code Review with RAG
            </p>
            <button 
              className={styles.clearBtn} 
              onClick={() => setShowAudit(!showAudit)}
              style={{ padding: '0.4rem 0.8rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            >
              <History size={16} /> {showAudit ? "Back to Analyzer" : "Audit Log"}
            </button>
          </div>
        </div>
      </div>

      <div className={styles.mainContent}>
        {showAudit ? (
          <AuditLog />
        ) : (
          <div className={styles.splitLayout}>
            <div className={styles.leftPane}>
              <RepositoryUploader onFileSelect={handleFileSelect} />
            </div>
            <div className={styles.rightPane}>
              <CodeEditor value={code} onChange={setCode} />

              <div className={styles.controls}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', color: '#ccc' }}>
                    Language:
                    <select
                      value={language}
                      onChange={(e) => setLanguage(e.target.value)}
                      style={{ padding: '0.3rem 0.5rem', borderRadius: '6px', border: '1px solid #555', background: '#2a2a3e', color: '#e0e0e0', fontSize: '0.85rem' }}
                    >
                      <option value="python">Python</option>
                      <option value="c">C</option>
                      <option value="cpp">C++</option>
                      <option value="javascript">JavaScript</option>
                      <option value="typescript">TypeScript</option>
                      <option value="java">Java</option>
                      <option value="go">Go</option>
                      <option value="rust">Rust</option>
                    </select>
                  </label>
                  {filePath && (
                    <span style={{ fontSize: '0.8rem', color: '#888', fontStyle: 'italic' }}>
                      📄 {filePath}
                    </span>
                  )}
                </div>

                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    onClick={handleAnalyze}
                    disabled={loading || !code.trim()}
                    className={styles.analyzeBtn}
                  >
                    {loading ? (
                      <>
                        <Loader2 size={18} className={styles.spinner} /> Analyzing...
                      </>
                    ) : (
                      <>
                        <Search size={18} /> Analyze Code
                      </>
                    )}
                  </button>

                  <button
                    onClick={handleClear}
                    disabled={loading || !code.trim()}
                    className={styles.clearBtn}
                  >
                    <Trash2 size={18} /> Clear
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <Modal
        isOpen={isModalOpen}
        onClose={handleCloseModal}
        title="Security Analysis Results"
        icon={<ShieldCheck size={24} />}
      >
        <AnalysisResults results={results} isLoading={loading} response={analysisResponse} projectId={projectId} />
      </Modal>

      <div className={styles.toastContainer}>
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            message={toast.message}
            type={toast.type}
            onClose={() => removeToast(toast.id)}
          />
        ))}
      </div>
    </div>
  );
}