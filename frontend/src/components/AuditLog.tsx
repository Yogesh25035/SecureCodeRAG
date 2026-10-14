import { useState, useEffect } from "react";
import { History, Eye } from "lucide-react";
import Modal from "./Modal";
import styles from "./AuditLog.module.css";

interface AuditEvent {
  id: number;
  event_type: string;
  timestamp: string;
  user: string;
  repository: string;
  repo_version: string;
  file: string;
  line: number;
  finding_id: string;
  detection_source: string;
  model_name: string;
  model_version: string;
  rag_sources: string;
  ai_explanation: string;
  recommendation: string;
  confidence: number;
  review_status: string;
  reviewer_changes: string;
  reason: string;
}

export default function AuditLog() {
  const [logs, setLogs] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedLog, setSelectedLog] = useState<AuditEvent | null>(null);

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/review/system/audit?limit=50");
      if (res.ok) {
        const data = await res.json();
        setLogs(data);
      }
    } catch (e) {
      console.error("Failed to fetch audit logs", e);
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: string, eventType: string) => {
    if (eventType === "ANALYSIS") return <span className={`${styles.badge} ${styles.badgeAnalysis}`}>ANALYSIS</span>;
    if (status === "ACCEPTED") return <span className={`${styles.badge} ${styles.badgeAccepted}`}>ACCEPTED</span>;
    if (status === "REJECTED") return <span className={`${styles.badge} ${styles.badgeRejected}`}>REJECTED</span>;
    if (status === "EDITED") return <span className={`${styles.badge} ${styles.badgeEdited}`}>EDITED</span>;
    return <span className={`${styles.badge} ${styles.badgeReview}`}>{status}</span>;
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <History size={24} />
        <h2>Audit History Traceability</h2>
      </div>

      {loading ? (
        <p>Loading audit trail...</p>
      ) : (
        <div className={styles.tableContainer}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Finding ID</th>
                <th>User</th>
                <th>Repo (Ver)</th>
                <th>Source</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id}>
                  <td>{new Date(log.timestamp).toLocaleString()}</td>
                  <td>{getStatusBadge(log.review_status, log.event_type)}</td>
                  <td>{log.finding_id.substring(0, 8)}...</td>
                  <td>{log.user}</td>
                  <td>{log.repository} ({log.repo_version || "HEAD"})</td>
                  <td>{log.detection_source || "-"}</td>
                  <td>
                    <button className={styles.detailsBtn} onClick={() => setSelectedLog(log)}>
                      <Eye size={16} /> View
                    </button>
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center" }}>No audit records found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {selectedLog && (
        <Modal
          isOpen={true}
          onClose={() => setSelectedLog(null)}
          title={`Audit Record Details`}
        >
          <div className={styles.modalContent}>
            <div>
              <strong>Event Traceability</strong>
              <div>Finding ID: {selectedLog.finding_id}</div>
              <div>Timestamp: {new Date(selectedLog.timestamp).toLocaleString()}</div>
              <div>Event Type: {selectedLog.event_type}</div>
              <div>Status: {selectedLog.review_status}</div>
              <div>User: {selectedLog.user}</div>
            </div>
            
            <hr />
            
            <div>
              <strong>Repository Context</strong>
              <div>Repo: {selectedLog.repository}</div>
              <div>Version: {selectedLog.repo_version}</div>
              <div>File: {selectedLog.file}</div>
              <div>Line: {selectedLog.line}</div>
              <div>Detection: {selectedLog.detection_source}</div>
            </div>

            <hr />
            
            <div>
              <strong>AI & RAG Evidence</strong>
              <div>Model: {selectedLog.model_name} {selectedLog.model_version}</div>
              <div>Confidence: {selectedLog.confidence}</div>
              <div>RAG Sources:</div>
              <div className={styles.codeBlock}>
                {selectedLog.rag_sources || "None"}
              </div>
              <div>AI Explanation:</div>
              <div className={styles.codeBlock}>
                {selectedLog.ai_explanation}
              </div>
            </div>

            {selectedLog.event_type === "REVIEW" && (
              <>
                <hr />
                <div>
                  <strong>Reviewer Decision</strong>
                  <div>Reason: {selectedLog.reason || "N/A"}</div>
                  {selectedLog.reviewer_changes && (
                    <>
                      <div>Changes:</div>
                      <div className={styles.codeBlock}>
                        {selectedLog.reviewer_changes}
                      </div>
                    </>
                  )}
                </div>
              </>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}
