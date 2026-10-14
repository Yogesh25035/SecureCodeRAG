import { useState } from "react";
import { Upload, FileCode2, Loader2, CheckCircle2 } from "lucide-react";
import styles from "./RepositoryUploader.module.css";

interface RepoFile {
  path: string;
  content: string;
  functions: string[];
}

interface RepositoryUploaderProps {
  onFileSelect: (code: string, projectId: string, filePath: string) => void;
}

export default function RepositoryUploader({ onFileSelect }: RepositoryUploaderProps) {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [projectId, setProjectId] = useState<string | null>(null);
  const [projectName, setProjectName] = useState<string | null>(null);
  const [files, setFiles] = useState<RepoFile[]>([]);
  const [error, setError] = useState("");

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    setError("");
    
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("/api/repositories/upload", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        throw new Error("Failed to upload repository");
      }

      const data = await res.json();
      setProjectId(data.project_id);
      setProjectName(data.project_name);
      setFiles(data.files || []);
    } catch (err: any) {
      setError(err.message || "Upload failed");
    } finally {
      setLoading(false);
    }
  };

  const handleFileClick = (repoFile: RepoFile) => {
    if (projectId) {
      onFileSelect(repoFile.content, projectId, repoFile.path);
    }
  };

  return (
    <div className={styles.container}>
      <h2 className={styles.title}>Repository Analysis</h2>
      
      {!projectId ? (
        <div className={styles.uploadSection}>
          <label className={styles.fileLabel}>
            <input type="file" accept=".zip" onChange={handleFileChange} className={styles.fileInput} />
            <span className={styles.fileText}>
              {file ? file.name : "Select Repository ZIP"}
            </span>
          </label>
          <button 
            onClick={handleUpload} 
            disabled={!file || loading}
            className={styles.uploadBtn}
          >
            {loading ? <Loader2 size={18} className={styles.spinner} /> : <Upload size={18} />}
            {loading ? "Uploading..." : "Upload & Ingest"}
          </button>
          {error && <div className={styles.error}>{error}</div>}
        </div>
      ) : (
        <div className={styles.projectInfo}>
          <div className={styles.successHeader}>
            <CheckCircle2 size={20} color="#10b981" />
            <span>Ingested: {projectName}</span>
          </div>
          <div className={styles.fileList}>
            <p className={styles.listTitle}>Select a file to analyze:</p>
            {files.length > 0 ? (
              <ul className={styles.list}>
                {files.map((f, i) => (
                  <li key={i} className={styles.listItem} onClick={() => handleFileClick(f)}>
                    <FileCode2 size={16} />
                    <span>{f.path}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className={styles.empty}>No C/C++ files found in repository.</p>
            )}
          </div>
          <button onClick={() => {
            setProjectId(null);
            setFiles([]);
            setFile(null);
          }} className={styles.resetBtn}>
            Upload Another
          </button>
        </div>
      )}
    </div>
  );
}
