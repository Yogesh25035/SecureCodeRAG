import { useState, useEffect } from "react";
import AnalyzerPage from "./pages/AnalyzerPage";
import { Shield } from "lucide-react";
import styles from "./pages/AnalyzerPage.module.css";

export default function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem("access_token"));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const formData = new URLSearchParams();
      formData.append("username", username);
      formData.append("password", password);

      const res = await fetch("/api/auth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData.toString()
      });

      if (res.ok) {
        const data = await res.json();
        localStorage.setItem("access_token", data.access_token);
        setToken(data.access_token);
      } else {
        setError("Invalid username or password");
      }
    } catch (err) {
      setError("Failed to connect to the server");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    setToken(null);
  };

  // Patch fetch to include Authorization header automatically
  useEffect(() => {
    const originalFetch = window.fetch;
    window.fetch = async (...args) => {
      let [resource, config] = args;
      if (token) {
        config = config || {};
        config.headers = {
          ...config.headers,
          Authorization: `Bearer ${token}`,
        };
      }
      const response = await originalFetch(resource, config);
      if (response.status === 401) {
        handleLogout();
      }
      return response;
    };
    return () => {
      window.fetch = originalFetch;
    };
  }, [token]);

  if (!token) {
    return (
      <div className={styles.container} style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <div style={{ background: 'white', padding: '2rem', borderRadius: '12px', boxShadow: '0 4px 6px rgba(0,0,0,0.1)', width: '100%', maxWidth: '400px' }}>
          <div className={`${styles.logo} ${styles.loginLogo}`} style={{ justifyContent: 'center', marginBottom: '1.5rem' }}>
            <Shield size={40} className={styles.logoIcon} />
            <h1>SecureCodeRAG</h1>
          </div>
          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {error && <div style={{ color: 'red', fontSize: '0.9rem', textAlign: 'center' }}>{error}</div>}
            <input 
              type="text" 
              placeholder="Username" 
              value={username} 
              onChange={e => setUsername(e.target.value)}
              style={{ padding: '0.75rem', borderRadius: '6px', border: '1px solid #ccc' }}
            />
            <input 
              type="password" 
              placeholder="Password" 
              value={password} 
              onChange={e => setPassword(e.target.value)}
              style={{ padding: '0.75rem', borderRadius: '6px', border: '1px solid #ccc' }}
            />
            <button type="submit" className={styles.analyzeBtn}>
              Login
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <>
      <div style={{ position: 'absolute', top: '1rem', right: '1rem', zIndex: 1000 }}>
        <button onClick={handleLogout} className={styles.clearBtn} style={{ padding: '0.5rem 1rem' }}>
          Logout
        </button>
      </div>
      <AnalyzerPage />
    </>
  );
}
