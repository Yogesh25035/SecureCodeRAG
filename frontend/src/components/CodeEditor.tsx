import { useState, useRef, useEffect } from "react";
import { Code, Hash, Sun, Moon } from "lucide-react";
import styles from "./CodeEditor.module.css";

interface Props {
  value: string;
  onChange: (v: string) => void;
}

export default function CodeEditor({ value, onChange }: Props) {
  const [lineCount, setLineCount] = useState(1);
  const [activeLine, setActiveLine] = useState(1);
  const [isDark, setIsDark] = useState(true);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const lineNumbersRef = useRef<HTMLDivElement>(null);

  const lines = value ? value.split("\n") : [""];

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    onChange(e.target.value);
    setLineCount(e.target.value.split("\n").length || 1);
  };

  const handleCursorChange = () => {
    if (!textareaRef.current) return;
    const cursorPos = textareaRef.current.selectionStart;
    const textBeforeCursor = value.substring(0, cursorPos);
    const currentLine = textBeforeCursor.split("\n").length;
    setActiveLine(currentLine);
  };

  const handleScroll = () => {
    if (textareaRef.current && lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  };

  useEffect(() => {
    setLineCount(lines.length);
  }, [lines.length]);

  return (
    <div className={`${styles.container} ${isDark ? styles.dark : styles.light}`}>
      <div className={styles.header}>
        <h2><Code size={20} /> Code Editor</h2>
        <div className={styles.headerControls}>
          <span className={styles.lineCounter}>
            <Hash size={14} />
            {lineCount} {lineCount === 1 ? "line" : "lines"}
          </span>
          <button
            className={styles.themeToggle}
            onClick={() => setIsDark(!isDark)}
            aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
          >
            {isDark ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </div>
      </div>

      <div className={styles.editorWrapper}>
        {!value && (
          <div className={styles.placeholder}>
            <span className={styles.typingText}>Paste your code here for security analysis...</span>
            <span className={styles.cursor}>|</span>
          </div>
        )}

        <div className={styles.editorContent}>
          <div className={styles.lineNumbers} ref={lineNumbersRef}>
            {lines.map((_, idx) => (
              <div
                key={idx}
                className={`${styles.lineNumber} ${activeLine === idx + 1 ? styles.activeLine : ""}`}
              >
                {idx + 1}
              </div>
            ))}
          </div>

          <div className={styles.codeArea}>
            <div className={styles.lineHighlights}>
              {lines.map((_, idx) => (
                <div
                  key={idx}
                  className={`${styles.lineHighlight} ${activeLine === idx + 1 ? styles.activeHighlight : ""}`}
                />
              ))}
            </div>

            <textarea
              ref={textareaRef}
              value={value}
              onChange={handleChange}
              onKeyUp={handleCursorChange}
              onClick={handleCursorChange}
              onScroll={handleScroll}
              className={styles.editor}
              spellCheck="false"
            />
          </div>
        </div>
      </div>
    </div>
  );
}