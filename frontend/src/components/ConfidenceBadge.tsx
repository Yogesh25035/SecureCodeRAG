import styles from "./ConfidenceBadge.module.css";

export default function ConfidenceBadge({
  confidence
}: {
  confidence: number;
}) {
  const getLevel = (score: number) => {
    if (score >= 0.8) return "High";
    if (score >= 0.6) return "Medium";
    return "Low";
  };

  const level = getLevel(confidence);

  const getColorClass = (level: string) => {
    switch (level.toLowerCase()) {
      case "critical":
      case "high":
        return styles.high;
      case "medium":
        return styles.medium;
      case "low":
        return styles.low;
      default:
        return styles.info;
    }
  };

  return (
    <span className={`${styles.badge} ${getColorClass(level)}`}>
      <span className={styles.level}>Confidence:</span>
      <span className={styles.score}>{(confidence * 100).toFixed(0)}%</span>
    </span>
  );
}