import { useEffect } from "react";
import { CheckCircle, XCircle, Info, X } from "lucide-react";
import styles from "./Toast.module.css";

interface ToastProps {
  message: string;
  type: "success" | "error" | "info";
  onClose: () => void;
}

export default function Toast({ message, type, onClose }: ToastProps) {
  useEffect(() => {
    const timer = setTimeout(onClose, 4000);
    return () => clearTimeout(timer);
  }, [onClose]);

  const getIcon = () => {
    switch (type) {
      case "success":
        return <CheckCircle size={20} />;
      case "error":
        return <XCircle size={20} />;
      case "info":
        return <Info size={20} />;
    }
  };

  return (
    <div className={`${styles.toast} ${styles[type]}`}>
      <span className={styles.icon}>{getIcon()}</span>
      <p className={styles.message}>{message}</p>
      <button className={styles.close} onClick={onClose}>
        <X size={18} />
      </button>
    </div>
  );
}