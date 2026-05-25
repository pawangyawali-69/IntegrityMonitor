import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function formatTimestamp(ts: string): string {
  try {
    const date = new Date(ts);
    return date.toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

export function truncatePath(path: string, maxLen: number = 60): string {
  if (path.length <= maxLen) return path;
  const parts = path.split("\\");
  if (parts.length > 3) {
    return parts[0] + "\\...\\" + parts.slice(-2).join("\\");
  }
  return path.slice(0, maxLen) + "...";
}

export function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical": return "text-red-500";
    case "high": return "text-orange-500";
    case "medium": return "text-yellow-500";
    case "low": return "text-green-500";
    default: return "text-blue-500";
  }
}

export function getRiskBadgeColor(level: string): string {
  switch (level.toLowerCase()) {
    case "critical": return "bg-red-500/20 text-red-400 border-red-500/30";
    case "high": return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "low": return "bg-green-500/20 text-green-400 border-green-500/30";
    default: return "bg-blue-500/20 text-blue-400 border-blue-500/30";
  }
}

export function getSuspicionColor(score: number): string {
  if (score >= 0.8) return "text-red-500";
  if (score >= 0.5) return "text-orange-500";
  if (score >= 0.3) return "text-yellow-500";
  return "text-green-500";
}

export function classNames(...classes: (string | boolean | undefined | null)[]): string {
  return classes.filter(Boolean).join(" ");
}
