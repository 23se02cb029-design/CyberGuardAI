export type RiskTone = "green" | "amber" | "red";

export interface RiskProfile {
  level: string;
  tone: RiskTone;
  // `.text-glow-*` are hand-rolled CSS classes (text-shadow), not registered
  // Tailwind utilities — Tailwind can't generate a `dark:` variant for them,
  // so light/dark glow classes are picked explicitly via `isDark` at render time.
  glowLight: string;
  glowDark: string;
  border: string;
  bg: string;
  bar: string;
  badge: string;
}

export function getRiskProfile(score: number): RiskProfile {
  if (score >= 80) {
    return {
      level: "CRITICAL",
      tone: "red",
      glowLight: "text-red-600",
      glowDark: "text-glow-red",
      border: "border-red-500/40",
      bg: "bg-red-500/10",
      bar: "bg-red-500",
      badge: "bg-red-500/15 text-red-700 dark:text-red-400 border-red-500/40",
    };
  }
  if (score >= 60) {
    return {
      level: "HIGH",
      tone: "amber",
      glowLight: "text-amber-600",
      glowDark: "text-glow-amber",
      border: "border-amber-500/40",
      bg: "bg-amber-500/10",
      bar: "bg-amber-400",
      badge: "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/40",
    };
  }
  if (score >= 30) {
    return {
      level: "ELEVATED",
      tone: "amber",
      glowLight: "text-amber-600",
      glowDark: "text-glow-amber",
      border: "border-amber-500/40",
      bg: "bg-amber-500/10",
      bar: "bg-amber-400",
      badge: "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/40",
    };
  }
  return {
    level: "NOMINAL",
    tone: "green",
    glowLight: "text-emerald-600",
    glowDark: "text-glow-green",
    border: "border-emerald-500/40",
    bg: "bg-emerald-500/10",
    bar: "bg-emerald-400",
    badge: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/40",
  };
}
