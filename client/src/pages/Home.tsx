import { useAuth } from "@/_core/hooks/useAuth";
import { useTheme } from "@/contexts/ThemeContext";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Laptop,
  Radar,
  Terminal,
  Activity,
  ArrowRight,
  CheckCircle2,
  Lock,
  Layers,
  FileText,
  MessageSquare,
  Zap,
  Globe,
  Sun,
  Moon,
  ExternalLink,
  ChevronRight,
  Cpu,
} from "lucide-react";
import { useLocation } from "wouter";

export default function Home() {
  const { isAuthenticated } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";
  const [, navigate] = useLocation();

  return (
    <div className="min-h-screen flex flex-col bg-[#f8fafc] dark:bg-[#060b13] text-slate-900 dark:text-slate-100 transition-colors duration-300 font-sans selection:bg-[#1884f7]/20 selection:text-[#1884f7]">
      
      {/* Top Navbar */}
      <header className="sticky top-0 z-50 w-full backdrop-blur-xl bg-white/80 dark:bg-[#070e1b]/80 border-b border-slate-200/70 dark:border-slate-800/70 transition-all">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between">
          
          {/* Logo with Blue Dot */}
          <div
            onClick={() => navigate("/")}
            className="flex items-center gap-2.5 cursor-pointer group"
          >
            <span className="h-6 w-6 rounded-full bg-[#1884f7] shadow-sm shadow-[#1884f7]/40 group-hover:scale-110 transition-transform" />
            <span className="text-xl font-black tracking-tight text-slate-900 dark:text-white">
              CyberGuard AI<span className="text-[#1884f7]">.</span>
            </span>
          </div>

          {/* Center Nav Links */}
          <nav className="hidden md:flex items-center gap-8 text-sm font-semibold text-slate-600 dark:text-slate-300">
            <a href="#features" className="hover:text-[#1884f7] dark:hover:text-[#1884f7] transition-colors">
              Platform
            </a>
            <a href="#edr" className="hover:text-[#1884f7] dark:hover:text-[#1884f7] transition-colors">
              Endpoint Fleet
            </a>
            <a href="#network" className="hover:text-[#1884f7] dark:hover:text-[#1884f7] transition-colors">
              Network EDR
            </a>
            <a href="#copilot" className="hover:text-[#1884f7] dark:hover:text-[#1884f7] transition-colors">
              SOC Copilot
            </a>
          </nav>

          {/* Right Action Buttons */}
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={toggleTheme}
              className="p-2 rounded-full text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/80 transition-colors"
              title="Toggle theme"
            >
              {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>

            {isAuthenticated ? (
              <Button
                onClick={() => navigate("/dashboard")}
                className="rounded-full bg-[#1884f7] hover:bg-[#1272d8] text-white font-semibold text-xs sm:text-sm px-6 py-2.5 shadow-md shadow-[#1884f7]/25"
              >
                Go to Dashboard
              </Button>
            ) : (
              <>
                <Button
                  variant="ghost"
                  onClick={() => navigate("/signin")}
                  className="rounded-full text-xs sm:text-sm font-semibold text-slate-700 dark:text-slate-200 hover:text-slate-900 dark:hover:text-white px-5"
                >
                  Sign In
                </Button>

                <Button
                  onClick={() => navigate("/signup")}
                  className="rounded-full bg-[#1884f7] hover:bg-[#1272d8] text-white font-semibold text-xs sm:text-sm px-6 py-2.5 shadow-md shadow-[#1884f7]/25 hover:scale-[1.02] active:scale-[0.98] transition-all"
                >
                  Get Started
                </Button>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative overflow-hidden pt-12 pb-20 md:pt-20 md:pb-28">
        {/* Soft Background Glows */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-96 bg-gradient-to-b from-blue-400/10 via-cyan-400/5 to-transparent blur-3xl pointer-events-none -z-10" />

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center space-y-8">
          
          {/* Eyebrow Pill */}
          <div className="inline-flex items-center gap-2 rounded-full border border-blue-500/20 bg-blue-500/5 dark:bg-blue-500/10 px-4 py-1.5 text-xs font-semibold text-blue-700 dark:text-blue-400 shadow-sm backdrop-blur-sm">
            <span className="h-2 w-2 rounded-full bg-[#1884f7] animate-pulse" />
            NEXT-GEN AI SECURITY OPERATIONS CENTER
          </div>

          {/* Main Title */}
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-black tracking-tight text-slate-900 dark:text-white max-w-4xl mx-auto leading-[1.08]">
            Defend Enterprise Fleet with Autonomous AI<span className="text-[#1884f7]">.</span>
          </h1>

          {/* Subtitle */}
          <p className="text-base sm:text-xl text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Real-time multi-PC endpoint telemetry, deep packet inspection, automated MITRE ATT&CK correlation, and AI-driven incident remediation in milliseconds.
          </p>

          {/* Primary CTA Buttons */}
          <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
            <Button
              size="lg"
              onClick={() => navigate("/signup")}
              className="rounded-full bg-[#1884f7] hover:bg-[#1272d8] text-white font-semibold text-sm sm:text-base px-8 py-3.5 shadow-xl shadow-[#1884f7]/30 hover:scale-105 active:scale-95 transition-all gap-2"
            >
              Get Started Free <ArrowRight className="h-4 w-4" />
            </Button>

            <Button
              size="lg"
              variant="outline"
              onClick={() => navigate("/signin")}
              className="rounded-full border-slate-300 dark:border-slate-700 font-semibold text-sm sm:text-base px-8 py-3.5 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
            >
              Sign In to Console
            </Button>

            <Button
              size="lg"
              variant="ghost"
              onClick={() => navigate("/demo")}
              className="rounded-full text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white text-sm sm:text-base px-6 py-3.5"
            >
              Explore Live Demo
            </Button>
          </div>

          {/* Live Interactive Hero Preview Card */}
          <div className="pt-10 max-w-5xl mx-auto">
            <div className="relative rounded-3xl border border-slate-200/80 dark:border-slate-800 bg-white/90 dark:bg-[#0c1626]/90 p-4 sm:p-7 shadow-[0_20px_60px_-15px_rgba(15,23,42,0.12)] dark:shadow-[0_25px_70px_-15px_rgba(0,0,0,0.6)] backdrop-blur-xl text-left">
              
              {/* Header inside Preview */}
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800/80 pb-4">
                <div className="flex items-center gap-3">
                  <div className="rounded-xl bg-[#1884f7]/10 p-2.5 text-[#1884f7]">
                    <ShieldCheck className="h-6 w-6" />
                  </div>
                  <div>
                    <h3 className="font-extrabold text-sm sm:text-base text-slate-900 dark:text-white flex items-center gap-2">
                      CyberGuard Active Fleet Defense
                      <Badge className="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-[10px]">
                        LIVE STREAMING
                      </Badge>
                    </h3>
                    <p className="text-xs text-slate-400 font-mono">SOC Console // Perimeter & Endpoints Synchronized</p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <div className="text-right hidden sm:block">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block">Fleet Risk Score</span>
                    <span className="font-black text-emerald-500 font-mono text-sm">12 / 100 (HEALTHY)</span>
                  </div>
                  <Button
                    size="sm"
                    onClick={() => navigate("/dashboard")}
                    className="rounded-full bg-[#1884f7] text-white text-xs h-8 px-4"
                  >
                    Open Console
                  </Button>
                </div>
              </div>

              {/* Grid with 3 Interactive Panels */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
                
                {/* Panel 1: Endpoints Fleet */}
                <div className="rounded-2xl border border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-[#08101d] p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-700 dark:text-slate-200 flex items-center gap-1.5">
                      <Laptop className="h-4 w-4 text-[#1884f7]" /> Monitored PCs
                    </span>
                    <span className="text-xs font-bold text-emerald-500">5 Online</span>
                  </div>
                  <div className="space-y-1.5 text-xs font-mono">
                    <div className="flex justify-between items-center bg-white dark:bg-[#0f1b2e] p-2 rounded-xl border border-slate-100 dark:border-slate-800">
                      <span>FIN-EXEC-PC01</span>
                      <span className="text-emerald-500 text-[11px]">Heartbeat OK</span>
                    </div>
                    <div className="flex justify-between items-center bg-white dark:bg-[#0f1b2e] p-2 rounded-xl border border-slate-100 dark:border-slate-800">
                      <span>DEV-UBUNTU-08</span>
                      <span className="text-emerald-500 text-[11px]">Heartbeat OK</span>
                    </div>
                  </div>
                </div>

                {/* Panel 2: Live Network Packet Flow */}
                <div className="rounded-2xl border border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-[#08101d] p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-700 dark:text-slate-200 flex items-center gap-1.5">
                      <Radar className="h-4 w-4 text-cyan-500" /> Network Telemetry
                    </span>
                    <span className="text-xs font-bold text-[#1884f7]">1,420 pkts/s</span>
                  </div>
                  <div className="space-y-1.5 text-xs font-mono">
                    <div className="flex justify-between items-center bg-white dark:bg-[#0f1b2e] p-2 rounded-xl border border-slate-100 dark:border-slate-800">
                      <span>192.168.1.45:443</span>
                      <span className="text-cyan-500 text-[11px]">HTTPS Allowed</span>
                    </div>
                    <div className="flex justify-between items-center bg-white dark:bg-[#0f1b2e] p-2 rounded-xl border border-slate-100 dark:border-slate-800">
                      <span>185.220.101.5:4444</span>
                      <span className="text-rose-500 text-[11px] font-bold">C2 Blocked</span>
                    </div>
                  </div>
                </div>

                {/* Panel 3: Gemini SOC Copilot */}
                <div className="rounded-2xl border border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-[#08101d] p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-700 dark:text-slate-200 flex items-center gap-1.5">
                      <MessageSquare className="h-4 w-4 text-emerald-500" /> AI SOC Analyst
                    </span>
                    <span className="text-xs font-bold text-slate-400">Gemini 2.5</span>
                  </div>
                  <div className="rounded-xl bg-white dark:bg-[#0f1b2e] p-2.5 border border-slate-100 dark:border-slate-800 text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">
                    "Identified suspicious outbound connection on port 4444 from powershell.exe. Host isolation rule automatically applied."
                  </div>
                </div>

              </div>
            </div>
          </div>

        </div>
      </section>

      {/* Feature Section */}
      <section id="features" className="py-20 border-t border-slate-200/70 dark:border-slate-800/70 bg-white dark:bg-[#09111e]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          <div className="text-center max-w-3xl mx-auto space-y-3 mb-16">
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-[#1884f7]">
              COMPLETE CYBER DEFENSE STACK
            </p>
            <h2 className="text-3xl sm:text-5xl font-black tracking-tight text-slate-900 dark:text-white">
              Built for Modern Security Operations Centers
            </h2>
            <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400">
              Replace fragmented cybersecurity point solutions with a unified, AI-native platform designed for enterprise scale.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            
            {/* Feature 1 */}
            <div className="rounded-3xl border border-slate-200/80 dark:border-slate-800 bg-slate-50/50 dark:bg-[#0b1424] p-7 space-y-4 hover:border-[#1884f7]/50 transition-all hover:shadow-lg">
              <div className="h-12 w-12 rounded-2xl bg-blue-500/10 text-[#1884f7] flex items-center justify-center">
                <Laptop className="h-6 w-6" />
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-white">Endpoint Fleet (EDR)</h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Monitor all Windows, Linux, and macOS workstations. Inspect active sockets, processes, and quarantine compromised hosts in 1 click.
              </p>
            </div>

            {/* Feature 2 */}
            <div className="rounded-3xl border border-slate-200/80 dark:border-slate-800 bg-slate-50/50 dark:bg-[#0b1424] p-7 space-y-4 hover:border-[#1884f7]/50 transition-all hover:shadow-lg">
              <div className="h-12 w-12 rounded-2xl bg-cyan-500/10 text-cyan-500 flex items-center justify-center">
                <Radar className="h-6 w-6" />
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-white">Live Network Capture</h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Stream live packet metadata and network flows with protocol breakdown (HTTPS, DNS, SSH, RDP) and instant C2 beacon detection.
              </p>
            </div>

            {/* Feature 3 */}
            <div className="rounded-3xl border border-slate-200/80 dark:border-slate-800 bg-slate-50/50 dark:bg-[#0b1424] p-7 space-y-4 hover:border-[#1884f7]/50 transition-all hover:shadow-lg">
              <div className="h-12 w-12 rounded-2xl bg-emerald-500/10 text-emerald-500 flex items-center justify-center">
                <Zap className="h-6 w-6" />
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-white">SOC Copilot Intelligence</h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Gemini-powered threat investigation, automated MITRE ATT&CK mapping, and actionable step-by-step incident response playbooks.
              </p>
            </div>

            {/* Feature 4 */}
            <div className="rounded-3xl border border-slate-200/80 dark:border-slate-800 bg-slate-50/50 dark:bg-[#0b1424] p-7 space-y-4 hover:border-[#1884f7]/50 transition-all hover:shadow-lg">
              <div className="h-12 w-12 rounded-2xl bg-purple-500/10 text-purple-500 flex items-center justify-center">
                <FileText className="h-6 w-6" />
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-white">Forensic Reporting</h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                High-throughput syslog, JSON, and CSV ingestion with cryptographic SHA-256 tamper-proof log integrity verification.
              </p>
            </div>

          </div>
        </div>
      </section>

      {/* Call to Action Section with Scenic Accent */}
      <section className="py-20 relative overflow-hidden bg-[#eef3f9] dark:bg-[#070d18]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center space-y-6">
          <h2 className="text-3xl sm:text-5xl font-black tracking-tight text-slate-900 dark:text-white">
            Ready to secure your enterprise fleet?
          </h2>
          <p className="text-base text-slate-600 dark:text-slate-400 max-w-xl mx-auto">
            Join security teams worldwide using CyberGuard AI to monitor workstations, detect anomalies, and prevent breaches.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4 pt-4">
            <Button
              size="lg"
              onClick={() => navigate("/signup")}
              className="rounded-full bg-[#1884f7] hover:bg-[#1272d8] text-white font-semibold text-base px-9 py-3.5 shadow-xl shadow-[#1884f7]/30 hover:scale-105 active:scale-95 transition-all gap-2"
            >
              Get Started Free <ArrowRight className="h-4 w-4" />
            </Button>

            <Button
              size="lg"
              variant="outline"
              onClick={() => navigate("/signin")}
              className="rounded-full border-slate-300 dark:border-slate-700 font-semibold text-base px-8 py-3.5 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
            >
              Sign In
            </Button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-200/80 dark:border-slate-800/80 bg-white dark:bg-[#050912] py-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <span className="h-4 w-4 rounded-full bg-[#1884f7]" />
            <span className="font-extrabold text-slate-800 dark:text-white text-sm">
              CyberGuard AI<span className="text-[#1884f7]">.</span>
            </span>
          </div>

          <div className="flex items-center gap-6">
            <button type="button" onClick={() => navigate("/signin")} className="hover:text-slate-900 dark:hover:text-white">
              Sign In
            </button>
            <button type="button" onClick={() => navigate("/signup")} className="hover:text-slate-900 dark:hover:text-white">
              Get Started
            </button>
            <button type="button" onClick={() => navigate("/demo")} className="hover:text-slate-900 dark:hover:text-white">
              Live Demo
            </button>
          </div>

          <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-mono">
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" /> ALL SYSTEMS OPERATIONAL
          </div>
        </div>
      </footer>

    </div>
  );
}
