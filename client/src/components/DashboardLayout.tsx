import { useAuth } from "@/_core/hooks/useAuth";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarSeparator,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import { useTheme } from "@/contexts/ThemeContext";
import { useIsMobile } from "@/hooks/useMobile";
import { Activity, Bell, FileBarChart, LayoutDashboard, LogOut, Lock, Moon, PanelLeft, Search, Settings, Shield, ShieldBan, ShieldAlert, Sun, Upload, MessageSquare } from "lucide-react";
import { CSSProperties, useEffect, useRef, useState } from "react";
import { useLocation } from "wouter";
import { DashboardLayoutSkeleton } from './DashboardLayoutSkeleton';

const menuItems = [
  { icon: LayoutDashboard, label: "Dashboard", path: "/dashboard", adminOnly: false },
  { icon: ShieldAlert, label: "Network Monitor", path: "/network", adminOnly: false },
  { icon: Shield, label: "Endpoints", path: "/endpoints", adminOnly: false },
  { icon: ShieldAlert, label: "Demo Flow", path: "/demo", adminOnly: false },
  { icon: ShieldAlert, label: "Threats", path: "/threats", adminOnly: true },
  { icon: Upload, label: "Log Upload", path: "/logs/upload", adminOnly: true },
  { icon: MessageSquare, label: "SOC Copilot", path: "/copilot", adminOnly: true },
  { icon: FileBarChart, label: "Reports", path: "/reports", adminOnly: true },
  { icon: Settings, label: "Settings", path: "/settings", adminOnly: false, disabled: false },
];

// Routes gated to admins only — matches menuItems' adminOnly flags, checked
// by prefix so nested routes (e.g. /threats/:id) are covered too.
function isAdminOnlyPath(path: string): boolean {
  return menuItems.some((item) => item.adminOnly && path.startsWith(item.path));
}

function getInitials(name?: string | null, email?: string | null): string {
  const trimmedName = name?.trim();
  if (trimmedName) {
    const initials = trimmedName
      .split(/\s+/)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase())
      .join("");
    if (initials) return initials;
  }
  return email?.charAt(0).toUpperCase() || "?";
}

const SIDEBAR_WIDTH_KEY = "sidebar-width";
const DEFAULT_WIDTH = 280;
const MIN_WIDTH = 200;
const MAX_WIDTH = 480;

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    const saved = localStorage.getItem(SIDEBAR_WIDTH_KEY);
    return saved ? parseInt(saved, 10) : DEFAULT_WIDTH;
  });
  const { user, isAuthenticated, loading, error } = useAuth();
  const [, navigate] = useLocation();

  useEffect(() => {
    localStorage.setItem(SIDEBAR_WIDTH_KEY, sidebarWidth.toString());
  }, [sidebarWidth]);

  useEffect(() => {
    if (!loading && !isAuthenticated && !error) {
      navigate("/signin");
    }
  }, [loading, isAuthenticated, error, navigate]);

  // Show a clear error when the backend/database is unreachable
  if (!loading && error && !isAuthenticated) {
    const isServiceDown = /database|unavailable|econnreset|connection/i.test(
      error.message || ""
    );
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-zinc-50 p-6 text-center dark:bg-zinc-950">
        <div className="flex flex-col items-center gap-4 rounded-xl border border-amber-500/30 bg-amber-500/5 p-10 dark:bg-amber-500/10">
          <Shield className="h-12 w-12 text-amber-500" />
          <p className="text-sm font-semibold text-amber-600 dark:text-amber-400">
            {isServiceDown
              ? "Service Temporarily Unavailable"
              : "Authentication Error"}
          </p>
          <p className="max-w-md font-mono text-xs text-zinc-600 dark:text-zinc-400">
            {isServiceDown
              ? "The database is currently unreachable. This may be a temporary issue — please try again in a moment."
              : "Unable to verify your session. Please sign in again."}
          </p>
          <div className="flex gap-3 mt-2">
            <button
              onClick={() => window.location.reload()}
              className="rounded-lg border border-amber-500/50 bg-amber-50 px-4 py-2 text-xs font-semibold text-amber-700 hover:bg-amber-100 dark:bg-amber-500/20 dark:text-amber-300 dark:hover:bg-amber-500/30"
            >
              Retry
            </button>
            <button
              onClick={() => navigate("/signin")}
              className="rounded-lg border border-zinc-300 px-4 py-2 text-xs font-semibold text-zinc-700 hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
            >
              Sign In
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (loading || !isAuthenticated || !user) {
    return <DashboardLayoutSkeleton />
  }

  return (
    <SidebarProvider
      style={
        {
          "--sidebar-width": `${sidebarWidth}px`,
        } as CSSProperties
      }
    >
      <DashboardLayoutContent setSidebarWidth={setSidebarWidth}>
        {children}
      </DashboardLayoutContent>
    </SidebarProvider>
  );
}

type DashboardLayoutContentProps = {
  children: React.ReactNode;
  setSidebarWidth: (width: number) => void;
};

function DashboardLayoutContent({
  children,
  setSidebarWidth,
}: DashboardLayoutContentProps) {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [location, setLocation] = useLocation();
  const { state, toggleSidebar } = useSidebar();
  const isCollapsed = state === "collapsed";
  const [isResizing, setIsResizing] = useState(false);
  const sidebarRef = useRef<HTMLDivElement>(null);
  const isMobile = useIsMobile();
  const isAdmin = user?.role === "admin";
  const routeIsRestricted = isAdminOnlyPath(location) && !isAdmin;

  useEffect(() => {
    if (isCollapsed) {
      setIsResizing(false);
    }
  }, [isCollapsed]);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing) return;

      const sidebarLeft = sidebarRef.current?.getBoundingClientRect().left ?? 0;
      const newWidth = e.clientX - sidebarLeft;
      if (newWidth >= MIN_WIDTH && newWidth <= MAX_WIDTH) {
        setSidebarWidth(newWidth);
      }
    };

    const handleMouseUp = () => {
      setIsResizing(false);
    };

    if (isResizing) {
      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
    }

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [isResizing, setSidebarWidth]);

  return (
    <>
      <div className="relative" ref={sidebarRef}>
        <Sidebar
          collapsible="icon"
          className="border-r-0 bg-transparent"
          disableTransition={isResizing}
        >
          <SidebarHeader className="h-20 justify-center border-b border-cyan-400/10">
            <div className="flex items-center gap-3 px-2 transition-all w-full">
              <button
                onClick={toggleSidebar}
                className="h-8 w-8 flex items-center justify-center hover:bg-accent rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ring shrink-0"
                aria-label="Toggle navigation"
              >
                <PanelLeft className="h-4 w-4 text-muted-foreground" />
              </button>
              {!isCollapsed ? (
                <div className="flex items-center gap-2 min-w-0">
                  <Shield className="h-5 w-5 text-cyan-600" />
                  <div className="min-w-0"><span className="block truncate text-sm font-bold tracking-tight text-slate-900">CyberGuard AI</span><span className="tech-label block truncate text-[9px] text-cyan-700/80">Detect • Analyze • Secure</span></div>
                </div>
              ) : null}
            </div>
          </SidebarHeader>

          <SidebarContent className="gap-0 px-2 pt-4">
            {!isCollapsed && <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">Operations</p>}
            <SidebarMenu className="px-2 py-1">
              {menuItems.map(item => {
                const isActive = location === item.path;
                const isLocked = item.adminOnly && !isAdmin;
                return (
                  <SidebarMenuItem key={item.path}>
                    <SidebarMenuButton
                      isActive={isActive}
                      onClick={() => { if (!item.disabled) setLocation(item.path); }}
                      tooltip={isLocked ? `${item.label} — Admin only` : item.disabled ? `${item.label} — Coming soon` : item.label}
                      className={`h-10 rounded-lg font-normal transition-all ${isLocked || item.disabled ? "opacity-40" : ""} ${isActive ? "border border-cyan-400/25 bg-cyan-400/10 text-cyan-800 shadow-[0_0_18px_rgba(34,211,238,0.08)] dark:text-cyan-100" : "text-slate-600 hover:bg-slate-200/70 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/60 dark:hover:text-slate-100"}`}
                    >
                      <item.icon
                        className={`h-4 w-4 ${isActive ? "text-primary" : ""}`}
                      />
                      <span>{item.label}</span>
                      {isLocked && <Lock className="ml-auto h-3 w-3 text-muted-foreground" />}
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarContent>

          <SidebarSeparator className="mx-0 bg-cyan-400/10" />

          <SidebarFooter className="gap-3 p-3">
            <div className="flex items-center gap-3 px-1">
              <Avatar className="h-9 w-9 border shrink-0">
                <AvatarFallback className="text-xs font-medium">
                  {getInitials(user?.name, user?.email)}
                </AvatarFallback>
              </Avatar>
              <div className="flex-1 min-w-0 group-data-[collapsible=icon]:hidden">
                <p className="text-sm font-medium truncate leading-none text-slate-900 dark:text-slate-100">
                  {user?.name || user?.email || "-"}
                </p>
                <Badge
                  variant="outline"
                  className={`mt-1.5 h-4 px-1.5 text-[9px] font-mono uppercase tracking-wider ${
                    isAdmin
                      ? "border-cyan-500/40 text-cyan-700 dark:text-cyan-400"
                      : "border-zinc-300 text-zinc-500 dark:border-zinc-700 dark:text-zinc-500"
                  }`}
                >
                  {user?.role ?? "user"}
                </Badge>
              </div>
            </div>

            <div className="flex items-center gap-1 group-data-[collapsible=icon]:flex-col">
              <button
                onClick={toggleTheme}
                title={theme === "dark" ? "Light mode" : "Dark mode"}
                aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
                className="h-8 w-8 flex items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              </button>
              <button
                onClick={logout}
                title="Sign out"
                aria-label="Sign out"
                className="h-8 w-8 flex items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-destructive/10 hover:text-destructive focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          </SidebarFooter>
        </Sidebar>
        <div
          className={`absolute top-0 right-0 w-1 h-full cursor-col-resize hover:bg-primary/20 transition-colors ${isCollapsed ? "hidden" : ""}`}
          onMouseDown={() => {
            if (isCollapsed) return;
            setIsResizing(true);
          }}
          style={{ zIndex: 50 }}
        />
      </div>

      <SidebarInset className="bg-transparent">
        <header className="sticky top-0 z-30 flex min-h-16 items-center justify-between gap-4 border-b border-border bg-background/85 px-4 py-3 backdrop-blur-xl lg:px-8">
          <div className="flex min-w-0 flex-1 items-center gap-3">
            {isMobile && <SidebarTrigger className="h-9 w-9 shrink-0 rounded-lg border border-border bg-card/80" />}
            <div className="relative hidden min-w-0 max-w-xl flex-1 md:block"><Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" /><input aria-label="Search security data" placeholder="Search logs, IP addresses, threats..." className="h-9 w-full rounded-lg border border-border bg-card/80 pl-10 pr-16 text-sm text-foreground outline-none transition focus:border-primary/60 focus:ring-2 focus:ring-primary/10" /><kbd className="absolute right-2 top-1.5 rounded border border-border px-1.5 py-1 text-[10px] text-muted-foreground">Ctrl K</kbd></div>
          </div>
          <div className="flex items-center gap-2">
            <div className="hidden items-center gap-2 text-xs text-muted-foreground sm:flex">
              <Activity className="h-3.5 w-3.5 text-emerald-500" /> Systems nominal
            </div>

            <button
              onClick={toggleTheme}
              title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-border bg-card/80 text-xs font-medium text-foreground transition hover:bg-accent focus:outline-none"
            >
              {theme === "dark" ? (
                <>
                  <Sun className="h-3.5 w-3.5 text-amber-400" />
                  <span className="hidden sm:inline">Light</span>
                </>
              ) : (
                <>
                  <Moon className="h-3.5 w-3.5 text-indigo-500" />
                  <span className="hidden sm:inline">Dark</span>
                </>
              )}
            </button>

            <button aria-label="Notifications" title="Notifications" className="rounded-lg p-2 text-muted-foreground transition hover:bg-accent hover:text-foreground">
              <Bell className="h-4 w-4" />
            </button>
          </div>
        </header>
        <main className="flex-1 p-4">
          {routeIsRestricted ? <AccessDenied /> : children}
        </main>
      </SidebarInset>
    </>
  );
}

function AccessDenied() {
  return (
    <div className="blueprint-grid -m-4 flex min-h-[calc(100vh-2rem)] flex-col items-center justify-center gap-4 bg-zinc-50 p-6 text-center dark:bg-zinc-950">
      <div className="flex flex-col items-center gap-4 rounded-xl border border-red-500/30 bg-red-500/5 p-10 dark:bg-red-500/10">
        <ShieldBan className="h-12 w-12 text-red-500" />
        <p className="tech-label text-red-600 dark:text-red-400">Access Denied</p>
        <p className="max-w-md font-mono text-sm text-zinc-600 dark:text-zinc-400">
          Access Denied: Enterprise Security Node requires Tier-3 Administrator Permissions.
        </p>
      </div>
    </div>
  );
}
