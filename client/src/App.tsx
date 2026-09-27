import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Home from "./pages/Home";
import SignIn from "./pages/SignIn";
import SignUp from "./pages/SignUp";
import Dashboard from "./pages/Dashboard";
import LogUpload from "./pages/LogUpload";
import Threats from "./pages/Threats";
import ThreatDetail from "./pages/ThreatDetail";
import SocCopilot from "./pages/SocCopilot";
import DemoPage from "./pages/DemoPage";
import NetworkMonitor from "./pages/NetworkMonitor";
import Reports from "./pages/Reports";
import Endpoints from "./pages/Endpoints";
import Settings from "./pages/Settings";

function Router() {
  // Dashboard-shell routes (Dashboard, LogUpload, Threats, SocCopilot, DemoPage)
  // are gated inside DashboardLayout, which redirects to /signin when
  // unauthenticated and applies role-based access control.
  return (
    <Switch>
      <Route path={"/"} component={Home} />
      <Route path={"/signin"} component={SignIn} />
      <Route path={"/signup"} component={SignUp} />
      <Route path={"/dashboard"} component={Dashboard} />
      <Route path={"/logs/upload"} component={LogUpload} />
      <Route path={"/threats"} component={Threats} />
      <Route path={"/threats/:id"} component={ThreatDetail} />
      <Route path={"/copilot"} component={SocCopilot} />
      <Route path={"/network"} component={NetworkMonitor} />
      <Route path={"/endpoints"} component={Endpoints} />
      <Route path={"/reports"} component={Reports} />
      <Route path={"/settings"} component={Settings} />
      <Route path={"/demo"} component={DemoPage} />
      <Route path={"/404"} component={NotFound} />
      {/* Final fallback route */}
      <Route component={NotFound} />
    </Switch>
  );
}

// NOTE: About Theme
// - First choose a default theme according to your design style (dark or light bg), than change color palette in index.css
//   to keep consistent foreground/background color across components
// - If you want to make theme switchable, pass `switchable` ThemeProvider and use `useTheme` hook

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider
        defaultTheme="dark"
        switchable
      >
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
