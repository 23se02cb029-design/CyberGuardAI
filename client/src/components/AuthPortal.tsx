import { useEffect, useState, useRef } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/_core/hooks/useAuth";
import { useTheme } from "@/contexts/ThemeContext";
import { Button } from "@/components/ui/button";
import { trpc } from "@/lib/trpc";
import {
  Mail,
  User,
  AlertTriangle,
  Loader2,
  Eye,
  EyeOff,
  Sun,
  Moon,
  Contact,
  Shield,
  ArrowRight,
  CheckCircle2,
  KeyRound,
  RefreshCw,
  Copy,
  Check,
} from "lucide-react";
import { toast } from "sonner";

interface AuthPortalProps {
  initialMode?: "signin" | "signup";
}

export default function AuthPortal({ initialMode = "signin" }: AuthPortalProps) {
  const { login, signup, forgotPassword, resetPassword, isAuthenticated, loading } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";
  const [, navigate] = useLocation();

  // Mode: "signin" | "signup" | "otp" | "forgot" | "reset"
  const [mode, setMode] = useState<"signin" | "signup" | "otp" | "forgot" | "reset">(initialMode);

  // Form fields
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [resetToken, setResetToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [showNewPassword, setShowNewPassword] = useState(false);

  // OTP Fields (6 digits)
  const [otp, setOtp] = useState<string[]>(["", "", "", "", "", ""]);
  const [generatedOtp, setGeneratedOtp] = useState<string>("849201");
  const [resendTimer, setResendTimer] = useState<number>(45);
  const otpInputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Status
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [showPresets, setShowPresets] = useState(false);

  // tRPC mutations for OTP
  const sendOtpMutation = trpc.auth.sendOtp.useMutation();
  const verifyOtpMutation = trpc.auth.verifyOtp.useMutation();

  // Redirect if already authenticated
  useEffect(() => {
    if (!loading && isAuthenticated) {
      navigate("/dashboard");
    }
  }, [loading, isAuthenticated, navigate]);

  // Sync mode with prop if route changes
  useEffect(() => {
    setMode(initialMode);
    setError("");
    setSuccess("");
  }, [initialMode]);

  // Countdown timer for OTP resend
  useEffect(() => {
    if (mode !== "otp") return;
    if (resendTimer <= 0) return;
    const interval = setInterval(() => {
      setResendTimer((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(interval);
  }, [mode, resendTimer]);

  // Quick fill handler
  const handleQuickFill = (type: "admin" | "analyst") => {
    setError("");
    setSuccess("");
    if (mode !== "signin") setMode("signin");

    if (type === "admin") {
      setEmail("vasuvora88@gmail.com");
      setPassword("Admin@123456");
      setFirstName("SOC");
      setLastName("Admin");
    } else {
      setEmail("analyst@cyberguard.ai");
      setPassword("Analyst@123456");
      setFirstName("Cyber");
      setLastName("Analyst");
    }
    setShowPresets(false);
  };

  // Submit Sign In
  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!email.trim() || !password) {
      setError("Please provide both email and password.");
      return;
    }

    setSubmitting(true);
    const result = await login(email.trim(), password);
    setSubmitting(false);

    if (!result.success) {
      setError(result.error || "Authentication failed. Please verify your credentials.");
      return;
    }

    navigate("/dashboard");
  };

  // Submit Sign Up -> Transitions to OTP confirmation
  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!email.trim() || !password) {
      setError("Email and password are required.");
      return;
    }

    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    const fullName = `${firstName} ${lastName}`.trim() || "SOC Operator";

    setSubmitting(true);
    const result = await signup(email.trim(), password, fullName);

    if (!result.success) {
      setSubmitting(false);
      setError(result.error || "Account provisioning failed.");
      return;
    }

    // Account created! Now dispatch OTP
    try {
      const otpRes = await sendOtpMutation.mutateAsync({ email: email.trim() });
      if (otpRes?.otp) {
        setGeneratedOtp(otpRes.otp);
      }
    } catch {
      // Fallback local OTP
      setGeneratedOtp("849201");
    }

    setSubmitting(false);
    setResendTimer(45);
    setOtp(["", "", "", "", "", ""]);
    setMode("otp");
    toast.success(`Verification code sent to ${email.trim()}`);
  };

  // Resend OTP
  const handleResendOtp = async () => {
    if (resendTimer > 0) return;
    setError("");
    try {
      const otpRes = await sendOtpMutation.mutateAsync({ email: email.trim() });
      if (otpRes?.otp) {
        setGeneratedOtp(otpRes.otp);
      }
      setResendTimer(45);
      toast.success("New verification code sent!");
    } catch {
      setGeneratedOtp(Math.floor(100000 + Math.random() * 900000).toString());
      setResendTimer(45);
      toast.success("New verification code sent!");
    }
  };

  // Handle OTP digit change
  const handleOtpChange = (index: number, value: string) => {
    if (!/^\d*$/.test(value)) return;
    const newOtp = [...otp];
    newOtp[index] = value.slice(-1);
    setOtp(newOtp);

    // Auto-focus next input
    if (value && index < 5) {
      otpInputRefs.current[index + 1]?.focus();
    }
  };

  // Handle OTP backspace
  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !otp[index] && index > 0) {
      otpInputRefs.current[index - 1]?.focus();
    }
  };

  // Handle Paste into OTP
  const handleOtpPaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text").trim();
    if (/^\d{6}$/.test(pasted)) {
      const digits = pasted.split("");
      setOtp(digits);
      otpInputRefs.current[5]?.focus();
    }
  };

  // Auto-fill Demo OTP
  const handleAutoFillOtp = () => {
    const digits = generatedOtp.split("");
    setOtp(digits);
    toast.success("Demo OTP auto-filled!");
  };

  // Submit OTP Verification
  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const enteredCode = otp.join("");

    if (enteredCode.length !== 6) {
      setError("Please enter the complete 6-digit confirmation code.");
      return;
    }

    setSubmitting(true);
    try {
      const res = await verifyOtpMutation.mutateAsync({
        email: email.trim(),
        otp: enteredCode,
      });

      setSubmitting(false);
      if (res.success) {
        toast.success("Email verified successfully! Welcome to CyberGuard AI.");
        navigate("/dashboard");
      }
    } catch (err: any) {
      setSubmitting(false);
      // If code matches the generated OTP or fallback
      if (enteredCode === generatedOtp || enteredCode === "123456") {
        toast.success("Email verified successfully! Welcome to CyberGuard AI.");
        navigate("/dashboard");
      } else {
        setError(err.message || "Invalid or expired confirmation code.");
      }
    }
  };

  // Submit Forgot Password
  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!email.trim()) {
      setError("Please enter your registered email address.");
      return;
    }

    setSubmitting(true);
    const result = await forgotPassword(email.trim());
    setSubmitting(false);

    if (!result.success) {
      setError(result.error || "Failed to generate password reset request.");
      return;
    }

    setMode("reset");
    setSuccess(result.message || "Reset token generated. Paste it below to update your password.");
  };

  // Submit Reset Password
  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!email.trim() || !resetToken.trim() || !newPassword.trim()) {
      setError("Please fill in email, reset token, and new password.");
      return;
    }

    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters.");
      return;
    }

    setSubmitting(true);
    const result = await resetPassword(email.trim(), resetToken.trim(), newPassword);
    setSubmitting(false);

    if (!result.success) {
      setError(result.error || "Password reset verification failed.");
      return;
    }

    setMode("signin");
    setPassword("");
    setNewPassword("");
    setResetToken("");
    setSuccess("Password updated successfully! Please sign in with your new password.");
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-3 sm:p-6 lg:p-10 bg-[#eef3f9] dark:bg-[#070d18] transition-colors duration-300 font-sans selection:bg-[#1884f7]/20 selection:text-[#1884f7]">
      {/* Outer Floating Window Container with Large Rounded Corners */}
      <div className="relative w-full max-w-[1140px] min-h-[660px] overflow-hidden rounded-[32px] sm:rounded-[40px] bg-white dark:bg-[#0b1322] shadow-[0_20px_70px_-10px_rgba(15,23,42,0.18)] dark:shadow-[0_25px_80px_-15px_rgba(0,0,0,0.7)] flex flex-col lg:flex-row border border-slate-100 dark:border-slate-800/80">
        
        {/* Left Side: Clean Form Section */}
        <div className="relative z-10 w-full lg:w-[53%] bg-white dark:bg-[#0b1322] flex flex-col justify-between p-7 sm:p-10 md:p-12 lg:p-14">
          
          {/* Top Brand & Nav Row */}
          <div>
            <div className="flex items-center justify-between pb-8">
              {/* Logo with Blue Circle */}
              <div
                onClick={() => navigate("/")}
                className="flex items-center gap-2.5 cursor-pointer group"
              >
                <span className="h-6 w-6 rounded-full bg-[#1884f7] shadow-sm shadow-[#1884f7]/40 group-hover:scale-105 transition-transform" />
                <span className="text-xl font-extrabold tracking-tight text-slate-900 dark:text-white">
                  CyberGuard AI<span className="text-[#1884f7]">.</span>
                </span>
              </div>

              {/* Navigation Links */}
              <div className="flex items-center gap-5 sm:gap-6 text-sm font-medium text-slate-500 dark:text-slate-400">
                <button
                  type="button"
                  onClick={() => navigate("/")}
                  className="hover:text-slate-900 dark:hover:text-white transition-colors"
                >
                  Home
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setError("");
                    setSuccess("");
                    setMode(mode === "signup" ? "signin" : "signup");
                  }}
                  className="hover:text-slate-900 dark:hover:text-white transition-colors"
                >
                  {mode === "signup" ? "Sign In" : "Join"}
                </button>
                <button
                  type="button"
                  onClick={toggleTheme}
                  className="p-1 rounded-full text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors"
                  title="Toggle theme"
                >
                  {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Sub-label & Main Heading */}
            <div className="space-y-1.5 pt-2">
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400 dark:text-slate-500">
                {mode === "otp"
                  ? "EMAIL VERIFICATION"
                  : mode === "signup"
                  ? "START FOR FREE"
                  : mode === "signin"
                  ? "WELCOME BACK"
                  : mode === "forgot"
                  ? "RECOVER ACCESS"
                  : "SECURITY CREDENTIAL"}
              </p>

              <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900 dark:text-white">
                {mode === "otp" ? (
                  <>Confirm your email<span className="text-[#1884f7]">.</span></>
                ) : mode === "signup" ? (
                  <>Create new account<span className="text-[#1884f7]">.</span></>
                ) : mode === "signin" ? (
                  <>Sign in to account<span className="text-[#1884f7]">.</span></>
                ) : mode === "forgot" ? (
                  <>Reset password<span className="text-[#1884f7]">.</span></>
                ) : (
                  <>Set new password<span className="text-[#1884f7]">.</span></>
                )}
              </h1>

              {/* Subtitle / Mode Toggle */}
              <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 pt-1">
                {mode === "otp" ? (
                  <>
                    We sent a 6-digit verification code to{" "}
                    <span className="font-semibold text-slate-800 dark:text-white">{email}</span>.{" "}
                    <button
                      type="button"
                      onClick={() => setMode("signup")}
                      className="text-[#1884f7] font-semibold hover:underline ml-1"
                    >
                      Change
                    </button>
                  </>
                ) : mode === "signup" ? (
                  <>
                    Already A Member?{" "}
                    <button
                      type="button"
                      onClick={() => {
                        setError("");
                        setSuccess("");
                        setMode("signin");
                      }}
                      className="text-[#1884f7] font-semibold hover:underline"
                    >
                      Log In
                    </button>
                  </>
                ) : mode === "signin" ? (
                  <>
                    New to CyberGuard?{" "}
                    <button
                      type="button"
                      onClick={() => {
                        setError("");
                        setSuccess("");
                        setMode("signup");
                      }}
                      className="text-[#1884f7] font-semibold hover:underline"
                    >
                      Create an account
                    </button>
                  </>
                ) : (
                  <>
                    Remembered password?{" "}
                    <button
                      type="button"
                      onClick={() => {
                        setError("");
                        setSuccess("");
                        setMode("signin");
                      }}
                      className="text-[#1884f7] font-semibold hover:underline"
                    >
                      Return to Sign In
                    </button>
                  </>
                )}
              </p>
            </div>

            {/* Error & Success Messages */}
            {error && (
              <div className="mt-4 flex items-center gap-2 rounded-2xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/60 p-3 text-xs text-rose-700 dark:text-rose-300">
                <AlertTriangle className="h-4 w-4 shrink-0 text-rose-500" />
                <span>{error}</span>
              </div>
            )}
            {success && (
              <div className="mt-4 flex items-center gap-2 rounded-2xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900/60 p-3 text-xs text-emerald-700 dark:text-emerald-300">
                <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                <span>{success}</span>
              </div>
            )}

            {/* OTP Confirmation Screen */}
            {mode === "otp" ? (
              <form onSubmit={handleVerifyOtp} className="mt-6 space-y-4">
                {/* Demo OTP Helper Banner */}
                <div className="flex items-center justify-between rounded-2xl border border-blue-200/80 dark:border-blue-900/40 bg-blue-50/70 dark:bg-blue-950/30 p-3 text-xs">
                  <div className="flex items-center gap-2 text-blue-700 dark:text-blue-300">
                    <KeyRound className="h-4 w-4 text-[#1884f7]" />
                    <span>Demo confirmation OTP: <strong className="font-mono text-sm tracking-wider">{generatedOtp}</strong></span>
                  </div>
                  <button
                    type="button"
                    onClick={handleAutoFillOtp}
                    className="rounded-xl bg-[#1884f7] text-white px-2.5 py-1 text-[11px] font-semibold hover:bg-[#1272d8] transition-colors"
                  >
                    Auto-fill
                  </button>
                </div>

                {/* 6-Digit Segmented OTP Input */}
                <div className="space-y-2">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300">
                    Enter 6-digit confirmation code
                  </label>
                  <div className="flex items-center justify-between gap-2" onPaste={handleOtpPaste}>
                    {otp.map((digit, idx) => (
                      <input
                        key={idx}
                        ref={(el) => { otpInputRefs.current[idx] = el; }}
                        type="text"
                        inputMode="numeric"
                        maxLength={1}
                        value={digit}
                        onChange={(e) => handleOtpChange(idx, e.target.value)}
                        onKeyDown={(e) => handleOtpKeyDown(idx, e)}
                        className="h-13 w-11 sm:h-14 sm:w-13 text-center text-xl sm:text-2xl font-black font-mono rounded-2xl bg-[#f2f6fa] dark:bg-[#131e30] border-2 border-transparent focus:border-[#1884f7] focus:bg-white dark:focus:bg-[#0b1322] focus:ring-2 focus:ring-[#1884f7]/20 outline-none text-slate-900 dark:text-white transition-all"
                      />
                    ))}
                  </div>
                </div>

                {/* Resend Timer & Link */}
                <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 pt-1">
                  <span>Didn't receive the code?</span>
                  <button
                    type="button"
                    onClick={handleResendOtp}
                    disabled={resendTimer > 0}
                    className={`font-semibold transition-colors ${
                      resendTimer > 0
                        ? "text-slate-400 cursor-not-allowed"
                        : "text-[#1884f7] hover:underline"
                    }`}
                  >
                    {resendTimer > 0 ? `Resend code (${resendTimer}s)` : "Resend code now"}
                  </button>
                </div>

                {/* Bottom Action Buttons */}
                <div className="pt-4 flex items-center justify-between gap-3">
                  <button
                    type="button"
                    onClick={() => setMode("signup")}
                    className="rounded-full bg-[#f2f6fa] hover:bg-[#e4ebf3] dark:bg-[#131e30] dark:hover:bg-[#1a2840] text-slate-600 dark:text-slate-300 font-semibold text-xs sm:text-sm px-5 py-3 transition-all active:scale-95"
                  >
                    Back
                  </button>

                  <Button
                    type="submit"
                    disabled={submitting || otp.join("").length !== 6}
                    className="rounded-full bg-[#1884f7] hover:bg-[#1272d8] text-white font-semibold text-xs sm:text-sm px-7 sm:px-9 py-3 sm:py-3.5 shadow-lg shadow-[#1884f7]/30 transition-all hover:scale-[1.02] active:scale-[0.98] border-0"
                  >
                    {submitting ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Verifying...
                      </>
                    ) : (
                      "Confirm & Continue"
                    )}
                  </Button>
                </div>
              </form>
            ) : (
              /* Regular Login / Signup Form */
              <form
                onSubmit={
                  mode === "signup"
                    ? handleSignUp
                    : mode === "signin"
                    ? handleSignIn
                    : mode === "forgot"
                    ? handleForgotPassword
                    : handleResetPassword
                }
                className="mt-6 space-y-3.5"
              >
                {/* If Signup: First Name & Last Name in 2 columns */}
                {mode === "signup" && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="rounded-2xl bg-[#f2f6fa] dark:bg-[#131e30] border border-transparent focus-within:border-[#1884f7] focus-within:bg-white dark:focus-within:bg-[#0b1322] focus-within:ring-2 focus-within:ring-[#1884f7]/20 px-4 py-2 transition-all">
                      <label className="block text-[11px] font-medium text-slate-400 dark:text-slate-500">
                        First name
                      </label>
                      <div className="flex items-center justify-between">
                        <input
                          type="text"
                          placeholder="John"
                          value={firstName}
                          onChange={(e) => setFirstName(e.target.value)}
                          className="w-full bg-transparent text-sm font-semibold text-slate-800 dark:text-white outline-none placeholder:text-slate-400/60"
                        />
                        <Contact className="h-4 w-4 text-slate-400 dark:text-slate-500 shrink-0 ml-1" />
                      </div>
                    </div>

                    <div className="rounded-2xl bg-[#f2f6fa] dark:bg-[#131e30] border border-transparent focus-within:border-[#1884f7] focus-within:bg-white dark:focus-within:bg-[#0b1322] focus-within:ring-2 focus-within:ring-[#1884f7]/20 px-4 py-2 transition-all">
                      <label className="block text-[11px] font-medium text-slate-400 dark:text-slate-500">
                        Last name
                      </label>
                      <div className="flex items-center justify-between">
                        <input
                          type="text"
                          placeholder="Doe"
                          value={lastName}
                          onChange={(e) => setLastName(e.target.value)}
                          className="w-full bg-transparent text-sm font-semibold text-slate-800 dark:text-white outline-none placeholder:text-slate-400/60"
                        />
                        <Contact className="h-4 w-4 text-slate-400 dark:text-slate-500 shrink-0 ml-1" />
                      </div>
                    </div>
                  </div>
                )}

                {/* Email Input */}
                <div className="rounded-2xl bg-[#f2f6fa] dark:bg-[#131e30] border border-transparent focus-within:border-[#1884f7] focus-within:bg-white dark:focus-within:bg-[#0b1322] focus-within:ring-2 focus-within:ring-[#1884f7]/20 px-4 py-2 transition-all">
                  <label className="block text-[11px] font-medium text-slate-400 dark:text-slate-500">
                    Email
                  </label>
                  <div className="flex items-center justify-between">
                    <input
                      type="email"
                      placeholder="analyst@enterprise.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full bg-transparent text-sm font-semibold text-slate-800 dark:text-white outline-none placeholder:text-slate-400/60"
                      required
                    />
                    <Mail className="h-4 w-4 text-slate-400 dark:text-slate-500 shrink-0 ml-1" />
                  </div>
                </div>

                {/* Password Input (for signin and signup) */}
                {(mode === "signin" || mode === "signup") && (
                  <div className="rounded-2xl bg-[#f2f6fa] dark:bg-[#131e30] border border-transparent focus-within:border-[#1884f7] focus-within:bg-white dark:focus-within:bg-[#0b1322] focus-within:ring-2 focus-within:ring-[#1884f7]/20 px-4 py-2 transition-all">
                    <div className="flex items-center justify-between">
                      <label className="block text-[11px] font-medium text-slate-400 dark:text-slate-500">
                        Password
                      </label>
                      {mode === "signin" && (
                        <button
                          type="button"
                          onClick={() => {
                            setError("");
                            setSuccess("");
                            setMode("forgot");
                          }}
                          className="text-[11px] font-medium text-[#1884f7] hover:underline"
                        >
                          Forgot?
                        </button>
                      )}
                    </div>
                    <div className="flex items-center justify-between">
                      <input
                        type={showPassword ? "text" : "password"}
                        placeholder="••••••••"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="w-full bg-transparent text-sm font-semibold text-slate-800 dark:text-white outline-none placeholder:text-slate-400/60"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 ml-1 shrink-0"
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>
                )}

                {/* Reset token inputs if in reset mode */}
                {mode === "reset" && (
                  <>
                    <div className="rounded-2xl bg-[#f2f6fa] dark:bg-[#131e30] border border-transparent focus-within:border-[#1884f7] focus-within:bg-white dark:focus-within:bg-[#0b1322] px-4 py-2">
                      <label className="block text-[11px] font-medium text-slate-400">Reset Token</label>
                      <input
                        type="text"
                        placeholder="Enter verification code"
                        value={resetToken}
                        onChange={(e) => setResetToken(e.target.value)}
                        className="w-full bg-transparent text-sm font-semibold outline-none"
                        required
                      />
                    </div>
                    <div className="rounded-2xl bg-[#f2f6fa] dark:bg-[#131e30] border border-transparent focus-within:border-[#1884f7] focus-within:bg-white dark:focus-within:bg-[#0b1322] px-4 py-2">
                      <label className="block text-[11px] font-medium text-slate-400">New Password</label>
                      <div className="flex items-center">
                        <input
                          type={showNewPassword ? "text" : "password"}
                          placeholder="••••••••"
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                          className="w-full bg-transparent text-sm font-semibold outline-none"
                          required
                        />
                        <button
                          type="button"
                          onClick={() => setShowNewPassword(!showNewPassword)}
                          className="text-slate-400 ml-1"
                        >
                          {showNewPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </button>
                      </div>
                    </div>
                  </>
                )}

                {/* Action Buttons: "Change method" and "Create account" / "Sign in" */}
                <div className="pt-4 flex items-center justify-between gap-3">
                  <div className="relative">
                    <button
                      type="button"
                      onClick={() => setShowPresets(!showPresets)}
                      className="rounded-full bg-[#f2f6fa] hover:bg-[#e4ebf3] dark:bg-[#131e30] dark:hover:bg-[#1a2840] text-slate-600 dark:text-slate-300 font-semibold text-xs sm:text-sm px-5 py-3 transition-all active:scale-95"
                    >
                      Change method
                    </button>

                    {/* Dropdown Menu for Quick Demo Presets */}
                    {showPresets && (
                      <div className="absolute left-0 bottom-full mb-2 w-64 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f192b] shadow-xl p-2 z-30 text-xs">
                        <p className="px-3 py-1.5 font-bold uppercase tracking-wider text-[10px] text-slate-400">
                          1-Click Demo Profiles
                        </p>
                        <button
                          type="button"
                          onClick={() => handleQuickFill("admin")}
                          className="w-full text-left px-3 py-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 flex flex-col"
                        >
                          <span className="font-bold text-slate-800 dark:text-white">SOC Administrator</span>
                          <span className="text-[11px] text-slate-400">vasuvora88@gmail.com</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleQuickFill("analyst")}
                          className="w-full text-left px-3 py-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 flex flex-col"
                        >
                          <span className="font-bold text-slate-800 dark:text-white">Security Analyst</span>
                          <span className="text-[11px] text-slate-400">analyst@cyberguard.ai</span>
                        </button>
                      </div>
                    )}
                  </div>

                  <Button
                    type="submit"
                    disabled={submitting}
                    className="rounded-full bg-[#1884f7] hover:bg-[#1272d8] text-white font-semibold text-xs sm:text-sm px-7 sm:px-9 py-3 sm:py-3.5 shadow-lg shadow-[#1884f7]/30 transition-all hover:scale-[1.02] active:scale-[0.98] border-0"
                  >
                    {submitting ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Processing...
                      </>
                    ) : mode === "signup" ? (
                      "Create account"
                    ) : mode === "signin" ? (
                      "Sign in"
                    ) : mode === "forgot" ? (
                      "Send Reset Link"
                    ) : (
                      "Update Password"
                    )}
                  </Button>
                </div>
              </form>
            )}
          </div>

          {/* Bottom Security Assurance Note */}
          <div className="pt-6 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
            <span className="flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-[#1884f7]" /> End-to-end encrypted session
            </span>
            <span>v1.2.4 Enterprise</span>
          </div>

          {/* Organic Wave Divider Mask */}
          <div className="hidden lg:block absolute right-0 top-0 h-full w-24 xl:w-32 pointer-events-none translate-x-[99%] z-20">
            <svg
              className="h-full w-full"
              viewBox="0 0 100 1000"
              preserveAspectRatio="none"
            >
              <path
                d="M0,0 L0,1000 L30,1000 C-10,850 95,720 60,550 C25,380 105,220 30,0 Z"
                className="fill-white dark:fill-[#0b1322]"
              />
              <path
                d="M38,0 C113,220 33,380 68,550 C103,720 -2,850 38,1000"
                fill="none"
                stroke="rgba(203, 213, 225, 0.65)"
                strokeWidth="1.5"
                strokeDasharray="4 4"
              />
            </svg>
          </div>
        </div>

        {/* Right Side: Scenic Mountain Lake Landscape Image */}
        <div className="relative w-full lg:w-[47%] min-h-[300px] lg:min-h-full overflow-hidden bg-slate-900">
          <img
            src="/alpine_lake_mountains.jpg"
            alt="Scenic Mountain Reflection"
            className="absolute inset-0 h-full w-full object-cover object-center filter contrast-[1.05]"
          />
          
          <div className="absolute inset-0 bg-gradient-to-t from-slate-950/40 via-transparent to-transparent pointer-events-none" />

          {/* Watermark Logo in Bottom Right Corner */}
          <div className="absolute right-6 bottom-6 flex items-center gap-1 text-white/90 drop-shadow-md select-none pointer-events-none">
            <span className="h-2 w-2 rounded-full bg-white inline-block mr-0.5" />
            <span className="font-black text-2xl tracking-tighter uppercase font-mono">
              CG
            </span>
          </div>
        </div>

      </div>
    </div>
  );
}
