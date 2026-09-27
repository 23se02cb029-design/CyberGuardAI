import { useEffect, useMemo, useRef, useState } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { Send, Terminal, Loader2, Sparkles, User, Plus, Settings as SettingsIcon, AlertCircle } from "lucide-react";
import { Streamdown } from "streamdown";
import { nanoid } from "nanoid";
import { Link } from "wouter";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
  source?: "gemini" | "heuristics";
}

const GREETING =
  "Hello! I'm your SOC Copilot. I can help you analyze security logs, understand threats, and recommend incident response actions. What would you like to know?";

const QUICK_PROMPTS = [
  "What is a brute force attack?",
  "How do I respond to a SQL injection alert?",
  "Explain MITRE ATT&CK T1110",
  "What does a path traversal attempt look like in logs?",
];

const SESSION_STORAGE_KEY = "cyberguard-ai-copilot-session";

function formatTime(date: Date): string {
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export default function SocCopilot() {
  const { user } = useAuth();
  const organizationId = user?.organizationId ?? 1;
  const utils = trpc.useUtils();
  const [sessionId, setSessionId] = useState(() => {
    const stored = localStorage.getItem(SESSION_STORAGE_KEY);
    if (stored) return stored;
    const fresh = nanoid();
    localStorage.setItem(SESSION_STORAGE_KEY, fresh);
    return fresh;
  });
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const loadedSessionRef = useRef<string | null>(null);

  const historyQuery = trpc.chat.history.useQuery({ sessionId, organizationId });
  const settingsQuery = trpc.settings.get.useQuery();

  useEffect(() => {
    if (!historyQuery.data || loadedSessionRef.current === sessionId) return;
    loadedSessionRef.current = sessionId;

    const restored: Message[] = historyQuery.data.flatMap((row) => {
      const createdAt = new Date(row.createdAt);
      const source = (row.context as { source?: "gemini" | "heuristics" } | null)?.source;
      return [
        { id: `${row.id}-user`, role: "user" as const, content: row.userMessage ?? "", timestamp: createdAt },
        { id: `${row.id}-assistant`, role: "assistant" as const, content: row.aiResponse ?? "", timestamp: createdAt, source },
      ];
    });
    setMessages(restored);
  }, [historyQuery.data, sessionId]);

  const chatMutation = trpc.chat.message.useMutation({
    onSuccess: (data) => {
      setMessages((prev) => [
        ...prev,
        {
          id: nanoid(),
          role: "assistant",
          content: data.response,
          timestamp: new Date(),
          source: data.source,
        },
      ]);
      setIsLoading(false);
      utils.chat.history.invalidate({ sessionId, organizationId });
    },
    onError: (error) => {
      setMessages((prev) => [
        ...prev,
        {
          id: nanoid(),
          role: "assistant",
          content: `[ERROR] ${error.message}`,
          timestamp: new Date(),
          source: "heuristics",
        },
      ]);
      setIsLoading(false);
    },
  });

  const lastSource = useMemo(() => [...messages].reverse().find((m) => m.source)?.source, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const sendMessage = (text: string) => {
    const trimmed = text.trim();
    if (!trimmed) return;

    const userMessage: Message = {
      id: nanoid(),
      role: "user",
      content: trimmed,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsLoading(true);

    chatMutation.mutate({
      sessionId,
      message: trimmed,
      organizationId,
    });
  };

  const handleNewChat = () => {
    const fresh = nanoid();
    localStorage.setItem(SESSION_STORAGE_KEY, fresh);
    loadedSessionRef.current = fresh;
    setSessionId(fresh);
    setMessages([]);
    setInput("");
  };

  return (
    <DashboardLayout>
      <div className="-m-4">
        <div className="blueprint-grid flex h-[calc(100vh-2rem)] flex-col bg-background p-5 text-foreground sm:p-7">
          {/* Header */}
          <div className="mb-6 flex flex-wrap items-center justify-between gap-4 border-b border-cyan-400/10 pb-6">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400">
                <Terminal className="h-5 w-5" />
                <span className="tech-label text-cyan-300">CyberGuard AI // SOC Copilot</span>
              </div>
              <h1 className="text-3xl font-black tracking-tighter text-zinc-900 sm:text-4xl dark:text-white">
                Security Assistant
              </h1>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {settingsQuery.data?.gemini.configured ? (
                <Badge className="gap-1.5 border-emerald-500/40 bg-emerald-500/10 text-emerald-400 font-mono text-xs">
                  <Sparkles className="h-3 w-3 text-emerald-400 animate-pulse" />
                  {settingsQuery.data.gemini.model.toUpperCase()} ACTIVE
                </Badge>
              ) : (
                <Badge className="gap-1.5 border-amber-500/40 bg-amber-500/10 text-amber-400 font-mono text-xs">
                  <AlertCircle className="h-3 w-3 text-amber-400" />
                  HEURISTICS ENGINE ACTIVE
                </Badge>
              )}

              <Link href="/settings">
                <Button
                  variant="outline"
                  size="sm"
                  className="border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 text-xs gap-1.5"
                >
                  <SettingsIcon className="h-3.5 w-3.5" />
                  Settings
                </Button>
              </Link>

              <Button
                variant="outline"
                size="sm"
                onClick={handleNewChat}
                disabled={isLoading}
                className="gap-1.5 text-xs"
              >
                <Plus className="h-3.5 w-3.5" />
                New Chat
              </Button>
            </div>
          </div>

          {/* Chat Terminal */}
          <div className="soc-surface flex flex-1 flex-col overflow-hidden rounded-xl">
            <div className="flex items-center justify-between border-b border-zinc-200 bg-zinc-50 px-4 py-2.5 dark:border-cyan-500/20 dark:bg-zinc-900/80">
              <div className="flex items-center gap-3">
                <div className="flex gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-500/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
                </div>
                <span className="font-mono text-xs text-zinc-500">soc_copilot.sh</span>
              </div>
              {isLoading && (
                <Badge className="gap-1.5 border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
                  THINKING
                </Badge>
              )}
            </div>

            <div className="flex-1 space-y-4 overflow-y-auto p-5 font-mono text-sm">
              {/* Static greeting — always shown, never persisted */}
              <div className="flex justify-start gap-3">
                <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-cyan-500/40 bg-cyan-500/10">
                  <Terminal className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
                </div>
                <div className="max-w-md rounded-lg border border-cyan-500/30 bg-cyan-500/[0.04] px-4 py-3 text-zinc-700 shadow-[0_0_14px_rgba(34,211,238,0.06)] lg:max-w-2xl dark:bg-black/40 dark:text-emerald-300 dark:shadow-[0_0_14px_rgba(34,211,238,0.12)]">
                  <p>{GREETING}</p>
                </div>
              </div>

              {messages.map((message) => (
                <div
                  key={message.id}
                  className={`flex gap-3 ${message.role === "user" ? "justify-end" : "justify-start"}`}
                >
                  {message.role === "assistant" && (
                    <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-cyan-500/40 bg-cyan-500/10">
                      <Terminal className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
                    </div>
                  )}

                  <div
                    className={`max-w-md rounded-lg border px-4 py-3 lg:max-w-2xl ${
                      message.role === "user"
                        ? "border-amber-500/40 bg-amber-500/5 text-zinc-800 dark:bg-amber-500/10 dark:text-amber-100"
                        : "border-cyan-500/30 bg-cyan-500/[0.04] text-zinc-700 shadow-[0_0_14px_rgba(34,211,238,0.06)] dark:bg-black/40 dark:text-emerald-300 dark:shadow-[0_0_14px_rgba(34,211,238,0.12)]"
                    }`}
                  >
                    {message.role === "assistant" ? (
                      <>
                        {message.source === "heuristics" && (
                          <p className="mb-1.5 text-[10px] tracking-widest text-amber-600 dark:text-amber-500/80">
                            [LOCAL_HEURISTICS_ENGINE — NO LIVE GEMINI CONNECTION]
                          </p>
                        )}
                        <div className="prose prose-sm dark:prose-invert max-w-none">
                          <Streamdown>{message.content}</Streamdown>
                        </div>
                      </>
                    ) : (
                      <p className="whitespace-pre-wrap">{message.content}</p>
                    )}
                    <p className="mt-1.5 text-[10px] text-zinc-400 dark:text-zinc-600">
                      {formatTime(message.timestamp)}
                    </p>
                  </div>

                  {message.role === "user" && (
                    <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-amber-500/40 bg-amber-500/10">
                      <User className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
                    </div>
                  )}
                </div>
              ))}
              {isLoading && (
                <div className="flex justify-start gap-3">
                  <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-cyan-500/40 bg-cyan-500/10">
                    <Terminal className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
                  </div>
                  <div className="flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/[0.04] px-4 py-3 text-zinc-500 dark:bg-black/40 dark:text-zinc-500">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Analyzing query...</span>
                  </div>
                </div>
              )}

              {messages.length === 0 && !isLoading && (
                <div className="flex flex-wrap gap-2 pl-10">
                  {QUICK_PROMPTS.map((prompt) => (
                    <button
                      key={prompt}
                      onClick={() => sendMessage(prompt)}
                      className="rounded-full border border-cyan-500/30 bg-cyan-500/[0.04] px-3 py-1.5 text-xs text-zinc-600 transition-colors hover:border-cyan-500/60 hover:bg-cyan-500/10 dark:text-zinc-400 dark:hover:text-cyan-300"
                    >
                      {prompt}
                    </button>
                  ))}
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Command Line Input */}
            <div className="border-t border-zinc-200 bg-zinc-50 p-3 dark:border-cyan-500/20 dark:bg-zinc-900/80">
              <div className="flex items-center gap-2 rounded-lg border border-zinc-300 bg-white px-3 py-2 focus-within:border-cyan-600/60 focus-within:ring-2 focus-within:ring-cyan-600/20 dark:border-zinc-700 dark:bg-black/60 dark:focus-within:border-cyan-500/60 dark:focus-within:ring-cyan-500/20">
                <span className="shrink-0 font-mono text-sm text-cyan-600 dark:text-cyan-500">$</span>
                <input
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      sendMessage(input);
                    }
                  }}
                  disabled={isLoading}
                  placeholder="ask --about threats, logs, or incident response..."
                  className="flex-1 bg-transparent font-mono text-sm text-zinc-800 placeholder:text-zinc-400 outline-none disabled:opacity-50 dark:text-emerald-300 dark:placeholder:text-zinc-600"
                />
                <Button
                  onClick={() => sendMessage(input)}
                  disabled={isLoading || !input.trim()}
                  size="icon"
                  variant="outline"
                  className="h-8 w-8 shrink-0 !border-2 !border-cyan-600/50 !bg-cyan-50 !text-cyan-700 shadow-none transition-all duration-300 hover:!bg-cyan-100 dark:!border-cyan-400/70 dark:!bg-cyan-500/25 dark:!text-cyan-100 dark:shadow-[0_0_14px_rgba(34,211,238,0.35)] dark:hover:!border-cyan-300 dark:hover:!bg-cyan-500/40 dark:hover:shadow-[0_0_28px_rgba(34,211,238,0.6)] disabled:opacity-40 disabled:shadow-none"
                >
                  {isLoading ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Send className="h-4 w-4" />
                  )}
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
