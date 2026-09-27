import { GoogleGenerativeAI } from "@google/generative-ai";

export const DEFAULT_MODEL = "gemini-1.5-flash";
export const SUPPORTED_MODELS = [
  "gemini-1.5-flash",
  "gemini-2.0-flash",
  "gemini-1.5-pro",
] as const;

export function getActiveModelName(): string {
  return process.env.GEMINI_MODEL?.trim() || DEFAULT_MODEL;
}

function getClient(overrideKey?: string): GoogleGenerativeAI {
  const apiKey = overrideKey || process.env.GEMINI_API_KEY;
  if (!apiKey?.trim()) {
    throw new Error("GEMINI_API_KEY is not configured");
  }
  return new GoogleGenerativeAI(apiKey.trim());
}

/**
 * Probe / Test Gemini connection with latency measurement
 */
export async function testGeminiConnection(
  apiKey?: string,
  modelName: string = getActiveModelName()
): Promise<{
  connected: boolean;
  latencyMs: number;
  model: string;
  response: string;
  error?: string;
}> {
  const start = Date.now();
  const keyToTest = apiKey?.trim() || process.env.GEMINI_API_KEY?.trim();

  if (!keyToTest) {
    return {
      connected: false,
      latencyMs: 0,
      model: modelName,
      response: "",
      error: "No Gemini API key provided. Get a free key at https://aistudio.google.com/app/apikey",
    };
  }

  try {
    const client = new GoogleGenerativeAI(keyToTest);
    const model = client.getGenerativeModel({ model: modelName });
    const result = await model.generateContent("Ping check: respond with 'CyberGuard SOC AI Online'.");
    const text = result.response.text();
    const latencyMs = Date.now() - start;

    return {
      connected: true,
      latencyMs,
      model: modelName,
      response: text.trim(),
    };
  } catch (error: any) {
    const latencyMs = Date.now() - start;
    let message = error?.message || String(error);

    // Provide friendly guidance for common API key issues
    if (message.includes("API_KEY_INVALID") || message.includes("API key not valid")) {
      message = "Invalid Gemini API Key. Please get a free API key starting with 'AIzaSy' from Google AI Studio (aistudio.google.com/app/apikey).";
    }

    return {
      connected: false,
      latencyMs,
      model: modelName,
      response: "",
      error: message,
    };
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs = 2500): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`Gemini request timed out after ${timeoutMs}ms`)), timeoutMs)
    ),
  ]);
}

/**
 * Runs a system+user prompt through Gemini and parses the response as JSON.
 * Falls back across alternate models if primary model encounters a transient error.
 */
export async function generateJson(
  systemPrompt: string,
  userPrompt: string
): Promise<any> {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (process.env.NODE_ENV === "test" && (!apiKey || !apiKey.startsWith("AIzaSy"))) {
    throw new Error("Gemini skipped in test environment; heuristic fallback active");
  }

  const client = getClient();
  const primaryModel = getActiveModelName();
  const fallbackModels = [primaryModel, "gemini-2.0-flash", "gemini-1.5-flash"].filter(
    (m, idx, arr) => arr.indexOf(m) === idx
  );

  let lastError: unknown = null;

  for (const modelName of fallbackModels) {
    try {
      const model = client.getGenerativeModel({
        model: modelName,
        systemInstruction: systemPrompt,
        generationConfig: { responseMimeType: "application/json" },
      });

      const result = await withTimeout(model.generateContent(userPrompt), 3000);
      return JSON.parse(result.response.text());
    } catch (err: any) {
      lastError = err;
      console.warn(`[Gemini JSON] Model ${modelName} failed, trying fallback: ${err.message}`);
    }
  }

  throw lastError;
}

/** Runs a system+user prompt through Gemini and returns the raw text response. */
export async function generateText(
  systemPrompt: string,
  userPrompt: string
): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (process.env.NODE_ENV === "test" && (!apiKey || !apiKey.startsWith("AIzaSy"))) {
    throw new Error("Gemini skipped in test environment; heuristic fallback active");
  }

  const client = getClient();
  const primaryModel = getActiveModelName();
  const fallbackModels = [primaryModel, "gemini-2.0-flash", "gemini-1.5-flash"].filter(
    (m, idx, arr) => arr.indexOf(m) === idx
  );

  let lastError: unknown = null;

  for (const modelName of fallbackModels) {
    try {
      const model = client.getGenerativeModel({
        model: modelName,
        systemInstruction: systemPrompt,
      });

      const result = await withTimeout(model.generateContent(userPrompt), 3000);
      return result.response.text();
    } catch (err: any) {
      lastError = err;
      console.warn(`[Gemini Text] Model ${modelName} failed, trying fallback: ${err.message}`);
    }
  }

  throw lastError;
}
