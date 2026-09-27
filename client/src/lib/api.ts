export async function analyzeLogs(logData: string) {
  const res = await fetch("/api/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ logData }),
  });

  if (!res.ok) {
    throw new Error("Analysis failed");
  }

  return res.json();
}
