// Scheduled Workers AI threat-campaign summarizer.
// Invoked only on confirmed high-severity multi-stage attacks or novel
// exploit payloads — never on low-severity events.

export interface Env {
  KV: KVNamespace;
  AI: any; // Workers AI binding
}

interface CampaignSummaryRequest {
  events: Array<{
    ip: string;
    score: number;
    module: string;
    iocs: string[];
    timestamp: string;
  }>;
}

export default {
  async scheduled(
    event: ScheduledEvent,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    // Only run if there are high-severity events to summarize
    const highSeverityKey = "ai:high_severity_pending";
    const pending = await env.KV.get(highSeverityKey, "json");

    if (!pending) {
      return; // No high-severity events to summarize
    }

    const payload = pending as unknown as CampaignSummaryRequest;

    // Guard: only invoke Workers AI on confirmed high-severity multi-stage
    // attacks or novel exploit payloads
    const highSeverityEvents = payload.events.filter((e) => e.score >= 75);
    if (highSeverityEvents.length === 0) {
      await env.KV.delete(highSeverityKey);
      return;
    }

    try {
      const summary = await summarizeCampaign(env, highSeverityEvents);
      ctx.waitUntil(
        env.KV.put("ai:last_summary", summary, { expirationTtl: 86400 }),
      );
      await env.KV.delete(highSeverityKey);
    } catch (err) {
      console.error("Workers AI summarization failed:", err);
    }
  },
};

async function summarizeCampaign(
  env: Env,
  events: Array<{ ip: string; score: number; module: string; iocs: string[]; timestamp: string }>,
): Promise<string> {
  const prompt = `
Summarize the following threat campaign for a SOC analyst.
Events:
${events.map((e) => `- ${e.timestamp} IP=${e.ip} score=${e.score} module=${e.module} IOCs=${e.iocs.join(",")}`).join("\n")}

Provide: (1) campaign overview, (2) targeted infrastructure, (3) recommended actions.
  `;

  const response = await env.AI.run(
    "@cf/meta/llama-3.1-8b-instruct",
    { prompt },
  );

  return response.response || "";
}
