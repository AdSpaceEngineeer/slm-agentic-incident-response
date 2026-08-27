import { Agent, getAgentByName } from "agents";

type IncidentCard = {
  id: string;
  incidentType:
    | "Human Contact"
    | "Near Miss"
    | "Property Collision"
    | "Conduct / Privacy";
  occurredAt: string;
  humanoidId: string;
  summary: string;
  reportedHarm: string;
  immediateAction: string;
  redactedFields: string[];
};

type TriageCard = {
  severity: "Low" | "Medium" | "High" | "Critical";
  route: "Safety" | "Technical" | "Conduct / Privacy";
  containment: string;
};

type LogState = {
  latest?: IncidentCard;
};

type IncidentLogRpc = {
  createLog(transcript: string): Promise<IncidentCard>;
};

type TriageRpc = {
  triage(card: IncidentCard): Promise<TriageCard>;
};

type RcaRpc = {
  generateRca(
    card: IncidentCard,
    triage: TriageCard,
    expertReply: string
  ): Promise<string>;
};

type HistoryRow = {
  incident_card: string;
  triage: string;
  rca: string;
};

async function getRpcAgent<T>(
  namespace: DurableObjectNamespace,
  name: string
): Promise<T> {
  return (await getAgentByName(
    namespace as unknown as DurableObjectNamespace<Agent<Env>>,
    name
  )) as unknown as T;
}

function parseModelJson<T>(value: unknown): T {
  if (value && typeof value === "object") {
    return value as T;
  }

  const text = String(value)
    .replace(/^```json\s*/i, "")
    .replace(/```$/i, "")
    .trim();

  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");

  if (start < 0 || end < 0) {
    throw new Error("Model did not return valid JSON.");
  }

  return JSON.parse(text.slice(start, end + 1)) as T;
}

function getModelText(result: unknown): string {
  if (typeof result === "string" && result.trim()) {
    return result.trim();
  }

  if (!result || typeof result !== "object") {
    throw new Error("RCA model returned no answer.");
  }

  const output = result as {
    response?: unknown;
    output_text?: unknown;
    result?: unknown;
    choices?: Array<{
      message?: {
        content?: unknown;
      };
      text?: unknown;
    }>;
  };

  const candidates = [
    output.response,
    output.choices?.[0]?.message?.content,
    output.choices?.[0]?.text,
    output.output_text,
    output.result
  ];

  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.trim();
    }
  }

  throw new Error(
    `RCA model returned no final answer: ${JSON.stringify(result).slice(0, 500)}`
  );
}

function redactPii(text: string): {
  text: string;
  fields: string[];
} {
  const fields = new Set<string>();
  let cleaned = text;

  cleaned = cleaned.replace(
    /\b(?:Mr|Mrs|Ms|Mdm|Madam|Encik|Puan|Cik|Uncle|Auntie)\.?\s+[\p{L}'-]+(?:\s+[\p{L}'-]+){0,2}/giu,
    () => {
      fields.add("personName");
      return "[PERSON_1]";
    }
  );

  cleaned = cleaned.replace(
    /\b[689]\d{3}\s?\d{4}\b/g,
    () => {
      fields.add("phone");
      return "[PHONE_1]";
    }
  );

  cleaned = cleaned.replace(
    /\bR-\d+\b/gi,
    () => {
      fields.add("residentId");
      return "[RESIDENT_ID_1]";
    }
  );

  return {
    text: cleaned,
    fields: [...fields]
  };
}

function applyTriageGuardrails(
  card: IncidentCard,
  triage: TriageCard
): TriageCard {
  const result = { ...triage };

  const harmReported =
    card.reportedHarm.trim() !== "" &&
    !/^(none|no injury|no harm|unknown)$/i.test(
      card.reportedHarm.trim()
    );

  if (card.incidentType === "Human Contact") {
    result.route = "Safety";

    if (
      harmReported &&
      (result.severity === "Low" ||
        result.severity === "Medium")
    ) {
      result.severity = "High";
    }

    if (
      !/\b(pause|stop|isolate|remove)\b/i.test(
        result.containment
      )
    ) {
      result.containment =
        `Pause and isolate ${card.humanoidId}; check the affected person and notify the safety supervisor.`;
    }
  }

  if (card.incidentType === "Near Miss") {
    result.route = "Safety";

    if (result.severity === "Low") {
      result.severity = "Medium";
    }

    if (
      !/\b(pause|stop|isolate|inspect)\b/i.test(
        result.containment
      )
    ) {
      result.containment =
        `Pause ${card.humanoidId}, preserve logs and inspect detection and navigation controls.`;
    }
  }

  if (card.incidentType === "Property Collision") {
    result.route = "Technical";

    if (
      !/\b(pause|stop|isolate)\b/i.test(
        result.containment
      )
    ) {
      result.containment =
        `Isolate ${card.humanoidId} and the damaged area; notify facilities management.`;
    }
  }

  if (card.incidentType === "Conduct / Privacy") {
    result.route = "Conduct / Privacy";

    if (
      !/\b(mute|stop|isolate|disable)\b/i.test(
        result.containment
      )
    ) {
      result.containment =
        `Mute ${card.humanoidId}, preserve conversation logs and notify the privacy lead.`;
    }
  }

  return result;
}

export class IncidentLogAgent extends Agent<Env, LogState> {
  initialState: LogState = {};

  async createLog(transcript: string): Promise<IncidentCard> {
    if (!transcript.trim()) {
      throw new Error("Transcript is required.");
    }

    const redacted = redactPii(transcript);

    const result = await this.env.AI.run(
      "@cf/meta/llama-3.1-8b-instruct-fast",
      {
        messages: [
          {
            role: "system",
            content: `You log human-humanoid incidents.

Interpret informal Singlish and mixed English, Malay and Chinese.
Write concise English.
The input has already had identifiers replaced with privacy tokens.
Keep every privacy token unchanged.
Do not reconstruct or guess identities.
Exclude phone numbers and resident IDs from the summary.
Never attribute human contact details to the humanoid.
Use [PERSON_1] only when a human reference is necessary.
Preserve operational facts.
Never invent missing details; use "Unknown".`
          },
          {
            role: "user",
            content: redacted.text
          }
        ],
        temperature: 0.1,
        max_tokens: 450,
        response_format: {
          type: "json_schema",
          json_schema: {
            type: "object",
            properties: {
              incidentType: {
                type: "string",
                enum: [
                  "Human Contact",
                  "Near Miss",
                  "Property Collision",
                  "Conduct / Privacy"
                ]
              },
              occurredAt: { type: "string" },
              humanoidId: { type: "string" },
              summary: { type: "string" },
              reportedHarm: { type: "string" },
              immediateAction: { type: "string" },
              redactedFields: {
                type: "array",
                items: { type: "string" }
              }
            },
            required: [
              "incidentType",
              "occurredAt",
              "humanoidId",
              "summary",
              "reportedHarm",
              "immediateAction",
              "redactedFields"
            ]
          }
        }
      }
    );

    const fields =
      parseModelJson<Omit<IncidentCard, "id">>(
        result.response
      );

    fields.summary = redactPii(fields.summary).text;
    fields.reportedHarm =
      redactPii(fields.reportedHarm).text;
    fields.immediateAction =
      redactPii(fields.immediateAction).text;
    fields.redactedFields = redacted.fields;

    const card: IncidentCard = {
      id: `INC-${Date.now()}`,
      ...fields
    };

    this.setState({ latest: card });
    return card;
  }
}

export class TriageAgent extends Agent<Env> {
  async triage(card: IncidentCard): Promise<TriageCard> {
    const result = await this.env.AI.run(
      "@cf/meta/llama-3.2-3b-instruct",
      {
        messages: [
          {
            role: "system",
            content: `You triage human-humanoid incidents.

Return only valid JSON:
{
  "severity": "Low | Medium | High | Critical",
  "route": "Safety | Technical | Conduct / Privacy",
  "containment": "one immediate action under 25 words"
}

Severity rules:
Critical = life-threatening harm or uncontrolled immediate danger.
High = reported human injury, physical contact with harm, or major safety-control failure.
Medium = contained near miss or property damage without injury.
Low = minor event with no harm and no continuing risk.

The human is the person who may need care.
Never provide first aid, reassurance or medical care to the humanoid.
Containment must stop, pause, mute or isolate the affected humanoid.
Do not perform root-cause analysis.`
          },
          {
            role: "user",
            content: JSON.stringify(card)
          }
        ],
        temperature: 0.1,
        max_tokens: 180
      }
    );

    const triage =
      parseModelJson<TriageCard>(result.response);

    return applyTriageGuardrails(card, triage);
  }
}

export class RcaAgent extends Agent<Env> {
  private seedHistory(): void {
    this.sql`
      CREATE TABLE IF NOT EXISTS incident_history (
        id TEXT PRIMARY KEY,
        incident_card TEXT NOT NULL,
        triage TEXT NOT NULL,
        rca TEXT NOT NULL
      )
    `;

    const countRows = [
      ...this.sql<{ count: number }>`
        SELECT COUNT(*) AS count
        FROM incident_history
      `
    ];

    if ((countRows[0]?.count ?? 0) >= 20) {
      return;
    }

    const types = [
      "Human Contact",
      "Near Miss",
      "Property Collision",
      "Conduct / Privacy"
    ] as const;

    const causes = [
      "proximity sensor confidence fell below the operational threshold",
      "stop intent was not recognised during mixed-language speech",
      "route planning did not account for a temporary obstruction",
      "access controls allowed unnecessary personal information disclosure"
    ] as const;

    for (let index = 0; index < 20; index++) {
      const type = types[index % types.length]!;
      const cause = causes[index % causes.length]!;
      const id =
        `HIST-${String(index + 1).padStart(3, "0")}`;

      const incidentCard = JSON.stringify({
        id,
        incidentType: type,
        humanoidId:
          `HMD-${String((index % 9) + 1).padStart(2, "0")}`,
        summary:
          `Synthetic historical ${type.toLowerCase()} incident`
      });

      const triage = JSON.stringify({
        severity: index % 5 === 0 ? "High" : "Medium",
        route:
          type === "Conduct / Privacy"
            ? "Conduct / Privacy"
            : type === "Property Collision"
              ? "Technical"
              : "Safety"
      });

      const rca = JSON.stringify({
        likelyCause: cause,
        action:
          "Review controls, test the affected mode and verify remediation."
      });

      this.sql`
        INSERT OR IGNORE INTO incident_history
          (id, incident_card, triage, rca)
        VALUES
          (${id}, ${incidentCard}, ${triage}, ${rca})
      `;
    }
  }

  async generateRca(
    card: IncidentCard,
    triage: TriageCard,
    expertReply: string
  ): Promise<string> {
    this.seedHistory();

    const history = [
      ...this.sql<HistoryRow>`
        SELECT incident_card, triage, rca
        FROM incident_history
        ORDER BY id
        LIMIT 20
      `
    ];

    const guidelines = {
      transportAuthority:
        "Humanoid systems must yield to people, stop when detection is uncertain, and report physical-contact events.",
      estateFacilities:
        "Isolate affected equipment or areas, preserve logs and scene evidence, and notify the duty facilities manager.",
      cybersecurityAuthority:
        "Contain suspected unauthorized access, preserve audit logs, apply least privilege, and rotate exposed credentials."
    };

    const result = await this.env.AI.run(
      "@cf/qwen/qwen3-30b-a3b-fp8",
      {
        messages: [
          {
            role: "system",
            content: `You are the RCA lead for human-humanoid incidents.

Produce only the final RCA, without reasoning notes.
Write exactly 150 words.
Include likely cause, supporting evidence, robotics expert comment, recurrence pattern and recommended action.
Reference only relevant supplied guidelines.
Clearly separate confirmed evidence from hypotheses.
Do not invent evidence.`
          },
          {
            role: "user",
            content:
              `/no_think\n${JSON.stringify({
                currentIncident: card,
                triage,
                guidelines,
                roboticsExpertSlackReply:
                  expertReply ||
                  "No expert reply received.",
                previousIncidents: history
              })}`
          }
        ],
        temperature: 0.2,
        max_tokens: 1200
      }
    );

    return getModelText(result);
  }
}

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: corsHeaders
  });
}

export default {
  async fetch(
    request: Request,
    env: Env
  ): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders
      });
    }

    if (request.method !== "POST") {
      return json({ error: "Use POST" }, 405);
    }

    try {
      const path = new URL(request.url).pathname;
      const body =
        await request.json<Record<string, unknown>>();
      const sessionId =
        String(body.sessionId || "demo");

      if (path === "/api/log") {
        const agent =
          await getRpcAgent<IncidentLogRpc>(
            env.INCIDENT_LOG_AGENT,
            sessionId
          );

        return json(
          await agent.createLog(
            String(body.transcript || "")
          )
        );
      }

      if (path === "/api/triage") {
        const agent =
          await getRpcAgent<TriageRpc>(
            env.TRIAGE_AGENT,
            sessionId
          );

        return json(
          await agent.triage(
            body.card as IncidentCard
          )
        );
      }

      if (path === "/api/rca") {
        const agent =
          await getRpcAgent<RcaRpc>(
            env.RCA_AGENT,
            sessionId
          );

        return json({
          rca: await agent.generateRca(
            body.card as IncidentCard,
            body.triage as TriageCard,
            String(body.expertReply || "")
          )
        });
      }

      return json({ error: "Not found" }, 404);
    } catch (error) {
      return json(
        {
          error:
            error instanceof Error
              ? error.message
              : String(error)
        },
        500
      );
    }
  }
} satisfies ExportedHandler<Env>;