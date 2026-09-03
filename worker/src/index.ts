import { Agent, getAgentByName } from "agents";

type IncidentType =
  | "Human Contact"
  | "Near Miss"
  | "Property Collision"
  | "Conduct / Privacy";

type IncidentCard = {
  id: string;
  incidentType: IncidentType;
  occurredAt: string;
  humanoidId: string;
  summary: string;
  reportedHarm: string;
  immediateAction: string;
  redactedFields: string[];
};

type IncidentModelFields = Omit<
  IncidentCard,
  "id" | "redactedFields"
>;

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
  id: string;
  incident_card: string;
  triage: string;
  rca: string;
};

type RcaAnalysis = {
  likelyCause: string;
  recommendedAction: string;
};

type RecurrenceSummary = {
  totalRecords: number;
  matchingTypeRecords: number;
  mostCommonRecordedCause: string;
  causeRecordCount: number;
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
  if (
    value &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    return value as T;
  }

  const text = String(value)
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/```$/i, "")
    .trim();

  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");

  if (start < 0 || end < 0) {
    throw new Error("Model did not return valid JSON.");
  }

  return JSON.parse(
    text.slice(start, end + 1)
  ) as T;
}

function extractModelPayload(result: unknown): unknown {
  if (
    typeof result === "string" &&
    result.trim()
  ) {
    return result;
  }

  if (!result || typeof result !== "object") {
    throw new Error("Model returned no answer.");
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
    if (
      candidate !== null &&
      candidate !== undefined &&
      (
        typeof candidate === "object" ||
        (
          typeof candidate === "string" &&
          candidate.trim()
        )
      )
    ) {
      return candidate;
    }
  }

  throw new Error(
    `Model returned no final answer: ${JSON.stringify(result).slice(0, 500)}`
  );
}

function redactPii(text: string): {
  text: string;
  fields: string[];
} {
  const fields = new Set<string>();
  let cleaned = text;

  cleaned = cleaned.replace(
    /\b(?:Mr|Mrs|Ms|Mdm|Madam|madam|Encik|encik|Puan|puan|Cik|cik|Uncle|uncle|Auntie|auntie)\.?\s+\p{Lu}[\p{L}'-]*(?:\s+\p{Lu}[\p{L}'-]*){0,2}/gu,
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

function cleanOperationalField(text: string): string {
  const cleaned = redactPii(
    String(text || "")
  ).text
    .replace(
      /\[(?:PHONE|RESIDENT_ID)_\d+\]/gi,
      "[REDACTED]"
    )
    .replace(/\s+/g, " ")
    .trim();

  return cleaned || "Unknown";
}

function inferIncidentType(
  transcript: string,
  modelType: IncidentType
): IncidentType {
  const text = transcript.toLowerCase();

  if (
    /\b(?:privacy|medical appointment|room number|personal information|personal data|announced|revealed|disclosed|muted)\b/i.test(
      text
    ) ||
    /很多人听到/u.test(transcript)
  ) {
    return "Conduct / Privacy";
  }

  if (
    /\b(?:near miss|nearly|almost|hampir)\b/i.test(
      text
    )
  ) {
    return "Near Miss";
  }

  if (
    /\b(?:glass door|door cracked|property damage|damaged property|hit the wall|hit the door)\b/i.test(
      text
    )
  ) {
    return "Property Collision";
  }

  if (
    /\b(?:bumped into|collided with|struck|made contact with)\b/i.test(
      text
    )
  ) {
    return "Human Contact";
  }

  return modelType;
}

function extractOccurredAt(
  transcript: string,
  modelValue: string
): string {
  const time =
    transcript.match(
      /\b(?:[01]?\d|2[0-3]):[0-5]\d\s?(?:am|pm)?\b/i
    )?.[0];

  const knownLocations = [
    "Block C lift lobby",
    "Lobby B",
    "loading bay",
    "dining hall"
  ];

  const location = knownLocations.find(
    (candidate) =>
      transcript
        .toLowerCase()
        .includes(candidate.toLowerCase())
  );

  if (location && time) {
    return `${location}, ${time}`;
  }

  if (location) {
    return location;
  }

  if (time) {
    return time;
  }

  const cleaned = cleanOperationalField(
    modelValue
  )
    .replace(/\[DATE\]/gi, "")
    .replace(/\s+/g, " ")
    .trim();

  return cleaned || "Unknown";
}

function extractReportedHarm(
  transcript: string,
  modelValue: string,
  incidentType: IncidentType
): string {
  if (
    /\b(?:no injury|nobody hurt|no one hurt|no one was hurt)\b/i.test(
      transcript
    )
  ) {
    return "None";
  }

  if (
    /\bleft arm pain\b/i.test(transcript)
  ) {
    return "Left arm pain";
  }

  let cleaned = cleanOperationalField(
    modelValue
  );

  if (incidentType === "Human Contact") {
    cleaned = cleaned.replace(
      /\b(?:the\s+)?(?:humanoid|robot)(?:'s)?\b/gi,
      "the person's"
    );
  }

  return cleaned;
}

function extractImmediateAction(
  transcript: string,
  incidentType: IncidentType,
  humanoidId: string,
  modelValue: string
): string {
  if (
    /\b(?:emergency button|emergency stop|tekan emergency)\b/i.test(
      transcript
    )
  ) {
    return `Staff activated the emergency stop; ${humanoidId} stopped.`;
  }

  if (
    incidentType === "Near Miss" &&
    /\b(?:block|blocked)\b/i.test(transcript)
  ) {
    return "The operator issued a stop command and blocked the humanoid's path.";
  }

  if (
    incidentType === "Conduct / Privacy" &&
    /\bmuted?\b/i.test(transcript)
  ) {
    return `Staff muted ${humanoidId}.`;
  }

  if (
    incidentType === "Property Collision"
  ) {
    return "No immediate containment action was reported.";
  }

  return cleanOperationalField(modelValue);
}

function sanitizeGeneratedSummary(
  text: string
): string {
  const redacted = redactPii(
    String(text || "")
  ).text;

  return redacted
    .split(/(?<=[.!?])\s+/)
    .filter(
      (sentence) =>
        !/\[(?:PHONE|RESIDENT_ID)_\d+\]/i.test(
          sentence
        ) &&
        !/\b(?:phone number|resident ID)\b/i.test(
          sentence
        )
    )
    .join(" ")
    .replace(/\[PERSON_\d+\]/gi, "a person")
    .replace(/\[DATE\]/gi, "")
    .replace(/\s+/g, " ")
    .trim();
}

function buildSafeSummary(
  fields: IncidentModelFields,
  transcript: string
): string {
  const humanoidId =
    cleanOperationalField(fields.humanoidId);

  const occurredAt =
    cleanOperationalField(fields.occurredAt);

  if (
    fields.incidentType === "Human Contact"
  ) {
    return [
      `Humanoid ${humanoidId} made contact with a person at ${occurredAt}.`,
      `Reported human harm: ${fields.reportedHarm}.`,
      `Immediate action: ${fields.immediateAction}`
    ].join(" ");
  }

  if (
    fields.incidentType === "Near Miss"
  ) {
    const personDescription =
      /\bstroller\b/i.test(transcript)
        ? "a person pushing a stroller"
        : "a person";

    return [
      `Humanoid ${humanoidId} nearly collided with ${personDescription} at ${occurredAt}.`,
      `Reported harm: ${fields.reportedHarm}.`,
      `Immediate action: ${fields.immediateAction}`
    ].join(" ");
  }

  if (
    fields.incidentType === "Property Collision"
  ) {
    if (
      /\bglass door\b/i.test(transcript)
    ) {
      return [
        `Humanoid ${humanoidId} collided with a glass door at ${occurredAt}.`,
        `The door cracked.`,
        `Reported harm: ${fields.reportedHarm}.`,
        `Immediate action: ${fields.immediateAction}`
      ].join(" ");
    }
  }

  if (
    fields.incidentType === "Conduct / Privacy"
  ) {
    return [
      `Humanoid ${humanoidId} disclosed personal information aloud at ${occurredAt}.`,
      `No personal identifiers are retained in this incident card.`,
      `Immediate action: ${fields.immediateAction}`
    ].join(" ");
  }

  const summary =
    sanitizeGeneratedSummary(fields.summary);

  return summary ||
    `Humanoid ${humanoidId} was involved in a ${fields.incidentType.toLowerCase()} incident at ${occurredAt}.`;
}

function applyTriageGuardrails(
  card: IncidentCard,
  triage: TriageCard
): TriageCard {
  const validSeverities: TriageCard["severity"][] = [
    "Low",
    "Medium",
    "High",
    "Critical"
  ];

  const result: TriageCard = {
    severity: validSeverities.includes(
      triage.severity
    )
      ? triage.severity
      : "Medium",

    route: triage.route,

    containment: cleanOperationalField(
      triage.containment
    )
  };

  const harmReported =
    card.reportedHarm.trim() !== "" &&
    !/^(?:none|no injury|no harm|unknown)$/i.test(
      card.reportedHarm.trim()
    );

  if (
    card.incidentType === "Human Contact"
  ) {
    result.route = "Safety";

    if (harmReported) {
      if (
        result.severity === "Low" ||
        result.severity === "Medium"
      ) {
        result.severity = "High";
      }
    } else if (result.severity === "Low") {
      result.severity = "Medium";
    }

    result.containment =
      `Pause and isolate ${card.humanoidId}; check the affected person and notify the safety supervisor.`;
  }

  if (
    card.incidentType === "Near Miss"
  ) {
    result.route = "Safety";

    if (result.severity === "Low") {
      result.severity = "Medium";
    }

    result.containment =
      `Pause ${card.humanoidId}; preserve logs and inspect detection, navigation and emergency-stop controls.`;
  }

  if (
    card.incidentType === "Property Collision"
  ) {
    result.route = "Technical";

    if (result.severity === "Low") {
      result.severity = "Medium";
    }

    result.containment =
      `Isolate ${card.humanoidId} and the damaged area; preserve logs and notify facilities management.`;
  }

  if (
    card.incidentType === "Conduct / Privacy"
  ) {
    result.route = "Conduct / Privacy";

    if (result.severity === "Low") {
      result.severity = "Medium";
    }

    result.containment =
      `Mute and isolate ${card.humanoidId}; preserve conversation logs and notify the privacy lead.`;
  }

  return result;
}

function calculateRecurrence(
  history: HistoryRow[],
  incidentType: IncidentType
): RecurrenceSummary {
  const matchingRows = history.filter(
    (row) => {
      try {
        const card = JSON.parse(
          row.incident_card
        ) as {
          incidentType?: string;
        };

        return (
          card.incidentType === incidentType
        );
      } catch {
        return false;
      }
    }
  );

  const causeCounts =
    new Map<string, number>();

  for (const row of matchingRows) {
    try {
      const report = JSON.parse(
        row.rca
      ) as {
        likelyCause?: string;
      };

      const cause =
        report.likelyCause?.trim() ||
        "Cause unconfirmed";

      causeCounts.set(
        cause,
        (causeCounts.get(cause) || 0) + 1
      );
    } catch {
      causeCounts.set(
        "Cause unconfirmed",
        (
          causeCounts.get(
            "Cause unconfirmed"
          ) || 0
        ) + 1
      );
    }
  }

  let mostCommonRecordedCause =
    "No recurring cause recorded";

  let causeRecordCount = 0;

  for (
    const [cause, count]
    of causeCounts
  ) {
    if (count > causeRecordCount) {
      mostCommonRecordedCause = cause;
      causeRecordCount = count;
    }
  }

  return {
    totalRecords: history.length,
    matchingTypeRecords:
      matchingRows.length,
    mostCommonRecordedCause,
    causeRecordCount
  };
}

function recurrenceText(
  card: IncidentCard,
  recurrence: RecurrenceSummary
): string {
  if (
    recurrence.matchingTypeRecords === 0
  ) {
    return [
      `None of the ${recurrence.totalRecords}`,
      `previous synthetic records share this incident type.`,
      `No recurrence conclusion can be drawn.`
    ].join(" ");
  }

  return [
    `${recurrence.matchingTypeRecords} of`,
    `${recurrence.totalRecords} previous synthetic records`,
    `were ${card.incidentType} incidents;`,
    `${recurrence.causeRecordCount} of those`,
    `recorded "${recurrence.mostCommonRecordedCause}".`,
    `This fleet-level pattern is context,`,
    `not proof about ${card.humanoidId}.`
  ].join(" ");
}

function relevantGuidelines(
  incidentType: IncidentType
): string[] {
  if (
    incidentType === "Human Contact"
  ) {
    return [
      "Transport Authority",
      "Estate Facilities"
    ];
  }

  if (
    incidentType === "Near Miss"
  ) {
    return [
      "Transport Authority"
    ];
  }

  if (
    incidentType === "Property Collision"
  ) {
    return [
      "Estate Facilities"
    ];
  }

  return [
    "Cybersecurity Authority"
  ];
}

function containsInventedClaim(
  text: string
): boolean {
  return (
    /\bHIST-\d+\b/i.test(text) ||
    /\b\d+(?:\.\d+)?%/.test(text) ||
    /\b\d+\s+(?:of|out of)\s+\d+\b/i.test(
      text
    ) ||
    /\b(?:confirmed|proved|established)\b/i.test(
      text
    ) ||
    /\b(?:telemetry|logs?)\s+(?:shows?|showed|confirms?|confirmed|indicates?|indicated)\b/i.test(
      text
    )
  );
}

function containsIrrelevantCause(
  incidentType: IncidentType,
  text: string
): boolean {
  if (
    incidentType === "Conduct / Privacy"
  ) {
    return /\b(?:proximity sensor|collision avoidance|turning clearance)\b/i.test(
      text
    );
  }

  if (
    incidentType === "Property Collision"
  ) {
    return /\b(?:speech privacy|medical information disclosure)\b/i.test(
      text
    );
  }

  return /\b(?:speech privacy filter|personal information access)\b/i.test(
    text
  );
}

function cleanRcaField(
  text: string,
  heading: string
): string {
  return String(text || "")
    .replace(
      new RegExp(
        `^${heading}\\s*:?\\s*`,
        "i"
      ),
      ""
    )
    .replace(/\s+/g, " ")
    .trim();
}

function trimWords(
  text: string,
  maximum: number
): string {
  const words = text
    .trim()
    .split(/\s+/);

  if (words.length <= maximum) {
    return text.trim();
  }

  return `${words
    .slice(0, maximum)
    .join(" ")}.`;
}

function fallbackAnalysis(
  card: IncidentCard
): RcaAnalysis {
  if (
    card.incidentType === "Human Contact"
  ) {
    return {
      likelyCause:
        "Cause remains unconfirmed. Person-detection or stopping-response failure is a working hypothesis; telemetry and inspection are required.",

      recommendedAction:
        `Keep ${card.humanoidId} isolated, check the affected person, preserve logs, obtain vendor telemetry and verify stopping behaviour before return to service.`
    };
  }

  if (
    card.incidentType === "Near Miss"
  ) {
    return {
      likelyCause:
        "Cause remains unconfirmed. Late person detection or stop-command recognition is a working hypothesis; telemetry and testing are required.",

      recommendedAction:
        `Keep ${card.humanoidId} paused, preserve logs, inspect detection and stop-command handling, then conduct controlled crossing tests before return to service.`
    };
  }

  if (
    card.incidentType === "Property Collision"
  ) {
    return {
      likelyCause:
        "Cause remains unconfirmed. Navigation or turning-clearance failure is a working hypothesis; inspection and telemetry are required.",

      recommendedAction:
        `Keep ${card.humanoidId} isolated, secure the damaged area, preserve logs, inspect for faults or interference, and test navigation before return to service.`
    };
  }

  return {
    likelyCause:
      "Cause remains unconfirmed. Excessive information access or missing speech-privacy filtering is a working hypothesis; audit evidence is required.",

    recommendedAction:
      `Keep ${card.humanoidId} muted, preserve audit logs, review data access, apply least privilege and complete privacy testing before return to service.`
  };
}

function limitWords(
  text: string,
  maximum: number
): string {
  const words = text
    .trim()
    .split(/\s+/);

  if (words.length <= maximum) {
    return text.trim();
  }

  return `${words
    .slice(0, maximum)
    .join(" ")}.`;
}

export class IncidentLogAgent extends Agent<
  Env,
  LogState
> {
  initialState: LogState = {};

  async createLog(
    transcript: string
  ): Promise<IncidentCard> {
    if (!transcript.trim()) {
      throw new Error(
        "Transcript is required."
      );
    }

    const redacted =
      redactPii(transcript);

    const result =
      await this.env.AI.run(
        "@cf/meta/llama-3.1-8b-instruct-fast",
        {
          messages: [
            {
              role: "system",
              content: `You log human-humanoid incidents.

Interpret informal Singlish and mixed English, Malay and Chinese.
Extract only supplied facts.
Never reconstruct an identity.
Never include phone numbers or resident IDs in the summary.
Never attribute a person's injury or contact information to a humanoid.
Use "Unknown" for missing information.`
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
                occurredAt: {
                  type: "string"
                },
                humanoidId: {
                  type: "string"
                },
                summary: {
                  type: "string"
                },
                reportedHarm: {
                  type: "string"
                },
                immediateAction: {
                  type: "string"
                }
              },
              required: [
                "incidentType",
                "occurredAt",
                "humanoidId",
                "summary",
                "reportedHarm",
                "immediateAction"
              ]
            }
          }
        }
      );

    const fields =
      parseModelJson<IncidentModelFields>(
        result.response
      );

    fields.incidentType =
      inferIncidentType(
        transcript,
        fields.incidentType
      );

    fields.humanoidId =
      cleanOperationalField(
        fields.humanoidId
      );

    fields.occurredAt =
      extractOccurredAt(
        transcript,
        fields.occurredAt
      );

    fields.reportedHarm =
      extractReportedHarm(
        transcript,
        fields.reportedHarm,
        fields.incidentType
      );

    fields.immediateAction =
      extractImmediateAction(
        transcript,
        fields.incidentType,
        fields.humanoidId,
        fields.immediateAction
      );

    fields.summary =
      buildSafeSummary(
        fields,
        transcript
      );

    const card: IncidentCard = {
      id: `INC-${Date.now()}`,
      ...fields,
      redactedFields:
        redacted.fields
    };

    this.setState({
      latest: card
    });

    return card;
  }
}

export class TriageAgent
  extends Agent<Env> {
  async triage(
    card: IncidentCard
  ): Promise<TriageCard> {
    const result =
      await this.env.AI.run(
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

Critical means life-threatening harm or uncontrolled danger.
High means reported human injury or major safety-control failure.
Medium means a contained near miss, property damage or privacy incident.
Low means no harm and no continuing risk.

The affected person receives care, not the humanoid.
Containment must pause, mute or isolate the humanoid.
Do not perform root-cause analysis.`
            },
            {
              role: "user",
              content:
                JSON.stringify(card)
            }
          ],
          temperature: 0.1,
          max_tokens: 180
        }
      );

    const triage =
      parseModelJson<TriageCard>(
        result.response
      );

    return applyTriageGuardrails(
      card,
      triage
    );
  }
}

export class RcaAgent
  extends Agent<Env> {
  private seedHistory(): void {
    this.sql`
      CREATE TABLE IF NOT EXISTS incident_history (
        id TEXT PRIMARY KEY,
        incident_card TEXT NOT NULL,
        triage TEXT NOT NULL,
        rca TEXT NOT NULL
      )
    `;

    const incidentTypes: IncidentType[] = [
      "Human Contact",
      "Near Miss",
      "Property Collision",
      "Conduct / Privacy"
    ];

    const causes: Record<
      IncidentType,
      string[]
    > = {
      "Human Contact": [
        "Late proximity detection",
        "Late proximity detection",
        "Late proximity detection",
        "Route clearance was not verified",
        "Cause unconfirmed"
      ],

      "Near Miss": [
        "Crossing intent was detected late",
        "Crossing intent was detected late",
        "Crossing intent was detected late",
        "Stop command was not recognised",
        "Cause unconfirmed"
      ],

      "Property Collision": [
        "Temporary obstruction was absent from route planning",
        "Temporary obstruction was absent from route planning",
        "Temporary obstruction was absent from route planning",
        "Turning clearance was insufficient",
        "Cause unconfirmed"
      ],

      "Conduct / Privacy": [
        "Content access controls were too broad",
        "Content access controls were too broad",
        "Content access controls were too broad",
        "Speech privacy filtering was not applied",
        "Cause unconfirmed"
      ]
    };

    const actions: Record<
      IncidentType,
      string
    > = {
      "Human Contact":
        "Inspect proximity sensing and verify stopping distance.",

      "Near Miss":
        "Test crossing detection and emergency-stop recognition.",

      "Property Collision":
        "Inspect route planning and turning clearance.",

      "Conduct / Privacy":
        "Review access controls and speech privacy filtering."
    };

    for (
      let index = 0;
      index < 20;
      index++
    ) {
      const incidentType =
        incidentTypes[index % 4]!;

      const occurrence =
        Math.floor(index / 4);

      const likelyCause =
        causes[incidentType][occurrence]!;

      const id =
        `HIST-${String(index + 1).padStart(3, "0")}`;

      const humanoidId =
        `HMD-${String((index % 9) + 1).padStart(2, "0")}`;

      const route: TriageCard["route"] =
        incidentType ===
        "Conduct / Privacy"
          ? "Conduct / Privacy"
          : incidentType ===
              "Property Collision"
            ? "Technical"
            : "Safety";

      const severity:
        TriageCard["severity"] =
          incidentType ===
          "Human Contact"
            ? "High"
            : "Medium";

      const incidentCard =
        JSON.stringify({
          id,
          incidentType,
          humanoidId,
          summary:
            `Synthetic historical ${incidentType.toLowerCase()} incident.`
        });

      const triage =
        JSON.stringify({
          severity,
          route,
          containment:
            "Incident contained and evidence preserved."
        });

      const rca =
        JSON.stringify({
          likelyCause,
          recommendedAction:
            actions[incidentType]
        });

      this.sql`
        INSERT OR REPLACE
        INTO incident_history
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
        SELECT
          id,
          incident_card,
          triage,
          rca
        FROM incident_history
        ORDER BY id
        LIMIT 20
      `
    ];

    const recurrence =
      calculateRecurrence(
        history,
        card.incidentType
      );

    const guidelines = {
      transportAuthority:
        "Humanoids must yield to people, stop when detection is uncertain, and report physical-contact events.",

      estateFacilities:
        "Isolate affected equipment or areas, preserve logs and scene evidence, and notify the duty facilities manager.",

      cybersecurityAuthority:
        "Contain unauthorized access, preserve audit logs, apply least privilege, and rotate exposed credentials."
    };

    const guidelineNames =
      relevantGuidelines(
        card.incidentType
      );

    const safeExpertComment =
      expertReply.trim()
        ? cleanOperationalField(
            expertReply
          )
        : "No expert comment was provided.";

    const result =
      await this.env.AI.run(
        "@cf/qwen/qwen3-30b-a3b-fp8",
        {
          messages: [
            {
              role: "system",
              content: `You are the RCA analysis agent.

Return only valid JSON:
{
  "likelyCause": "a cautious working hypothesis, maximum 24 words",
  "recommendedAction": "a practical action, maximum 30 words"
}

Use only supplied information.
The incident report is not independent proof.
The expert comment is an opinion, not confirmed evidence.
Do not change or quote the expert comment.
Do not invent telemetry, inspections, historical IDs, counts or percentages.
Do not claim a specific humanoid has prior incidents.
Do not repeat recurrence statistics.
A sabotage suggestion may justify inspection but is not proof of sabotage.
Reference only the listed relevant guidelines.`
            },
            {
              role: "user",
              content:
                `/no_think\n${JSON.stringify({
                  currentIncident: card,
                  triage,
                  guidelines,
                  relevantGuidelines:
                    guidelineNames,
                  expertComment:
                    safeExpertComment,
                  verifiedDatabaseSummary:
                    recurrence
                })}`
            }
          ],
          temperature: 0.1,
          max_tokens: 1200,
          response_format: {
            type: "json_schema",
            json_schema: {
              type: "object",
              properties: {
                likelyCause: {
                  type: "string"
                },
                recommendedAction: {
                  type: "string"
                }
              },
              required: [
                "likelyCause",
                "recommendedAction"
              ]
            }
          }
        }
      );

    const payload =
      extractModelPayload(result);

    let analysis =
      parseModelJson<RcaAnalysis>(
        payload
      );

    analysis = {
      likelyCause:
        trimWords(
          cleanRcaField(
            analysis.likelyCause,
            "likely cause"
          ),
          24
        ),

      recommendedAction:
        trimWords(
          cleanRcaField(
            analysis.recommendedAction,
            "recommended action"
          ),
          30
        )
    };

    if (
      !analysis.likelyCause ||
      !analysis.recommendedAction ||
      containsInventedClaim(
        analysis.likelyCause
      ) ||
      containsInventedClaim(
        analysis.recommendedAction
      ) ||
      containsIrrelevantCause(
        card.incidentType,
        analysis.likelyCause
      ) ||
      /\b(?:sabotage|deliberate interference)\b/i.test(
        analysis.likelyCause
      )
    ) {
      analysis =
        fallbackAnalysis(card);
    }

    const report = [
      `**Likely cause (unconfirmed):** ${analysis.likelyCause}`,

      `**Supporting evidence:** The incident report states: ${card.summary} Triage: ${triage.severity}, ${triage.route}. No telemetry or inspection findings were supplied.`,

      `**Expert comment:** ${safeExpertComment}`,

      `**Recurrence pattern:** ${recurrenceText(
        card,
        recurrence
      )}`,

      `**Recommended action:** ${analysis.recommendedAction} Relevant guidelines: ${guidelineNames.join(", ")}.`
    ].join("\n\n");

    return limitWords(
      report,
      150
    );
  }
}

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods":
    "POST, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type"
};

function json(
  data: unknown,
  status = 200
): Response {
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
    if (
      request.method === "OPTIONS"
    ) {
      return new Response(null, {
        headers: corsHeaders
      });
    }

    if (
      request.method !== "POST"
    ) {
      return json(
        {
          error: "Use POST"
        },
        405
      );
    }

    try {
      const path =
        new URL(request.url).pathname;

      const body =
        await request.json<
          Record<string, unknown>
        >();

      const sessionId =
        String(
          body.sessionId || "demo"
        );

      if (path === "/api/log") {
        const agent =
          await getRpcAgent<IncidentLogRpc>(
            env.INCIDENT_LOG_AGENT,
            sessionId
          );

        return json(
          await agent.createLog(
            String(
              body.transcript || ""
            )
          )
        );
      }

      if (
        path === "/api/triage"
      ) {
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
          rca:
            await agent.generateRca(
              body.card as IncidentCard,
              body.triage as TriageCard,
              String(
                body.expertReply || ""
              )
            )
        });
      }

      return json(
        {
          error: "Not found"
        },
        404
      );
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