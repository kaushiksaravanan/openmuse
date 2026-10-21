import { defineTool } from "@copilotkit/runtime/v2";
import { z } from "zod";
import type { AgentService } from "./engine/service.ts";

/** One closed-loop attempt: what the agent tried, what it observed, and the
 * ratchet verdict. The log is the durable memory; git semantics in spirit
 * (keep-if-improved, discard-and-log-otherwise) without a filesystem. */
export interface ResearchAttempt {
  round: number;
  hypothesis: string;
  actions: string;
  evidence: string;
  result: string;
  verdict: "keep" | "discard";
  note: string;
  at: string;
}

export interface ResearchProgram {
  id: string;
  threadId: string;
  objective: string;
  metric: string;
  budget: number;
  log: ResearchAttempt[];
  /** Summary of the current best-known state, updated whenever a round is kept. */
  best: string;
  updatedAt: string;
}

const attemptSchema = {
  round: z.number().int().min(0).max(10_000).optional(),
  hypothesis: z.string().trim().max(1000).optional(),
  actions: z.string().trim().max(2000).optional(),
  evidence: z.string().trim().max(4000).optional(),
  result: z.string().trim().max(2000).optional(),
  verdict: z.enum(["keep", "discard"]).optional(),
  note: z.string().trim().max(1000).optional(),
};

export function createResearchTools(service: AgentService, owner: string, threadId: string) {
  const recordId = `autoresearch:${threadId}`;
  const read = async () =>
    (await service.db.get<ResearchProgram>(owner, "autoresearch", recordId)) ?? null;
  const write = async (program: ResearchProgram) => {
    program.updatedAt = new Date().toISOString();
    await service.db.put(owner, "autoresearch", program);
    return program;
  };

  return [
    defineTool({
      name: "autoresearch",
      description:
        "Keep the experiment log of an autonomous research loop on this conversation. action plan starts or re-scopes the loop (objective, success metric, iteration budget); action append records one completed attempt with its keep/discard verdict; action read returns the whole log. The tool stores only the log; you run the experiments with the other tools.",
      parameters: z.object({
        action: z.enum(["plan", "append", "read"]),
        objective: z.string().trim().max(500).optional(),
        metric: z.string().trim().max(300).optional(),
        budget: z.number().int().min(1).max(200).optional(),
        ...attemptSchema,
      }),
      execute: async (args) => {
        try {
          if (args.action === "read") {
            const program = await read();
            return program
              ? { program }
              : {
                  message:
                    "No autoresearch loop is planned in this conversation yet. Call autoresearch with action plan first.",
                };
          }
          if (args.action === "plan") {
            if (!args.objective?.trim()) return { error: "plan requires the objective." };
            if (!args.metric?.trim()) return { error: "plan requires the success metric." };
            const existing = await read();
            const program: ResearchProgram = {
              id: recordId,
              threadId,
              objective: args.objective,
              metric: args.metric,
              budget: args.budget ?? 12,
              log: existing?.log ?? [],
              best: existing?.best ?? "",
              updatedAt: new Date().toISOString(),
            };
            await write(program);
            return { program };
          }
          // append
          const program = await read();
          if (!program)
            return {
              error: "No program yet: call autoresearch with action plan before appending.",
            };
          const attempt: ResearchAttempt = {
            round: args.round ?? program.log.length,
            hypothesis: args.hypothesis ?? "",
            actions: args.actions ?? "",
            evidence: args.evidence ?? "",
            result: args.result ?? "",
            verdict: args.verdict ?? "discard",
            note: args.note ?? "",
            at: new Date().toISOString(),
          };
          // The latest verdict wins for "best"; the log itself is append-only
          // history that is trimmed to the last 200 attempts.
          if (attempt.verdict === "keep" && attempt.result) program.best = attempt.result;
          program.log = [...program.log, attempt].slice(-200);
          await write(program);
          return { program };
        } catch (error) {
          return { error: error instanceof Error ? error.message : "Autoresearch log failed" };
        }
      },
    }),
  ];
}
