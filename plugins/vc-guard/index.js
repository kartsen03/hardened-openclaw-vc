// vc-guard: defense-in-depth hooks for the hardened deployment.
//
//  1. before_tool_call   - blocks any tool that is not on the calling agent's allowlist (a second
//                          check behind OpenClaw's own tool policy), and blocks web_fetch to hosts
//                          that are not on the fetch allowlist (a second check behind the proxy).
//  2. tool-result middleware - replaces secret values in tool output before the model sees it.
//  3. tool_result_persist / before_message_write - replaces secret values before transcript writes.
//  4. message_sending / reply_payload_sending   - replaces secret values in outgoing replies.
//  5. An audit line per tool decision: time, agent, tool, decision, reason, URL host for
//     web_fetch. No arguments or results are logged, so the audit log holds no content.
//
// Policy comes from a read-only JSON file (VC_GUARD_POLICY). Secret *values* are read from the
// environment variables the policy names and are kept only in memory; they are never logged.
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const POLICY_PATH = process.env.VC_GUARD_POLICY || "/run/config/vc-guard-policy.json";
const policy = JSON.parse(readFileSync(POLICY_PATH, "utf8"));
const AUDIT = policy.auditLog || "/state/vc-guard/tool-calls.jsonl";
const MARK = "[REDACTED]";

// Secret values plus simple encodings of them, longest first.
function buildSecretVariants() {
  const out = new Set();
  for (const name of policy.redactEnv || []) {
    const v = process.env[name];
    if (!v || v.length < 8) continue;
    const b = Buffer.from(v, "utf8");
    out.add(v);
    out.add(b.toString("base64").replace(/=+$/, ""));
    out.add(b.toString("base64url"));
    out.add(b.toString("hex"));
    out.add([...v].reverse().join(""));
    out.add(encodeURIComponent(v));
  }
  return [...out].filter((s) => s.length >= 8).sort((a, b) => b.length - a.length);
}
const SECRETS = buildSecretVariants();

function redactString(s) {
  if (typeof s !== "string" || SECRETS.length === 0) return s;
  let out = s;
  for (const v of SECRETS) if (out.includes(v)) out = out.split(v).join(MARK);
  return out;
}

// Deep copy with every string redacted. Returns [copy, changed].
function redactDeep(value, depth = 0) {
  if (depth > 40) return [value, false];
  if (typeof value === "string") {
    const r = redactString(value);
    return [r, r !== value];
  }
  if (Array.isArray(value)) {
    let changed = false;
    const arr = value.map((v) => {
      const [r, c] = redactDeep(v, depth + 1);
      changed ||= c;
      return r;
    });
    return [changed ? arr : value, changed];
  }
  if (value && typeof value === "object") {
    let changed = false;
    const obj = {};
    for (const [k, v] of Object.entries(value)) {
      const [r, c] = redactDeep(v, depth + 1);
      changed ||= c;
      obj[k] = r;
    }
    return [changed ? obj : value, changed];
  }
  return [value, false];
}

function audit(entry) {
  try {
    mkdirSync(dirname(AUDIT), { recursive: true });
    appendFileSync(AUDIT, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n");
  } catch {
    // Audit failure must not crash the gateway; the decision itself is still enforced.
  }
}

function hostAllowed(host) {
  host = String(host || "").toLowerCase().replace(/\.$/, "");
  return (policy.fetchAllowlist || []).some((rule) => {
    rule = rule.toLowerCase();
    return rule.startsWith("*.") ? host === rule.slice(2) || host.endsWith(rule.slice(1)) : host === rule;
  });
}

export default definePluginEntry({
  id: "vc-guard",
  name: "VC guard",
  description: "Tool allowlist, fetch allowlist, secret redaction and tool-call audit log.",
  register(api) {
    api.on(
      "before_tool_call",
      (event, ctx) => {
        const agent = ctx?.agentId || "unknown";
        const tool = event?.toolName || "unknown";
        const allowed = policy.agents?.[agent];
        // Tool discovery helpers are needed to call anything at all; they do nothing themselves.
        const always = new Set(policy.alwaysAllow || []);
        if (!always.has(tool) && (!Array.isArray(allowed) || !allowed.includes(tool))) {
          audit({ agent, tool, decision: "block", reason: "tool_not_allowed_for_agent", run: ctx?.runId });
          return { block: true, blockReason: `vc-guard: tool '${tool}' is not allowed for agent '${agent}'.` };
        }
        if (tool === "web_fetch") {
          let host = "";
          try {
            host = new URL(String(event.params?.url || "")).hostname;
          } catch {
            host = "";
          }
          if (!hostAllowed(host)) {
            audit({ agent, tool, decision: "block", reason: "host_not_allowlisted", host, run: ctx?.runId });
            return { block: true, blockReason: `vc-guard: '${host || "invalid URL"}' is not an approved source.` };
          }
          audit({ agent, tool, decision: "allow", host, run: ctx?.runId });
          return;
        }
        audit({ agent, tool, decision: "allow", run: ctx?.runId });
      },
      { priority: 100 },
    );

    api.registerAgentToolResultMiddleware((event) => {
      const [result, changed] = redactDeep(event.result);
      if (changed) {
        audit({ tool: event.toolName, decision: "redacted_tool_result" });
        return { result };
      }
    });

    api.on("tool_result_persist", (event) => {
      const [message, changed] = redactDeep(event?.message);
      if (changed) return { message };
    });

    api.on("before_message_write", (event) => {
      const [message, changed] = redactDeep(event?.message);
      if (changed) return { message };
    });

    for (const hook of ["message_sending", "reply_payload_sending"]) {
      api.on(hook, (event) => {
        const [copy, changed] = redactDeep(event);
        if (!changed) return;
        audit({ decision: "redacted_outbound", hook });
        // Return the rewritten fields the hook understands; unknown keys are ignored by the host.
        const { content, text, payload } = copy;
        return { content, text, payload };
      });
    }
  },
});
