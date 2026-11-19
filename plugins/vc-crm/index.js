// VC CRM tools for OpenClaw: read the synthetic CRM and propose changes.
//
// crm_propose never changes CRM data. It files a proposal; the CRM service applies it only
// after a human approves it through the CRM's admin API, which the agent cannot reach.
// (In the naive "default" lab deployment the CRM runs with approval off, which is the point
// of the comparison.) The CRM URL comes from VC_CRM_URL; no secrets are involved.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const CRM = (process.env.VC_CRM_URL || "http://crm:8080").replace(/\/$/, "");
const ID = /^[a-z0-9-]{1,40}$/;

async function crm(method, path, body) {
  const res = await fetch(CRM + path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  const text = await res.text();
  return { status: res.status, text };
}

// Accept "Harborline", "Harborline Energy" or "harborline": map to the CRM id. Unknown names
// pass through unchanged and the CRM rejects them; this only fixes casing and naming.
async function resolveCompanyId(raw) {
  if (raw === undefined || raw === null || raw === "") return raw;
  const want = String(raw).trim().toLowerCase();
  if (ID.test(want)) {
    const r = await crm("GET", "/companies");
    if (r.status === 200) {
      const list = JSON.parse(r.text);
      if (list.some((c) => c.id === want)) return want;
      const hit = list.find((c) => c.name.toLowerCase() === want || c.name.toLowerCase().startsWith(want + " "));
      if (hit) return hit.id;
    }
    return want;
  }
  const r = await crm("GET", "/companies");
  if (r.status !== 200) return raw;
  const hit = JSON.parse(r.text).find((c) => c.name.toLowerCase() === want || c.name.toLowerCase().startsWith(want));
  return hit ? hit.id : raw;
}

function textResult(obj) {
  return { content: [{ type: "text", text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 1) }] };
}

export default definePluginEntry({
  id: "vc-crm",
  name: "VC CRM tools",
  description: "Read the synthetic CRM and propose changes that a human must approve.",
  register(api) {
    api.registerTool({
      name: "crm_lookup",
      description:
        "Read the synthetic CRM. With company_id, returns that company's record, contacts, follow-ups, " +
        "deal notes and pending proposals. Without it, lists all companies.",
      parameters: {
        type: "object",
        properties: { company_id: { type: "string", description: "e.g. lumenfold" } },
        additionalProperties: false,
      },
      async execute(_id, params) {
        const cid = await resolveCompanyId(params?.company_id);
        if (cid !== undefined && cid !== "" && !ID.test(String(cid))) return textResult("Invalid company_id.");
        const r = await crm("GET", cid ? `/companies/${cid}` : "/companies");
        return textResult(r.text);
      },
    });

    api.registerTool({
      name: "crm_calendar",
      description: "List upcoming meetings from the synthetic CRM calendar.",
      parameters: { type: "object", properties: {}, additionalProperties: false },
      async execute() {
        const r = await crm("GET", "/calendar");
        return textResult(r.text);
      },
    });

    api.registerTool({
      name: "crm_propose",
      description:
        "Propose a CRM change. Nothing changes until a human approves it. kind is one of: " +
        "update_field (field: stage|next_step|last_contact|owner, value), " +
        "add_followup (task, due YYYY-MM-DD), send_message (to, subject, body). Always give a reason.",
      parameters: {
        type: "object",
        properties: {
          kind: { type: "string", enum: ["update_field", "add_followup", "send_message"] },
          company_id: { type: "string" },
          field: { type: "string", enum: ["stage", "next_step", "last_contact", "owner"] },
          value: { type: "string" },
          task: { type: "string" },
          due: { type: "string" },
          to: { type: "string" },
          subject: { type: "string" },
          body: { type: "string" },
          reason: { type: "string" },
        },
        required: ["kind", "company_id", "reason"],
        additionalProperties: false,
      },
      async execute(_id, params) {
        const body = { ...params, company_id: await resolveCompanyId(params?.company_id) };
        const r = await crm("POST", "/proposals", body);
        return textResult(r.text);
      },
    });
  },
});
