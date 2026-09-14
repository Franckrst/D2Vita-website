// The frozen API v1 contract (../../contract) as compiled validators and as
// vectors. Nothing here imports the API: this module is the yardstick the tests
// hold the API against.
//
// Schemas are compiled with Ajv 2020 in strict mode, all four registered by
// $id so that the $refs between them resolve (contract/README.md, "Notes for
// implementers").

import Ajv2020, { type ValidateFunction } from "ajv/dist/2020";
import adminSchema from "../../contract/schemas/admin.v1.schema.json";
import bugSchema from "../../contract/schemas/bug.v1.schema.json";
import claimSchema from "../../contract/schemas/claim.v1.schema.json";
import decisionSchema from "../../contract/schemas/decision.v1.schema.json";
import claimsInvalid from "../../contract/vectors/claims-invalid.v1.json";
import responseSig from "../../contract/vectors/response-sig.v1.json";
import signatures from "../../contract/vectors/signatures.v1.json";

export const SCHEMAS = {
  "claim.v1": claimSchema,
  "decision.v1": decisionSchema,
  "bug.v1": bugSchema,
  "admin.v1": adminSchema,
} as const;

export type SchemaFile = keyof typeof SCHEMAS;

export interface SignatureVector {
  name: string;
  claim: Record<string, unknown>;
  canon: string;
  signature: string;
}

export interface InvalidClaimVector {
  name: string;
  base: string;
  claim: unknown;
  invalid_at: string;
}

export interface ResponseSigVector {
  name: string;
  seed_hex: string;
  public_key_hex: string;
  body_utf8: string;
  signature_b64: string;
}

export interface ResponseSigNegative {
  name: string;
  public_key_hex: string;
  body_utf8: string;
  signature_b64: string;
  expect: string;
}

export const SIGNATURE_VECTORS = signatures.cases as SignatureVector[];
export const INVALID_CLAIM_VECTORS = claimsInvalid.cases as InvalidClaimVector[];
export const RESPONSE_SIG_VECTORS = responseSig.cases as ResponseSigVector[];
export const RESPONSE_SIG_NEGATIVES = responseSig.negative_cases as ResponseSigNegative[];

const ajv = new Ajv2020({ strict: true, allErrors: true });
ajv.addSchema(Object.values(SCHEMAS));

const compiled = new Map<string, ValidateFunction>();

// `ref` is "<file>" or "<file>#<Name>", e.g. "claim.v1", "admin.v1#ErrorBody".
export function contractValidator(ref: string): ValidateFunction {
  let validate = compiled.get(ref);
  if (!validate) {
    const [file, name] = ref.split("#") as [SchemaFile, string | undefined];
    const schema = SCHEMAS[file];
    if (!schema) throw new Error(`unknown contract schema ${file}`);
    const uri = name ? `${schema.$id}#/$defs/${name}` : schema.$id;
    const found = ajv.getSchema(uri);
    if (!found) throw new Error(`unknown contract definition ${ref}`);
    validate = found;
    compiled.set(ref, validate);
  }
  return validate;
}

// null when `value` matches the definition, otherwise every error as text.
export function contractErrors(ref: string, value: unknown): string | null {
  const validate = contractValidator(ref);
  if (validate(value)) return null;
  return (validate.errors ?? [])
    .map((e) => `${e.instancePath || "/"} ${e.message ?? ""} ${JSON.stringify(e.params)}`)
    .join("; ");
}

export function matchesContract(ref: string, value: unknown): boolean {
  return contractValidator(ref)(value);
}

// ---------------------------------------------------------------------------
// Responses: which definition each answer must match, and the rules of
// contract/README.md around them (status of every error code, answers bound to
// the request they answer, signed console routes).

// Status of every error code (contract/README.md, "Error codes").
export const ERROR_STATUS: Record<string, number> = {
  invalid_payload: 400,
  unauthorized: 401,
  unknown_build: 403,
  bad_token: 403,
  turnstile: 403,
  not_found: 404,
  method_not_allowed: 405,
  exists: 409,
  incomplete: 409,
  payload_too_large: 413,
  rate_limited: 429,
  internal_error: 500,
  not_accepting: 503,
};

export const ERROR_CODES = Object.keys(ERROR_STATUS);

const REPORT_ID = new RegExp(SCHEMAS["claim.v1"].$defs.ReportId.pattern);
const ARTIFACT_NAMES: readonly string[] = SCHEMAS["claim.v1"].$defs.ArtifactName.enum;

interface Route {
  method: string;
  path: RegExp;
  success: Record<number, string>;
}

const ROUTES: Route[] = [
  { method: "POST", path: /^\/v1\/claims$/, success: { 200: "decision.v1" } },
  {
    method: "PUT",
    path: /^\/v1\/reports\/[^/]+\/artifacts\/[^/]+$/,
    success: { 201: "decision.v1#ArtifactStored" },
  },
  { method: "POST", path: /^\/v1\/reports\/[^/]+\/complete$/, success: { 200: "decision.v1#CompleteResponse" } },
  { method: "POST", path: /^\/v1\/bugs$/, success: { 201: "bug.v1#BugCreated" } },
  { method: "GET", path: /^\/v1\/admin\/signatures$/, success: { 200: "admin.v1#SignatureList" } },
  { method: "GET", path: /^\/v1\/admin\/signatures\/[^/]+$/, success: { 200: "admin.v1#SignatureDetail" } },
  { method: "PATCH", path: /^\/v1\/admin\/signatures\/[^/]+$/, success: { 200: "admin.v1#SignatureDetail" } },
  { method: "GET", path: /^\/v1\/admin\/reports\/[^/]+$/, success: { 200: "admin.v1#ReportDetail" } },
  { method: "GET", path: /^\/v1\/admin\/bugs$/, success: { 200: "admin.v1#BugList" } },
  { method: "GET", path: /^\/v1\/admin\/bugs\/[^/]+$/, success: { 200: "admin.v1#BugDetail" } },
  { method: "PATCH", path: /^\/v1\/admin\/bugs\/[^/]+$/, success: { 200: "admin.v1#BugDetail" } },
  { method: "POST", path: /^\/v1\/admin\/builds$/, success: { 200: "admin.v1#BuildRecord", 201: "admin.v1#BuildRecord" } },
  {
    method: "DELETE",
    path: /^\/v1\/admin\/installs\/[^/]+$/,
    // 202 is this API's "call again" answer; the body is the same.
    success: { 200: "admin.v1#ForgetInstallResult", 202: "admin.v1#ForgetInstallResult" },
  },
  { method: "GET", path: /^\/v1\/admin\/stats$/, success: { 200: "admin.v1#Stats" } },
  { method: "PUT", path: /^\/v1\/admin\/settings$/, success: { 200: "admin.v1#Settings" } },
];

// Console routes: every answer is signed and names the request it answers.
function consoleRequest(method: string, path: string): { report_id?: string; artifact?: string } | null {
  if (path === "/v1/claims") return {};
  const put = /^\/v1\/reports\/([^/]+)\/artifacts\/([^/]+)$/.exec(path);
  if (put && method === "PUT") {
    const bound: { report_id?: string; artifact?: string } = {};
    if (REPORT_ID.test(put[1]!)) bound.report_id = put[1]!;
    if (ARTIFACT_NAMES.includes(put[2]!)) bound.artifact = put[2]!;
    return bound;
  }
  const complete = /^\/v1\/reports\/([^/]+)\/complete$/.exec(path);
  if (complete && method === "POST") {
    return REPORT_ID.test(complete[1]!) ? { report_id: complete[1]! } : {};
  }
  return path.startsWith("/v1/reports/") ? {} : null;
}

export function successRef(method: string, path: string, status: number): string | undefined {
  const route = ROUTES.find((r) => r.method === method && r.path.test(path));
  return route?.success[status];
}

export interface ResponseProblem {
  where: string;
  detail: string;
}

// Every JSON answer the API produces has to match the contract: the definition
// of its route for a success, admin.v1#ErrorBody with the documented status for
// a failure, plus the binding and signature rules of the console routes.
// Returns the problems found, empty when the answer conforms.
export async function contractResponseProblems(request: Request, response: Response): Promise<ResponseProblem[]> {
  const { method } = request;
  const path = new URL(request.url).pathname;
  const problems: ResponseProblem[] = [];
  const where = `${method} ${path} -> ${response.status}`;
  const add = (detail: string) => problems.push({ where, detail });

  const bound = consoleRequest(method, path);
  if (bound !== null) {
    const signature = response.headers.get("x-d2v-signature");
    if (signature === null || signature.length !== 88) {
      add(`console answers are signed; X-D2V-Signature was ${JSON.stringify(signature)}`);
    }
  }

  const type = response.headers.get("content-type") ?? "";
  if (!type.startsWith("application/json")) return problems;
  let body: unknown;
  try {
    body = await response.clone().json();
  } catch (e) {
    add(`body is not JSON: ${String(e)}`);
    return problems;
  }

  if (response.status >= 400) {
    const errors = contractErrors("admin.v1#ErrorBody", body);
    if (errors) add(`does not match admin.v1#ErrorBody: ${errors}`);
    const code = (body as { error?: string }).error;
    if (code && ERROR_STATUS[code] !== response.status) {
      add(`error ${code} is ${ERROR_STATUS[code]} in the contract, not ${response.status}`);
    }
  } else {
    const ref = successRef(method, path, response.status);
    if (!ref) {
      add("no contract definition for this route and status (add it to ROUTES)");
      return problems;
    }
    const errors = contractErrors(ref, body);
    if (errors) add(`does not match ${ref}: ${errors}`);
  }

  // A signed body about one report names it, and the console compares.
  if (bound) {
    const named = body as { report_id?: string; name?: string; artifact?: string };
    if (bound.report_id !== undefined && named.report_id !== bound.report_id) {
      add(`report_id should be ${bound.report_id}, was ${JSON.stringify(named.report_id)}`);
    }
    const piece = response.status >= 400 ? named.artifact : named.name;
    if (bound.artifact !== undefined && piece !== bound.artifact) {
      add(`artifact should be ${bound.artifact}, was ${JSON.stringify(piece)}`);
    }
  }
  return problems;
}
