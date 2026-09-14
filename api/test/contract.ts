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
