// Single-point mutations of a JSON body: every field set to each value of a
// list, every field removed, an unknown key added to every object. Comparing a
// hand-written validator with the contract schema over this sweep catches the
// drift no hand-written case list would.

export interface Mutant {
  what: string;
  value: unknown;
}

export function paths(value: unknown, prefix = ""): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, i) => [`${prefix}/${i}`, ...paths(item, `${prefix}/${i}`)]);
  }
  if (typeof value === "object" && value !== null) {
    return Object.keys(value).flatMap((key) => [
      `${prefix}/${key}`,
      ...paths((value as Record<string, unknown>)[key], `${prefix}/${key}`),
    ]);
  }
  return [];
}

function at(root: unknown, path: string): { parent: any; key: string | number } {
  const parts = path.split("/").slice(1);
  let parent: any = root;
  for (const part of parts.slice(0, -1)) parent = Array.isArray(parent) ? parent[Number(part)] : parent[part];
  const last = parts[parts.length - 1]!;
  return { parent, key: Array.isArray(parent) ? Number(last) : last };
}

export function* mutants(body: Record<string, unknown>, values: readonly unknown[]): Generator<Mutant> {
  for (const path of paths(body)) {
    for (const value of values) {
      const copy = structuredClone(body);
      const { parent, key } = at(copy, path);
      parent[key] = value;
      yield { what: `set ${path} = ${JSON.stringify(value) ?? "undefined"}`, value: copy };
    }
    const removed = structuredClone(body);
    const { parent, key } = at(removed, path);
    if (Array.isArray(parent)) parent.splice(key as number, 1);
    else delete parent[key];
    yield { what: `remove ${path}`, value: removed };

    // An unknown key in every object of the body.
    const { parent: target } = at(structuredClone(body), `${path}/x`);
    if (target !== undefined && !Array.isArray(target) && typeof target === "object" && target !== null) {
      const extra = structuredClone(body);
      (at(extra, `${path}/x`).parent as Record<string, unknown>).unexpected = 1;
      yield { what: `add ${path}/unexpected`, value: extra };
    }
  }
  const extra = structuredClone(body);
  extra.unexpected = 1;
  yield { what: "add /unexpected", value: extra };
}
