// Pure consent-state logic, kept out of the React layer so the dependency rules are unit-testable.
import type { ConsentItem } from "./types.ts";

/** All consents start unchecked. */
export function initConsents(items: ConsentItem[]): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const it of items) out[it.id] = false;
  return out;
}

/**
 * Toggle one consent and re-establish the `implies` invariant: a checked item requires every id it
 * implies to be checked. Checking an item also checks what it implies (transitively); unchecking an
 * item also unchecks anything that (transitively) implies it.
 */
export function toggleConsent(
  consents: Record<string, boolean>,
  items: ConsentItem[],
  id: string,
): Record<string, boolean> {
  const byId = new Map(items.map((i) => [i.id, i]));
  const next = { ...consents, [id]: !consents[id] };

  if (next[id]) {
    const stack = [...(byId.get(id)?.implies ?? [])];
    while (stack.length) {
      const dep = stack.pop()!;
      if (!next[dep]) {
        next[dep] = true;
        stack.push(...(byId.get(dep)?.implies ?? []));
      }
    }
  } else {
    // Fixpoint: drop any checked item whose implied dependency is now unchecked.
    let changed = true;
    while (changed) {
      changed = false;
      for (const it of items) {
        if (next[it.id] && it.implies?.some((d) => !next[d])) {
          next[it.id] = false;
          changed = true;
        }
      }
    }
  }
  return next;
}

/** Returns `{ [id]: message }` for any required consent left unchecked. */
export function validateConsents(
  consents: Record<string, boolean>,
  items: ConsentItem[],
): Record<string, string> {
  const errs: Record<string, string> = {};
  for (const it of items) {
    if (it.required && !consents[it.id]) errs[it.id] = "Required to proceed";
  }
  return errs;
}
