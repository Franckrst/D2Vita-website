// Counts the D1 statements a piece of code runs. Every statement of a batch
// counts, as for the Workers Free limit of 50 D1 queries per invocation.

export interface CountedDb {
  db: D1Database;
  statements: () => number;
}

export function countStatements(db: D1Database): CountedDb {
  let statements = 0;
  const real = new WeakMap<object, D1PreparedStatement>();

  const wrap = (statement: D1PreparedStatement): D1PreparedStatement => {
    const proxy = new Proxy(statement, {
      get(target, prop) {
        if (prop === "bind") return (...values: unknown[]) => wrap(target.bind(...values));
        if (prop === "run" || prop === "all" || prop === "first" || prop === "raw") {
          return (...args: unknown[]) => {
            statements++;
            return (target[prop] as (...a: unknown[]) => unknown).apply(target, args);
          };
        }
        const value = Reflect.get(target, prop, target) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    real.set(proxy, statement);
    return proxy;
  };

  const proxy = new Proxy(db, {
    get(target, prop) {
      if (prop === "prepare") return (sql: string) => wrap(target.prepare(sql));
      if (prop === "batch") {
        return (list: D1PreparedStatement[]) => {
          statements += list.length;
          return target.batch(list.map((s) => real.get(s) ?? s));
        };
      }
      const value = Reflect.get(target, prop, target) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { db: proxy, statements: () => statements };
}
