/**
 * An own entry of a text table. A wire name such as `constructor` or `__proto__` must not reach a
 * member of `Object.prototype`: the lookup would answer a function or an object, which React cannot
 * show, instead of falling back to the name itself.
 */
export function own<V>(table: Readonly<Record<string, V>>, key: string): V | undefined {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}
