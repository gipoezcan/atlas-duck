// Embedded JS self-test for the spec 9.3 engine configuration (spec 15 V11).
// Source text only, never bytecode. Evaluated by engine::run_selftest_in as a
// function expression: `start(expectUtc)` runs every check that needs no
// pending job, registers the Promise checks, and publishes
// `globalThis.__atlas_selftest_finish`. Rust drains the job queue and then
// calls `finish()`, which returns the failed check names joined by ", "
// (an empty string means every check passed).
(function (expectUtc) {
  'use strict';
  var failures = [];
  function check(name, ok) {
    if (!ok) {
      failures.push(name);
    }
  }

  // Base objects
  check('Array.map', [1, 2, 3].map(function (x) { return x * 2; }).join() === '2,4,6');
  check('String.toUpperCase', 'abc'.toUpperCase() === 'ABC');
  check('Math.max', Math.max(1, 2) === 2);
  check('Symbol.iterator', typeof Symbol.iterator === 'symbol');
  check('RangeError', new RangeError('x') instanceof Error);

  // Eval (required to load source, spec 9.3)
  check('Eval.eval', eval('1 + 2') === 3);
  check('Eval.Function', new Function('a', 'return a + 1')(1) === 2);

  // JSON
  check('JSON.parse', JSON.parse('{"a":[1,2,{"b":null}]}').a[2].b === null);
  check('JSON.stringify', JSON.stringify({ a: [1, 'x'] }) === '{"a":[1,"x"]}');

  // RegExp
  check('RegExp.literal', /a+/.test('aa'));
  check('RegExp.constructor', new RegExp('b+').test('bb'));
  check('RegExp.replace', '2026-10-07'.replace(/(\d+)-(\d+)-(\d+)/, '$3.$2.$1') === '07.10.2026');

  // MapSet
  var m = new Map();
  m.set('k', 1).set('l', 2);
  check('Map', m.get('k') === 1 && m.size === 2);
  var s = new Set([1, 1, 2]);
  check('Set', s.size === 2 && s.has(2));
  check('MapSet.spread', [...m.keys()].join() === 'k,l');

  // Date, with TZ=UTC0 where libc honours it (Unix, spec 3.4)
  var d = new Date(2026, 0, 1);
  check('Date.getHours', d.getHours() === 0);
  var offset = d.getTimezoneOffset();
  check('Date.getTimezoneOffset', typeof offset === 'number' && offset === Math.floor(offset));
  if (expectUtc) {
    check('Date.getTimezoneOffset is 0', offset === 0);
    check('Date local equals UTC', d.getTime() === Date.UTC(2026, 0, 1));
  }
  check('Date.toLocaleString', typeof d.toLocaleString() === 'string');
  check('Date.toLocaleDateString', typeof d.toLocaleDateString() === 'string');
  check('Date.toISOString', new Date(0).toISOString() === '1970-01-01T00:00:00.000Z');
  check('Date.UTC', Date.UTC(2026, 0, 1) === 1767225600000);
  check('Date.now', typeof Date.now() === 'number');

  // Promise: these settle only when Rust drains the job queue.
  var thenRan = false;
  var asyncRan = false;
  var allRan = false;
  Promise.resolve(41).then(function (v) { thenRan = (v + 1 === 42); });
  (async function () {
    var v = await Promise.resolve(7);
    asyncRan = (v === 7);
  })();
  Promise.all([Promise.resolve(1), Promise.resolve(2)]).then(function (vs) {
    allRan = (vs.join() === '1,2');
  });
  check('Promise is not synchronous', thenRan === false);

  globalThis.__atlas_selftest_finish = function () {
    check('Promise.then job drained', thenRan);
    check('async function job drained', asyncRan);
    check('Promise.all job drained', allRan);
    return failures.join(', ');
  };
})
