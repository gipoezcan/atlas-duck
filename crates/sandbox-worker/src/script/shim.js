// The atlas.* API of one script run (spec 9.2; plan M8 PD-131, PD-136, PD-152). Source text,
// never bytecode. Evaluated by script::shim as a function expression after the Date prelude and
// before the agent's source, and called once with the Rust natives and the init data:
// - natives.call(id, opId, paramsJson, instance, all) writes a host.call frame (synchronously);
// - natives.log(line) writes a host.log frame (synchronously);
// - natives.ok(json) / natives.err(class, message, stack) record how main settled.
// It returns { start, deliver, fulfilled, fail }, or { refused } when the init data names an op id
// it cannot place under atlas. Every intrinsic it relies on is captured here,
// before any agent code runs; the natives and the dispatcher are closure captures, never globals.
//
// Rule for everything that runs once main has started: agent code can rewrite every intrinsic
// prototype, so the shim only calls captured functions, reads own properties of objects it made
// or parsed, keeps its state in closures and null-prototype objects, and builds property
// descriptors on null-prototype objects. Agent code it runs on purpose (toJSON, a then getter, a
// thrown value's fields) sits inside try/catch or a promise job.
(function (natives, configJson) {
  'use strict';
  var freeze = Object.freeze;
  var isFrozen = Object.isFrozen;
  var create = Object.create;
  var defineProperty = Object.defineProperty;
  var getOwnPropertyNames = Object.getOwnPropertyNames;
  var getOwnPropertySymbols = Object.getOwnPropertySymbols;
  var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  var keysOf = Object.keys;
  var isArray = Array.isArray;
  var uncurry = Function.prototype.bind.bind(Function.prototype.call);
  var hasOwn = uncurry(Object.prototype.hasOwnProperty);
  var push = uncurry(Array.prototype.push);
  var pop = uncurry(Array.prototype.pop);
  var join = uncurry(Array.prototype.join);
  var split = uncurry(String.prototype.split);
  var slice = uncurry(String.prototype.slice);
  var wellFormed = uncurry(String.prototype.toWellFormed);
  var mapGet = uncurry(Map.prototype.get);
  var mapSet = uncurry(Map.prototype.set);
  var mapDelete = uncurry(Map.prototype.delete);
  var jsonParse = JSON.parse;
  var jsonStringify = JSON.stringify;
  var PromiseCtor = Promise;
  var MapCtor = Map;
  var StringCtor = String;
  var ErrorCtor = Error;
  var TypeErrorCtor = TypeError;
  var RangeErrorCtor = RangeError;

  var nativeCall = natives.call;
  var nativeLog = natives.log;
  var settleOk = natives.ok;
  var settleErr = natives.err;

  var config = jsonParse(configJson);
  var maxConcurrent = config.max_concurrent_calls;
  var maxResultUnits = config.max_result_units;
  // The script.error frame cap in bytes, as a UTF-16 unit bound for each field of a thrown value.
  var maxErrorUnits = config.max_error_units;
  // The worker -> host frame cap in bytes, used as a UTF-16 unit bound (a text never has fewer
  // UTF-8 bytes than UTF-16 units): a call whose params, op id and instance are longer together is
  // refused and a longer log line is cut here, before the text is copied to Rust outside the heap
  // limit.
  var maxFrameUnits = config.max_frame_units;
  var callTooLarge = config.call_too_large;

  // A writable, enumerable, configurable data descriptor that inherits nothing.
  function dataDescriptor(value) {
    var d = create(null);
    d.value = value;
    d.writable = true;
    d.enumerable = true;
    d.configurable = true;
    return d;
  }

  // A host rejection inside the script (spec 9.2): catchable, with the host's class and details.
  // The fields are defined, not assigned (no setter up the prototype chain runs), and the class
  // is frozen so its heritage cannot be swapped. Its prototype stays open: freezing it would make
  // `err.name = ...` on an instance fail (the override mistake), and construction never reads it.
  class AtlasError extends ErrorCtor {
    constructor(cls, details) {
      super('host call rejected: ' + cls);
      defineProperty(this, 'class', dataDescriptor(cls));
      defineProperty(this, 'details', dataDescriptor(details));
    }
  }
  defineProperty(AtlasError.prototype, 'name', {
    value: 'AtlasError', writable: true, enumerable: false, configurable: true
  });
  freeze(AtlasError);

  // Freezes `root` and everything reachable through its own data properties.
  function deepFreeze(root) {
    var stack = [root];
    while (stack.length > 0) {
      var o = pop(stack);
      if (o === null || (typeof o !== 'object' && typeof o !== 'function') || isFrozen(o)) {
        continue;
      }
      freeze(o);
      var keys = getOwnPropertyNames(o);
      var symbols = getOwnPropertySymbols(o);
      for (var s = 0; s < symbols.length; s++) {
        push(keys, symbols[s]);
      }
      for (var k = 0; k < keys.length; k++) {
        var d = getOwnPropertyDescriptor(o, keys[k]);
        if (d !== undefined && hasOwn(d, 'value')) {
          push(stack, d.value);
        }
      }
    }
    return root;
  }

  // Host calls: ids from 1, at most max_concurrent_calls outstanding, the rest queued locally and
  // sent in call order as earlier ones settle (spec 9.2, 3.4). The queue is a null-prototype
  // object with head and tail counters: no index accessor on Array.prototype or Object.prototype
  // can swallow or forge a queued call. Ids leave strictly increasing (deliver pumps the queue
  // before it settles anything), which the native checks.
  var nextId = 1;
  var outstanding = 0;
  var queue = create(null);
  var qHead = 0;
  var qTail = 0;
  var pending = new MapCtor();

  function send(c) {
    outstanding++;
    mapSet(pending, c.id, c);
    try {
      nativeCall(c.id, c.opId, c.text, c.instance, c.all);
    } catch (e) {
      mapDelete(pending, c.id);
      outstanding--;
      c.reject(e);
    }
  }

  function pump() {
    while (outstanding < maxConcurrent && qHead < qTail) {
      var c = queue[qHead];
      delete queue[qHead];
      qHead++;
      send(c);
    }
  }

  function request(opId, params, opts, all) {
    return new PromiseCtor(function (resolve, reject) {
      if (typeof opId !== 'string') {
        throw new TypeErrorCtor('the op id must be a string');
      }
      var instance = null;
      if (opts !== undefined && opts !== null) {
        if (typeof opts !== 'object') {
          throw new TypeErrorCtor('the options must be an object');
        }
        var inst = opts.instance;
        if (inst !== undefined && inst !== null) {
          if (typeof inst !== 'string') {
            throw new TypeErrorCtor('options.instance must be a string');
          }
          instance = inst;
        }
      }
      var text = jsonStringify(params === undefined ? {} : params);
      if (typeof text !== 'string') {
        throw new TypeErrorCtor('the params are not JSON-serializable');
      }
      // The op id and the instance go into the frame too, and every string is copied to Rust.
      if (text.length + opId.length + (instance === null ? 0 : instance.length) > maxFrameUnits) {
        throw new RangeErrorCtor(callTooLarge);
      }
      var c = {
        id: nextId++,
        opId: wellFormed(opId),
        text: wellFormed(text),
        instance: instance === null ? null : wellFormed(instance),
        all: all,
        resolve: resolve,
        reject: reject
      };
      // While the queue holds calls, `outstanding` is at the cap (pump fills up to it), so a new
      // call never overtakes a queued one.
      if (outstanding < maxConcurrent) {
        send(c);
      } else {
        queue[qTail++] = c;
      }
    });
  }

  // One host frame `{"jsonrpc":"2.0","id":n,"result":{"ok":v}|{"rejected":{class,details}}}`,
  // parsed once here. 0 = settled; 1 = not JSON; 2 = wrong shape; 3 = no outstanding call with
  // that id. Nothing changes unless the answer is 0, and once the state has changed it returns 0
  // whatever the agent code it triggers does (a then getter on the value, Error hooks).
  function deliver(text) {
    var msg;
    try {
      msg = jsonParse(text);
    } catch (e) {
      return 1;
    }
    if (msg === null || typeof msg !== 'object' || isArray(msg) || keysOf(msg).length !== 3 ||
        !hasOwn(msg, 'jsonrpc') || msg.jsonrpc !== '2.0' || !hasOwn(msg, 'id') ||
        !hasOwn(msg, 'result')) {
      return 2;
    }
    var r = msg.result;
    if (r === null || typeof r !== 'object' || isArray(r) || keysOf(r).length !== 1) {
      return 2;
    }
    var rejected = null;
    if (hasOwn(r, 'rejected')) {
      rejected = r.rejected;
      if (rejected === null || typeof rejected !== 'object' || isArray(rejected) ||
          keysOf(rejected).length !== 2 || !hasOwn(rejected, 'class') ||
          typeof rejected.class !== 'string' || !hasOwn(rejected, 'details')) {
        return 2;
      }
    } else if (!hasOwn(r, 'ok')) {
      return 2;
    }
    var c = typeof msg.id === 'number' ? mapGet(pending, msg.id) : undefined;
    if (c === undefined) {
      return 3;
    }
    mapDelete(pending, msg.id);
    outstanding--;
    // Queued calls go out before the settlement can run agent code that makes new calls.
    try {
      pump();
    } catch (x) {
      // Unreachable short of a halt: send catches what the native throws.
    }
    try {
      if (rejected === null) {
        c.resolve(r.ok);
      } else {
        var err;
        try {
          err = new AtlasError(rejected.class, rejected.details);
        } catch (x) {
          err = x;
        }
        c.reject(err);
      }
    } catch (x) {
      // Resolve functions do not throw; a halt is reported by Rust.
    }
    return 0;
  }

  // The script's `atlas` (spec 9.2, PD-152): atlas.<product>.<...> from read_op_ids, call, all,
  // ops, instances, log; deep-frozen.
  var RESERVED = ['all', 'call', 'instances', 'log', 'ops'];
  function isReserved(name) {
    for (var i = 0; i < RESERVED.length; i++) {
      if (RESERVED[i] === name) {
        return true;
      }
    }
    return false;
  }

  function opFunction(opId) {
    var f = (params, opts) => request(opId, params, opts, false);
    defineProperty(f, 'name', { value: opId });
    return f;
  }

  function materialize(node) {
    var obj = node.op !== null ? opFunction(node.op) : {};
    for (var key in node.kids) {
      defineProperty(obj, key, {
        value: materialize(node.kids[key]), writable: true, enumerable: true, configurable: true
      });
    }
    return obj;
  }

  // The init data names an op id the shim cannot place: the host's fault, not the engine's. The
  // shim then returns { refused: message } instead of its API (the worker exits EXIT_PROTOCOL);
  // any other failure while it installs is an engine fault.
  function InitRefused(message) {
    this.message = message;
  }

  function buildAtlas(opIds, instances) {
    var root = { kids: create(null), op: null };
    for (var i = 0; i < opIds.length; i++) {
      var id = opIds[i];
      var parts = split(id, '.');
      if (parts.length < 2 || isReserved(parts[0])) {
        throw new InitRefused('op id cannot be placed under atlas: ' + id);
      }
      var node = root;
      for (var j = 0; j < parts.length; j++) {
        var part = parts[j];
        if (part === '') {
          throw new InitRefused('op id with an empty segment: ' + id);
        }
        var next = node.kids[part];
        if (next === undefined) {
          next = { kids: create(null), op: null };
          node.kids[part] = next;
        }
        node = next;
      }
      if (node.op !== null) {
        throw new InitRefused('duplicate op id: ' + id);
      }
      node.op = id;
    }
    var atlas = materialize(root);
    var ops = deepFreeze(opIds);
    var list = deepFreeze(instances);
    var members = {
      call: function call(opId, params, opts) { return request(opId, params, opts, false); },
      all: function all(opId, params, opts) { return request(opId, params, opts, true); },
      ops: function ops_() { return ops; },
      instances: function instances_() { return list; },
      log: function log() {
        var parts = [];
        for (var i = 0; i < arguments.length; i++) {
          push(parts, StringCtor(arguments[i]));
        }
        var line = join(parts, ' ');
        if (line.length > maxFrameUnits) {
          // Cut before wellFormed: the cut may split a surrogate pair.
          line = slice(line, 0, maxFrameUnits);
        }
        nativeLog(wellFormed(line));
      }
    };
    defineProperty(members.ops, 'name', { value: 'ops' });
    defineProperty(members.instances, 'name', { value: 'instances' });
    for (var m = 0; m < RESERVED.length; m++) {
      defineProperty(atlas, RESERVED[m], {
        value: members[RESERVED[m]], writable: true, enumerable: true, configurable: true
      });
    }
    return deepFreeze(atlas);
  }

  // No agent code has run yet: `instanceof` and the error's fields are the shim's own.
  var atlas;
  try {
    atlas = buildAtlas(config.read_op_ids, config.instances);
  } catch (e) {
    if (e instanceof InitRefused) {
      return { refused: e.message };
    }
    throw e;
  }
  var args = deepFreeze(config.args);

  // A field of a thrown value, cut to the error frame cap before it is copied out of QuickJS (the
  // copy would otherwise count against heap_mb, and its Rust copy against process_mb); the run
  // loop cuts it to the exact byte cap and adds the marker. Cut before wellFormed: the cut may
  // split a surrogate pair.
  function errorField(s) {
    return wellFormed(s.length > maxErrorUnits ? slice(s, 0, maxErrorUnits) : s);
  }

  // The rejection of main, as untrusted payload: class, message, stack (spec 9.5).
  function describe(e) {
    var cls = 'Error';
    var message = '';
    var stack = '';
    try {
      if (e !== null && (typeof e === 'object' || typeof e === 'function')) {
        var name = e.name;
        if (typeof name === 'string') {
          cls = name;
        }
        var m = e.message;
        message = typeof m === 'string' ? m : StringCtor(e);
        var s = e.stack;
        if (typeof s === 'string') {
          stack = s;
        }
      } else {
        message = StringCtor(e);
      }
    } catch (x) {
      message = 'the thrown value could not be described';
    }
    return [errorField(cls), errorField(message), errorField(stack)];
  }

  function fail(e) {
    var d = describe(e);
    settleErr(d[0], d[1], d[2]);
  }

  // The result is JSON text (undefined -> null); a value JSON cannot encode is a TypeError, and a
  // text with more UTF-16 units than the terminal frame allows bytes is ResultTooLarge (PD-136;
  // Rust checks the exact UTF-8 length of the rest).
  function fulfilled(v) {
    var text;
    try {
      text = jsonStringify(v === undefined ? null : v);
    } catch (e) {
      fail(e);
      return;
    }
    if (typeof text !== 'string') {
      settleErr('TypeError', 'the result is not JSON-serializable', '');
    } else if (text.length > maxResultUnits) {
      settleErr('ResultTooLarge', 'the result is above max_result_mb', '');
    } else {
      settleOk(wellFormed(text));
    }
  }

  // Observes main's promise with `await`, which (unlike Promise.prototype.then) never looks up a
  // species constructor. QuickJS-NG reads the promise's `constructor` at the await and, when that
  // read throws, rejects this observer's own promise instead of throwing at the await; Rust then
  // reads main's promise state itself and calls `fulfilled` or `fail` (Engine::drain_jobs).
  async function observe(p) {
    var v;
    try {
      v = await p;
    } catch (e) {
      fail(e);
      return;
    }
    fulfilled(v);
  }

  return {
    // Calls main and returns its promise (undefined if the call threw, which is then settled).
    start: function (main) {
      var p;
      try {
        p = main(args, atlas);
      } catch (e) {
        fail(e);
        return undefined;
      }
      observe(p);
      return p;
    },
    deliver: deliver,
    fulfilled: fulfilled,
    fail: fail
  };
})
