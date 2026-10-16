// The atlas.* API of one script run (spec 9.2; plan M8 PD-131, PD-136, PD-152). Source text,
// never bytecode. Evaluated by script::shim as a function expression after the Date prelude and
// before the agent's source, and called once with the Rust natives and the init data:
// - natives.call(id, opId, paramsJson, instance, all) writes a host.call frame (synchronously);
// - natives.log(line) writes a host.log frame (synchronously);
// - natives.ok(json) / natives.err(class, message, stack) record how main settled.
// It returns { start, deliver }. Every intrinsic it relies on is captured here, before any agent
// code runs; the natives and the dispatcher are closure captures, never globals.
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
  var shift = uncurry(Array.prototype.shift);
  var join = uncurry(Array.prototype.join);
  var split = uncurry(String.prototype.split);
  var wellFormed = uncurry(String.prototype.toWellFormed);
  var then = uncurry(Promise.prototype.then);
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

  var nativeCall = natives.call;
  var nativeLog = natives.log;
  var settleOk = natives.ok;
  var settleErr = natives.err;

  var config = jsonParse(configJson);
  var maxConcurrent = config.max_concurrent_calls;
  var maxResultUnits = config.max_result_units;

  // A host rejection inside the script (spec 9.2): catchable, with the host's class and details.
  class AtlasError extends ErrorCtor {
    constructor(cls, details) {
      super('host call rejected: ' + cls);
      this.class = cls;
      this.details = details;
    }
  }
  defineProperty(AtlasError.prototype, 'name', {
    value: 'AtlasError', writable: true, enumerable: false, configurable: true
  });

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
  // sent in call order as earlier ones settle (spec 9.2, 3.4).
  var nextId = 1;
  var outstanding = 0;
  var queue = [];
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
    while (outstanding < maxConcurrent && queue.length > 0) {
      send(shift(queue));
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
          instance = wellFormed(inst);
        }
      }
      var text = jsonStringify(params === undefined ? {} : params);
      if (typeof text !== 'string') {
        throw new TypeErrorCtor('the params are not JSON-serializable');
      }
      var c = {
        id: nextId++,
        opId: wellFormed(opId),
        text: wellFormed(text),
        instance: instance,
        all: all,
        resolve: resolve,
        reject: reject
      };
      if (outstanding < maxConcurrent) {
        send(c);
      } else {
        push(queue, c);
      }
    });
  }

  // One host frame `{"jsonrpc":"2.0","id":n,"result":{"ok":v}|{"rejected":{class,details}}}`,
  // parsed once here. 0 = settled; 1 = not JSON; 2 = wrong shape; 3 = no outstanding call with
  // that id. Nothing changes unless the answer is 0.
  function deliver(text) {
    var msg;
    try {
      msg = jsonParse(text);
    } catch (e) {
      return 1;
    }
    if (msg === null || typeof msg !== 'object' || isArray(msg) || keysOf(msg).length !== 3 ||
        msg.jsonrpc !== '2.0' || !hasOwn(msg, 'id') || !hasOwn(msg, 'result')) {
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
          keysOf(rejected).length !== 2 || typeof rejected.class !== 'string' ||
          !hasOwn(rejected, 'details')) {
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
    if (rejected === null) {
      c.resolve(r.ok);
    } else {
      c.reject(new AtlasError(rejected.class, rejected.details));
    }
    pump();
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

  function buildAtlas(opIds, instances) {
    var root = { kids: create(null), op: null };
    for (var i = 0; i < opIds.length; i++) {
      var id = opIds[i];
      var parts = split(id, '.');
      if (parts.length < 2 || isReserved(parts[0])) {
        throw new ErrorCtor('op id cannot be placed under atlas: ' + id);
      }
      var node = root;
      for (var j = 0; j < parts.length; j++) {
        var part = parts[j];
        if (part === '') {
          throw new ErrorCtor('op id with an empty segment: ' + id);
        }
        var next = node.kids[part];
        if (next === undefined) {
          next = { kids: create(null), op: null };
          node.kids[part] = next;
        }
        node = next;
      }
      if (node.op !== null) {
        throw new ErrorCtor('duplicate op id: ' + id);
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
        nativeLog(wellFormed(join(parts, ' ')));
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

  var atlas = buildAtlas(config.read_op_ids, config.instances);
  var args = deepFreeze(config.args);

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
    return [wellFormed(cls), wellFormed(message), wellFormed(stack)];
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

  return {
    start: function (main) {
      then(main(args, atlas), fulfilled, fail);
    },
    deliver: deliver
  };
})
