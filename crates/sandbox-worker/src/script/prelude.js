// Local time is UTC on every OS (spec 9.2; plan M8 PD-151, R4). Source text, never bytecode.
// Evaluated by script::shim as a function expression and called once per run, before the shim
// and the agent's source. QuickJS-NG on Windows reads the system time zone and ignores TZ (M1
// V03), so instead of relying on TZ=UTC0 the local-time surface of Date is mapped to UTC here:
// - the local getters and setters, getYear/setYear, getTimezoneOffset;
// - the component constructor new Date(y, m, ...);
// - Date.parse(s) and new Date(s): an ISO date-time without an offset gets "Z"; any other form
//   is parsed with a leading "GMT " zone, which an explicit zone later in the string overrides
//   (QuickJS's non-ISO parser keeps the last zone it reads);
// - toString, toDateString, toTimeString and toLocale*String, in QuickJS's own formats;
// - Date() called as a function.
// Date.prototype is patched in place and the constructor is wrapped, with
// Date.prototype.constructor pointing at the wrapper and wrapper.prototype === Date.prototype.
(function () {
  'use strict';
  var OrigDate = Date;
  var proto = OrigDate.prototype;
  var defineProperty = Object.defineProperty;
  var setPrototypeOf = Object.setPrototypeOf;
  var uncurry = Function.prototype.bind.bind(Function.prototype.call);
  var apply = uncurry(Function.prototype.apply);
  var regexpTest = uncurry(RegExp.prototype.test);
  var trunc = Math.trunc;
  var StringCtor = String;
  var TypeErrorCtor = TypeError;
  var origParse = OrigDate.parse;
  var origUTC = OrigDate.UTC;
  var origNow = OrigDate.now;
  var toPrimitiveKey = Symbol.toPrimitive;

  var getTime = uncurry(proto.getTime);
  var setTime = uncurry(proto.setTime);
  var getUTCFullYear = uncurry(proto.getUTCFullYear);
  var getUTCMonth = uncurry(proto.getUTCMonth);
  var getUTCDate = uncurry(proto.getUTCDate);
  var getUTCDay = uncurry(proto.getUTCDay);
  var getUTCHours = uncurry(proto.getUTCHours);
  var getUTCMinutes = uncurry(proto.getUTCMinutes);
  var getUTCSeconds = uncurry(proto.getUTCSeconds);
  var setUTCFullYear = uncurry(proto.setUTCFullYear);

  function isObject(v) {
    return v !== null && (typeof v === 'object' || typeof v === 'function');
  }

  // Installs `fn` as Date.prototype[name] with the attributes of a built-in method.
  function method(name, length, fn) {
    defineProperty(fn, 'name', { value: name });
    defineProperty(fn, 'length', { value: length });
    defineProperty(proto, name, { value: fn, writable: true, enumerable: false, configurable: true });
  }

  var units = ['FullYear', 'Month', 'Date', 'Day', 'Hours', 'Minutes', 'Seconds', 'Milliseconds'];
  for (var i = 0; i < units.length; i++) {
    (function (unit) {
      var utcGet = proto['getUTC' + unit];
      method('get' + unit, 0, function () { return apply(utcGet, this, arguments); });
      if (unit !== 'Day') {
        var utcSet = proto['setUTC' + unit];
        method('set' + unit, utcSet.length, function () { return apply(utcSet, this, arguments); });
      }
    })(units[i]);
  }

  method('getTimezoneOffset', 0, function () {
    var t = getTime(this);
    return t !== t ? NaN : 0;
  });

  // Annex B getYear/setYear over UTC fields.
  method('getYear', 0, function () {
    var t = getTime(this);
    return t !== t ? NaN : getUTCFullYear(this) - 1900;
  });
  method('setYear', 1, function (year) {
    var t = getTime(this);
    var y = +year;
    if (y !== y) {
      return setTime(this, NaN);
    }
    var yi = trunc(y);
    var full = yi >= 0 && yi <= 99 ? 1900 + yi : y;
    if (t !== t) {
      setTime(this, 0);
    }
    return setUTCFullYear(this, full);
  });

  // Renderings in QuickJS's formats (get_date_string fmt 1 and fmt 3) with the zone at +0000.
  var DAYS = 'SunMonTueWedThuFriSat';
  var MONTHS = 'JanFebMarAprMayJunJulAugSepOctNovDec';
  function pad(n, width) {
    var s = '' + n;
    while (s.length < width) {
      s = '0' + s;
    }
    return s;
  }
  function yearText(y) {
    return y < 0 ? '-' + pad(-y, 4) : pad(y, 4);
  }
  function datePart(d) {
    var wd = getUTCDay(d) * 3;
    var mon = getUTCMonth(d) * 3;
    return DAYS.slice(wd, wd + 3) + ' ' + MONTHS.slice(mon, mon + 3) + ' ' +
      pad(getUTCDate(d), 2) + ' ' + yearText(getUTCFullYear(d));
  }
  function clock(h, d) {
    return pad(h, 2) + ':' + pad(getUTCMinutes(d), 2) + ':' + pad(getUTCSeconds(d), 2);
  }
  function timePart(d) {
    return clock(getUTCHours(d), d) + ' GMT+0000';
  }
  function localeDatePart(d) {
    return pad(getUTCMonth(d) + 1, 2) + '/' + pad(getUTCDate(d), 2) + '/' + yearText(getUTCFullYear(d));
  }
  function localeTimePart(d) {
    var h = getUTCHours(d);
    return clock((h + 11) % 12 + 1, d) + ' ' + (h < 12 ? 'A' : 'P') + 'M';
  }
  function render(name, body) {
    method(name, 0, function () {
      var t = getTime(this);
      return t !== t ? 'Invalid Date' : body(this);
    });
  }
  function toStringUTC(d) {
    return datePart(d) + ' ' + timePart(d);
  }
  render('toString', toStringUTC);
  render('toDateString', datePart);
  render('toTimeString', timePart);
  render('toLocaleString', function (d) { return localeDatePart(d) + ', ' + localeTimePart(d); });
  render('toLocaleDateString', localeDatePart);
  render('toLocaleTimeString', localeTimePart);

  // Strings: an ISO date-time without an offset (the ECMAScript format reads it as local time) is
  // read as UTC; other ISO forms are left to the ISO parser; everything else defaults to GMT.
  var ISO_LOCAL = /^(?:[+-]\d{6}|\d{4})(?:-\d{2}(?:-\d{2})?)?T\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?$/;
  var ISO_OTHER = /^(?:[+-]\d{6}|\d{4})(?:-\d{2}(?:-\d{2})?)?(?:$|[T+Z-])/;
  function parseUTC(s) {
    if (regexpTest(ISO_LOCAL, s)) {
      return origParse(s + 'Z');
    }
    if (regexpTest(ISO_OTHER, s)) {
      return origParse(s);
    }
    return origParse('GMT ' + s);
  }
  function toText(v) {
    if (typeof v === 'symbol') {
      throw new TypeErrorCtor('cannot convert a Symbol to a string');
    }
    return StringCtor(v);
  }
  var parse = function parse(string) {
    return parseUTC(toText(string));
  };

  // ECMAScript ToPrimitive(value) without a hint, as the one-argument constructor uses it.
  function toPrimitive(v) {
    if (!isObject(v)) {
      return v;
    }
    var exotic = v[toPrimitiveKey];
    if (exotic !== undefined && exotic !== null) {
      if (typeof exotic !== 'function') {
        throw new TypeErrorCtor('Symbol.toPrimitive is not a function');
      }
      var r = apply(exotic, v, ['default']);
      if (isObject(r)) {
        throw new TypeErrorCtor('cannot convert object to primitive value');
      }
      return r;
    }
    var names = ['valueOf', 'toString'];
    for (var j = 0; j < names.length; j++) {
      var f = v[names[j]];
      if (typeof f === 'function') {
        var p = apply(f, v, []);
        if (!isObject(p)) {
          return p;
        }
      }
    }
    throw new TypeErrorCtor('cannot convert object to primitive value');
  }

  function isDate(v) {
    try {
      getTime(v);
      return true;
    } catch (e) {
      return false;
    }
  }

  var D = function Date(year, month, date, hours, minutes, seconds, ms) {
    if (new.target === undefined) {
      return toStringUTC(new OrigDate(origNow()));
    }
    var n = arguments.length;
    var t;
    if (n === 0) {
      t = origNow();
    } else if (n === 1) {
      if (isDate(year)) {
        t = getTime(year);
      } else {
        var prim = toPrimitive(year);
        t = typeof prim === 'string' ? parseUTC(prim) : +prim;
      }
    } else {
      t = apply(origUTC, undefined, arguments);
    }
    var d = new OrigDate(t);
    if (new.target !== D) {
      var target = new.target.prototype;
      if (isObject(target)) {
        setPrototypeOf(d, target);
      }
    }
    return d;
  };

  defineProperty(D, 'prototype', { value: proto, writable: false, enumerable: false, configurable: false });
  defineProperty(proto, 'constructor', { value: D, writable: true, enumerable: false, configurable: true });
  defineProperty(D, 'UTC', { value: origUTC, writable: true, enumerable: false, configurable: true });
  defineProperty(D, 'now', { value: origNow, writable: true, enumerable: false, configurable: true });
  defineProperty(D, 'parse', { value: parse, writable: true, enumerable: false, configurable: true });
  defineProperty(globalThis, 'Date', { value: D, writable: true, enumerable: false, configurable: true });
})
