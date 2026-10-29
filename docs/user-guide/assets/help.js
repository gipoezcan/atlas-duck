// Atlas Duck user guide: search, language switch and anchor scroll (M16, PD-324).
// Plain substring matching over window.ATLAS_HELP_INDEX (search-index.js); no library, no network.
// Without this script the table of contents and every page still work.
(function () {
  'use strict';

  var box = document.querySelector('.search');
  var input = document.getElementById('help-search');
  var list = document.getElementById('help-results');
  var index = window.ATLAS_HELP_INDEX;
  var MAX_RESULTS = 10;

  // The language switch keeps the anchor: the same section in the other language.
  var sw = document.querySelector('.lang-switch');
  if (sw) {
    var base = sw.getAttribute('href');
    var sync = function () {
      sw.setAttribute('href', base + location.hash);
    };
    sync();
    window.addEventListener('hashchange', sync);
  }

  // A target that sits under the sticky bar, or appears after layout, is scrolled into view.
  var toTarget = function () {
    if (!location.hash) return;
    var el = document.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (el) el.scrollIntoView();
  };
  window.addEventListener('hashchange', toTarget);
  toTarget();

  if (!box || !input || !list || !Array.isArray(index)) return;
  box.hidden = false;

  var tokens = function (q) {
    return q.toLowerCase().split(/\s+/).filter(Boolean);
  };

  // Every token must occur; a hit in the heading counts more than one in the title or the text.
  var score = function (entry, words) {
    var heading = entry.heading.toLowerCase();
    var title = entry.title.toLowerCase();
    var text = entry.text.toLowerCase();
    var total = 0;
    for (var i = 0; i < words.length; i++) {
      var w = words[i];
      var s = 0;
      if (heading.indexOf(w) >= 0) s += 4;
      if (title.indexOf(w) >= 0) s += 2;
      if (text.indexOf(w) >= 0) s += 1;
      if (s === 0) return 0;
      total += s;
    }
    return total;
  };

  var el = function (tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text) node.textContent = text;
    return node;
  };

  var render = function (hits) {
    list.textContent = '';
    if (hits.length === 0) {
      list.appendChild(el('li', 'empty', input.getAttribute('data-empty') || ''));
    }
    hits.forEach(function (entry) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = entry.href;
      a.appendChild(el('strong', '', entry.heading));
      if (entry.heading !== entry.title) a.appendChild(el('small', '', entry.title));
      if (entry.text) a.appendChild(el('small', '', entry.text));
      li.appendChild(a);
      list.appendChild(li);
    });
    list.hidden = false;
  };

  var search = function () {
    var words = tokens(input.value);
    if (words.length === 0) {
      list.hidden = true;
      list.textContent = '';
      return;
    }
    var hits = [];
    index.forEach(function (entry, position) {
      var s = score(entry, words);
      if (s > 0) hits.push({ entry: entry, score: s, position: position });
    });
    hits.sort(function (a, b) {
      return b.score - a.score || a.position - b.position;
    });
    render(hits.slice(0, MAX_RESULTS).map(function (h) { return h.entry; }));
  };

  input.addEventListener('input', search);
  input.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      input.value = '';
      search();
    } else if (event.key === 'Enter') {
      var first = list.querySelector('a');
      if (first) location.href = first.href;
    } else if (event.key === 'ArrowDown') {
      var link = list.querySelector('a');
      if (link) {
        event.preventDefault();
        link.focus();
      }
    }
  });
  list.addEventListener('click', function () {
    list.hidden = true;
  });
  document.addEventListener('click', function (event) {
    if (!box.contains(event.target)) list.hidden = true;
  });
})();
