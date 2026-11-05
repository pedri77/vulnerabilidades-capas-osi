(function () {
  "use strict";
  var form = document.getElementById("filtros");
  var entradas = Array.prototype.slice.call(document.querySelectorAll("#lista .entrada"));
  var estado = document.getElementById("estado");
  var vacio = document.getElementById("vacio");
  var campos = ["area", "decada", "causa", "naturaleza", "ident"];
  form.hidden = false;

  function valores() {
    var v = {};
    campos.forEach(function (c) { v[c] = form.elements[c].value; });
    v.q = form.elements.q.value.trim().toLowerCase();
    return v;
  }

  function cumple(el, v) {
    var ok = campos.every(function (c) {
      return !v[c] || el.dataset[c].split(" ").indexOf(v[c]) !== -1;
    });
    return ok && (!v.q || el.dataset.busca.indexOf(v.q) !== -1);
  }

  function aplicar(guardar) {
    var v = valores();
    var n = 0;
    entradas.forEach(function (el) {
      var ok = cumple(el, v);
      el.hidden = !ok;
      if (ok) { n += 1; }
    });
    estado.textContent = n + " de " + entradas.length + " entradas";
    vacio.hidden = n !== 0;
    if (guardar) {
      var p = new URLSearchParams();
      Object.keys(v).forEach(function (k) { if (v[k]) { p.set(k, v[k]); } });
      var s = p.toString();
      history.replaceState(null, "", location.pathname + (s ? "?" + s : "") + location.hash);
    }
  }

  function desdeUrl() {
    var p = new URLSearchParams(location.search);
    campos.concat("q").forEach(function (c) {
      var campo = form.elements[c];
      var valor = p.get(c) || "";
      if (c === "q" || Array.prototype.some.call(campo.options, function (o) { return o.value === valor; })) {
        campo.value = valor;
      }
    });
  }

  function limpiar() {
    form.reset();
    aplicar(true);
  }

  function abrirHash() {
    var id = location.hash.slice(1);
    var el = /^OSI-\d{3}$/.test(id) ? document.getElementById(id) : null;
    if (!el) { return; }
    if (el.hidden) { limpiar(); }
    el.open = true;
    el.scrollIntoView();
  }

  form.addEventListener("input", function () { aplicar(true); });
  form.addEventListener("submit", function (ev) { ev.preventDefault(); });
  document.getElementById("limpiar").addEventListener("click", limpiar);
  document.getElementById("limpiar2").addEventListener("click", limpiar);
  document.querySelectorAll(".celda").forEach(function (a) {
    a.addEventListener("click", function (ev) {
      ev.preventDefault();
      form.reset();
      form.elements.area.value = a.dataset.area;
      form.elements.decada.value = a.dataset.decada;
      aplicar(true);
      document.getElementById("tabla").scrollIntoView();
    });
  });
  window.addEventListener("hashchange", abrirHash);
  desdeUrl();
  aplicar(false);
  abrirHash();
})();
