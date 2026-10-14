#!/usr/bin/env node
/*
 * sast-scan.js — AST-based taint scanner for frontend credential exfiltration.
 * DEFENSIVE / read-only. Parses JS (and inline <script> in HTML), tracks data
 * flow from SOURCES (reading secrets) to SINKS (sending data out), and reports
 * source->sink flows plus sinks that target non-first-party hosts.
 *
 * Usage: node sast-scan.js <dir> [--allow host1,host2]
 *
 * This reasons about the AST; it never executes the analyzed code.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');

const argv = process.argv.slice(2);
const root = argv.find((a) => !a.startsWith('--')) || '.';
const allowIdx = argv.indexOf('--allow');
const ALLOW = allowIdx >= 0 && argv[allowIdx + 1] ? argv[allowIdx + 1].split(',') : [];

/* ---- helpers ---------------------------------------------------------- */

// Does a member expression read a known secret source? e.g. document.cookie,
// localStorage.getItem(...), sessionStorage.getItem(...), <el>.value
function isSourceNode(node) {
  if (!node) return null;
  if (node.type === 'MemberExpression') {
    const prop = node.property && (node.property.name || node.property.value);
    const obj = node.object;
    if (prop === 'cookie' && obj.type === 'Identifier' && obj.name === 'document')
      return 'document.cookie';
    if (prop === 'value') return 'form field .value';
  }
  if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
    const o = node.callee.object && node.callee.object.name;
    const m = node.callee.property && node.callee.property.name;
    if ((o === 'localStorage' || o === 'sessionStorage') && m === 'getItem')
      return `${o}.getItem`;
  }
  if (node.type === 'NewExpression' && node.callee.name === 'FormData')
    return 'FormData(form)';
  return null;
}

// Collect identifier names referenced anywhere inside an expression subtree.
function idsIn(node, out = new Set()) {
  if (!node || typeof node !== 'object') return out;
  if (node.type === 'Identifier') out.add(node.name);
  for (const k of Object.keys(node)) {
    const v = node[k];
    if (Array.isArray(v)) v.forEach((c) => idsIn(c, out));
    else if (v && typeof v.type === 'string') idsIn(v, out);
  }
  return out;
}

// Does an expression subtree contain a source read, or reference a tainted var?
function exprIsTainted(node, tainted) {
  let hit = null;
  walk.full(node, (n) => {
    if (!hit) {
      const s = isSourceNode(n);
      if (s) hit = s;
      else if (n.type === 'Identifier' && tainted.has(n.name)) hit = `var "${n.name}"`;
    }
  });
  return hit;
}

// Extract a string-literal URL from the first arg of a sink call, if present.
function urlLiteral(args) {
  if (args && args[0] && args[0].type === 'Literal' && typeof args[0].value === 'string')
    return args[0].value;
  return null;
}

function hostOf(url) {
  try {
    if (/^[a-z]+:\/\//i.test(url) || url.startsWith('//')) return new URL(url, 'https://x').host;
    return null; // relative URL -> same-origin
  } catch {
    return null;
  }
}

function lineOf(src, pos) {
  return src.slice(0, pos).split('\n').length;
}

/* ---- core scan of one source string ----------------------------------- */

function scanSource(code, label, findings) {
  let ast;
  try {
    ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module', locations: false });
  } catch {
    try {
      ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'script', locations: false });
    } catch (e) {
      findings.push({ sev: 'INFO', file: label, line: 0, msg: `parse skipped (${e.message})` });
      return;
    }
  }

  // Pass 1 (fixpoint): propagate taint across simple var assignments.
  const tainted = new Set();
  for (let i = 0; i < 3; i++) {
    const before = tainted.size;
    walk.full(ast, (n) => {
      if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && n.init) {
        if (exprIsTainted(n.init, tainted)) tainted.add(n.id.name);
      }
      if (n.type === 'AssignmentExpression' && n.left.type === 'Identifier' && n.right) {
        if (exprIsTainted(n.right, tainted)) tainted.add(n.left.name);
      }
    });
    if (tainted.size === before) break;
  }

  // Pass 2: find sinks and check taint + destination host.
  walk.full(ast, (n) => {
    let sink = null;
    let args = null;

    if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression') {
      const o = n.callee.object && n.callee.object.name;
      const m = n.callee.property && n.callee.property.name;
      if (o === 'navigator' && m === 'sendBeacon') { sink = 'navigator.sendBeacon'; args = n.arguments; }
      else if (m === 'send') { sink = 'XHR/WebSocket .send'; args = n.arguments; }
    }
    if (n.type === 'CallExpression' && n.callee.type === 'Identifier' && n.callee.name === 'fetch') {
      sink = 'fetch'; args = n.arguments;
    }
    if (n.type === 'NewExpression' && n.callee.name === 'WebSocket') { sink = 'new WebSocket'; args = n.arguments; }
    // pixel beacon: assignment to .src
    if (n.type === 'AssignmentExpression' && n.left.type === 'MemberExpression' &&
        (n.left.property.name === 'src') && exprIsTainted(n.right, tainted)) {
      findings.push({ sev: 'HIGH', file: label, line: lineOf(code, n.start),
        msg: `tainted data assigned to .src (pixel-beacon exfiltration): ${exprIsTainted(n.right, tainted)}` });
    }

    if (!sink) return;

    // Does tainted data reach this sink's arguments?
    let taintHit = null;
    for (const a of args || []) {
      taintHit = exprIsTainted(a, tainted);
      if (taintHit) break;
    }
    const url = urlLiteral(args);
    const host = url ? hostOf(url) : null;
    const external = host && !ALLOW.includes(host);

    if (taintHit && external)
      findings.push({ sev: 'HIGH', file: label, line: lineOf(code, n.start),
        msg: `${sink}() sends tainted data (${taintHit}) to EXTERNAL host "${host}"` });
    else if (taintHit)
      findings.push({ sev: 'MED', file: label, line: lineOf(code, n.start),
        msg: `${sink}() carries tainted data (${taintHit}); confirm destination is first-party` });
    else if (external)
      findings.push({ sev: 'LOW', file: label, line: lineOf(code, n.start),
        msg: `${sink}() targets external host "${host}"; no secret flow detected here` });
  });
}

/* ---- file walking ------------------------------------------------------ */

function extractScripts(html) {
  const out = [];
  const re = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html))) if (m[1].trim()) out.push(m[1]);
  return out;
}

function listFiles(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...listFiles(p));
    else if (/\.(js|mjs|jsx|html)$/i.test(e.name)) out.push(p);
  }
  return out;
}

const findings = [];
const rootStat = fs.statSync(root);
const target = rootStat.isDirectory() ? root : path.basename(root);
const files = rootStat.isDirectory() ? listFiles(root) : [root];
for (const f of files) {
  const code = fs.readFileSync(f, 'utf8');
  if (f.endsWith('.html')) extractScripts(code).forEach((s, i) => scanSource(s, `${f}#script${i + 1}`, findings));
  else scanSource(code, f, findings);
}

const order = { HIGH: 0, MED: 1, LOW: 2, INFO: 3 };
findings.sort((a, b) => order[a.sev] - order[b.sev]);
console.log(`== taint scan: ${target} ${ALLOW.length ? `(allow: ${ALLOW.join(', ')})` : '(no allowlist)'} ==\n`);
if (!findings.length) console.log('no source->sink flows detected.');
for (const f of findings) console.log(`[${f.sev}] ${f.file}:${f.line}\n       ${f.msg}\n`);
const high = findings.filter((f) => f.sev === 'HIGH').length;
console.log(`== ${findings.length} finding(s), ${high} HIGH ==`);
process.exit(high ? 1 : 0);
