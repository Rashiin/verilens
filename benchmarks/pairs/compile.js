// Compile every contrastive-pair contract with the solc version its pragma asks for.
// npm install --no-save solc08@npm:solc@0.8.26 solc07@npm:solc@0.7.6 solc04@npm:solc@0.4.26
const fs = require('fs');
const path = require('path');
const compilers = { '0.8': require('solc08'), '0.7': require('solc07'), '0.4': require('solc04') };
let failed = 0;
for (const file of process.argv.slice(2)) {
  const src = fs.readFileSync(file, 'utf8');
  const v = src.match(/pragma solidity \^?(\d+\.\d+)/)[1];
  const solc = compilers[v];
  const input = { language: 'Solidity', sources: { [path.basename(file)]: { content: src } },
    settings: { outputSelection: { '*': { '*': ['abi'] } } } };
  const raw = v === "0.4" ? solc.compileStandardWrapper(JSON.stringify(input)) : solc.compile(JSON.stringify(input)); const out = JSON.parse(raw);
  const errs = (out.errors || []).filter(e => e.severity === 'error');
  const warns = (out.errors || []).filter(e => e.severity === 'warning').length;
  if (errs.length) { failed++; console.log('FAIL', file, errs.map(e => e.formattedMessage).join('\n')); }
  else console.log('ok  ', v, path.relative(process.cwd(), file), warns ? `(${warns} warnings)` : '');
}
process.exit(failed ? 1 : 0);
