// Decode getE3Quote's revert precisely: raw eth_call, then match the 4-byte
// selector against every custom error in the Interfold + pricing ABIs.
const { createPublicClient, http, parseAbi, encodeFunctionData, decodeErrorResult } = require('viem');
const { readFileSync, readdirSync } = require('fs');
const { join } = require('path');

const INTERFOLD = '0x8198f5d8F8CfFE8f9C413d98a0A55aEB8ab9FbB7';
const PROGRAM = '0xD8a5a9b31c3C0232E196d518E89Fd8bF83AcAd43';
const ART = join(process.env.HOME, 'Documents/zk/interfold/packages/interfold-contracts/artifacts');

const abi = parseAbi([
  'struct E3RequestParams { uint8 committeeSize; uint256[2] inputWindow; address e3Program; uint8 paramSet; bytes computeProviderParams; bytes customParams; }',
  'function getE3Quote(E3RequestParams requestParams) view returns (uint256)',
]);

function collectAbis(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) collectAbis(p, out);
    else if (e.name.endsWith('.json') && !e.name.endsWith('.dbg.json')) {
      try {
        const j = JSON.parse(readFileSync(p, 'utf8'));
        if (Array.isArray(j.abi)) out.push(...j.abi.filter((x) => x.type === 'error'));
      } catch {}
    }
  }
  return out;
}

(async () => {
  const c = createPublicClient({ transport: http('http://127.0.0.1:8545') });
  const block = await c.getBlock();
  const start = Number(block.timestamp) + 90;
  const data = encodeFunctionData({
    abi, functionName: 'getE3Quote',
    args: [{
      committeeSize: 0,
      inputWindow: [BigInt(start), BigInt(start + 300)],
      e3Program: PROGRAM, paramSet: 4,
      computeProviderParams: '0x', customParams: '0x',
    }],
  });
  let raw;
  try {
    const r = await c.request({ method: 'eth_call', params: [{ to: INTERFOLD, data }, 'latest'] });
    console.log('CALL OK ->', r);
    return;
  } catch (e) {
    raw = e.cause?.data ?? e.data ?? e.details ?? '';
    console.log('revert raw:', JSON.stringify(raw).slice(0, 200));
  }
  const hex = typeof raw === 'string' ? raw.match(/0x[0-9a-fA-F]+/)?.[0] : null;
  if (!hex || hex.length < 10) { console.log('no selector in revert data'); return; }
  const errs = collectAbis(ART);
  try {
    const d = decodeErrorResult({ abi: errs, data: hex });
    console.log('DECODED ERROR:', d.errorName, JSON.stringify(d.args?.map(String)));
  } catch {
    console.log('selector', hex.slice(0, 10), 'not found among', errs.length, 'known errors');
  }
})();
