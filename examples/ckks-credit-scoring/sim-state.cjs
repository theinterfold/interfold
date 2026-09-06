// Read the on-chain state getE3Quote depends on, to find which precondition fails.
const { createPublicClient, http, parseAbi } = require('viem');

const INTERFOLD = '0x8198f5d8F8CfFE8f9C413d98a0A55aEB8ab9FbB7';
const PROGRAM = '0xD8a5a9b31c3C0232E196d518E89Fd8bF83AcAd43';

const abi = parseAbi([
  'function paramSetRegistry(uint8) view returns (bytes)',
  'function committeeThresholds(uint8) view returns (uint32, uint32)',
  'function maxDuration() view returns (uint256)',
  'function e3Programs(address) view returns (bool)',
  'function ciphernodeRegistry() view returns (address)',
]);
const regAbi = parseAbi(['function sortitionSubmissionWindow() view returns (uint256)']);

(async () => {
  const c = createPublicClient({ transport: http('http://127.0.0.1:8545') });
  const rd = async (name, args = []) => {
    try {
      const v = await c.readContract({ address: INTERFOLD, abi, functionName: name, args });
      return Array.isArray(v) ? v.map(String).join(',') : String(v);
    } catch (e) { return 'REVERT/absent: ' + (e.shortMessage ?? e.message).slice(0, 60); }
  };
  for (const ps of [0, 2, 3, 4]) {
    const v = await rd('paramSetRegistry', [ps]);
    console.log(`paramSetRegistry[${ps}]: ${v === '0x' ? 'EMPTY ***' : v.slice(0, 40) + ' (len ' + (v.length - 2) / 2 + ')'}`);
  }
  for (const cs of [0, 1, 2]) console.log(`committeeThresholds[${cs}]: ${await rd('committeeThresholds', [cs])}`);
  console.log('maxDuration:', await rd('maxDuration'));
  console.log('e3Programs[program]:', await rd('e3Programs', [PROGRAM]));
  const reg = await rd('ciphernodeRegistry');
  console.log('ciphernodeRegistry:', reg);
  try {
    const w = await c.readContract({ address: reg, abi: regAbi, functionName: 'sortitionSubmissionWindow' });
    console.log('sortitionSubmissionWindow:', String(w));
  } catch (e) { console.log('sortitionSubmissionWindow: REVERT', (e.shortMessage ?? '').slice(0, 60)); }
})();
