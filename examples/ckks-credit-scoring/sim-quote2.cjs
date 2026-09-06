const { createPublicClient, http } = require('viem');
const j = require(process.env.HOME + '/Documents/zk/interfold/packages/interfold-contracts/artifacts/contracts/Interfold.sol/Interfold.json');
const INTERFOLD = '0x8198f5d8F8CfFE8f9C413d98a0A55aEB8ab9FbB7';
const PROGRAM = '0xD8a5a9b31c3C0232E196d518E89Fd8bF83AcAd43';
(async () => {
  const c = createPublicClient({ transport: http('http://127.0.0.1:8545') });
  const b = await c.getBlock();
  const start = Number(b.timestamp) + 90;
  const p = { committeeSize: 0, inputWindow: [BigInt(start), BigInt(start + 300)], e3Program: PROGRAM,
    paramSet: Number(process.env.PS ?? 4), computeProviderParams: '0x', customParams: '0x',
    expectedFeeToken: process.env.FT ?? '0x0000000000000000000000000000000000000000',
    expectedCryptoConfigId: '0x' + '0'.repeat(64), maxFee: 0n };
  try {
    const fee = await c.readContract({ address: INTERFOLD, abi: j.abi, functionName: 'getE3Quote', args: [p] });
    console.log('PS=' + p.paramSet, 'quote OK fee =', String(fee));
  } catch (e) {
    console.log('PS=' + p.paramSet, 'FAILED:', e.cause?.data?.errorName ?? e.cause?.reason ?? e.shortMessage);
    if (e.cause?.data?.args) console.log('   args:', e.cause.data.args.map(String).join(', '));
  }
})();
