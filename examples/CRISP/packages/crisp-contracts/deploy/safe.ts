// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The canonical Safe 1.3.0 and 1.4.1 proxy code hashes and singletons, the same on every chain (read
// from mainnet and Sepolia). `CRISPProgram` treats a slot as a Safe only when both match.
export const SAFE_PROXY_CODEHASHES = [
  '0xb89c1b3bdf2cf8827818646bce9a8f6e372885f8c55e5c07acbd307cb133b000', // GnosisSafeProxy 1.3.0 (canonical and EIP-155 factories)
  '0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c', // SafeProxy 1.4.1
]
export const SAFE_SINGLETONS = [
  '0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552', // GnosisSafe 1.3.0
  '0x3E5c63644E683549055b9Be8653de26E0B4CD36E', // GnosisSafeL2 1.3.0
  '0x69f4D1788e39c87893C980c06EdF4b7f686e2938', // GnosisSafe 1.3.0 (EIP-155)
  '0xfb1bffC9d739B8D520DaF37dF666da4C687191EA', // GnosisSafeL2 1.3.0 (EIP-155)
  '0x41675C099F32341bf84BFc5382aF534df5C7461a', // Safe 1.4.1
  '0x29fcB43b46531BcA003ddC8FCB67FFE91900C762', // SafeL2 1.4.1
]
