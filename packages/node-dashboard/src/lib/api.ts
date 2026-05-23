// SPDX-License-Identifier: LGPL-3.0-only

export async function api(path: string): Promise<string> {
  const r = await fetch(path)
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.text()
}
