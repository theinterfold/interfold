#!/usr/bin/env bash
# r115 V1 leg: SECURE-8192 (prod field, committee=minimum) C6 (threshold/share_decryption)
# gate RE-MEASURE at the box-1 field under the I14-patched payload (raw ct0/ct1 limbs
# -> 1-field public ct_commitment; identical lever to the one shipped into C3).
# Self-restoring: config byte-restored, on-disk insecure C6 json re-restored from
# /tmp/r115_c6_insecure_pre.json. Prints the three RAN lines: V0 baseline (on-disk
# insecure), V0 secure (recorded previous leg 2,977,228), V1 secure (patched, fresh).
set -u
cd /home/dev/interfold-research/interfold

TJ=circuits/bin/threshold/target/share_decryption.json
INSEC=/tmp/r115_c6_base_secure.json   # the on-disk INSECURE raw-payload artifact (86,892 g) snapshotted pre-flip
[ -f "$INSEC" ] || { echo "FATAL: insecure pre-snapshot $INSEC missing"; exit 2; }

CFG=circuits/lib/src/configs/committee/active.nr
DEF=circuits/lib/src/configs/default/mod.nr

# insecure on-disk gate (load-bearing baseline for the diff)
b0=$(bb gates -b "$TJ" -t noir-recursive 2>/dev/null \
     | python3 -c "import sys,json; d=json.load(sys.stdin); f=d.get('functions') or [d]; print(sum(x['circuit_size'] for x in f))")
echo "INSECURE  on-disk baseline          = $b0 g"

# flip -> secure
sed -i "s/super::insecure::/super::secure::/" "$DEF"
restore() { sed -i "s/super::secure::/super::insecure::/" "$DEF"; cp "$INSEC" "$TJ"; }
trap restore EXIT

cd circuits/bin/threshold/share_decryption
/usr/bin/time -v nargo compile 2>&1 | tail -4

cd /home/dev/interfold-research/interfold
b1=$(bb gates -b "$TJ" -t noir-recursive 2>/dev/null \
     | python3 -c "import sys,json; d=json.load(sys.stdin); f=d.get('functions') or [d]; print(sum(x['circuit_size'] for x in f))")
echo "SECURE V0 (raw payload, recorded)   = 2977228 g"
echo "SECURE V1 (I14-patched payload)     = $b1 g"
echo "DELTA = $(( 2977228 - b1 )) g  = -$(python3 -c "print(f'{(2977228-b1)/2977228*100:.3f}')")% of C6-secure"