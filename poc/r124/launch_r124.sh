set -uo pipefail
TS0=$(date +%s)
STARTED=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
cd /home/dev/interfold-research/interfold
echo "STARTED $STARTED epoch=$TS0"
echo "head nproc=$(nproc) $(grep -c ^processor /proc/cpuinfo)"
python3 - <<'PYEOF' > mem_pre.json 2>&1
import json
mi={l.split(':')[0]:int(l.split()[1]) for l in open('/proc/meminfo') if not l.endswith(':')}
print(json.dumps({'MemTotal':mi['MemTotal'],'MemAvailable':mi['MemAvailable'],'SwapTotal':mi['SwapTotal'],'SwapFree':mi['SwapFree']}))
PYEOF
/usr/bin/time -v pnpm build:circuits --preset secure-8192 --committee small \
  > buildout.log 2>&1
RC=$?
TS1=$(date +%s)
echo "FINISHED $(date -u '+%Y-%m-%dT%H:%M:%SZ') rc=$RC wall=$((TS1-TS0))s"
exit $RC