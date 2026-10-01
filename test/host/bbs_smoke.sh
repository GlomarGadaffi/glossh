#!/bin/bash
# GLOSSH BBS end to end against a real OpenSSH client: terminal check, dial-up,
# main menu, a screen, log off (NO CARRIER), and the idle timeout firing while
# on_tick keeps the screen animating.
cd "$(dirname "$0")"
PORT=${1:-2323}
OPTS="-p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR"
PASS=0; FAIL=0
ok(){ echo "PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "FAIL: $1"; FAIL=$((FAIL+1)); }

pkill -x bbs_host 2>/dev/null; sleep 0.3
setsid ./bbs_host $PORT 3 >bbs.log 2>&1 </dev/null &
SRV=$!
sleep 0.5

# 1. a full call: pick 24-bit color, skip the dial-up, open Task Monitor, hang up
out=$( { sleep 2; printf 1; sleep 0.5; printf ' '; sleep 0.3; printf ' '; sleep 1
         printf 4; sleep 1.5; printf '\033'; sleep 0.5; printf g; sleep 0.5; printf y; sleep 4; } \
       | timeout 20 sshpass -p bbs ssh -tt $OPTS caller@127.0.0.1 2>/dev/null )
echo "$out" | grep -q "T E R M I N A L" && ok "terminal check screen" || bad "terminal check screen"
echo "$out" | grep -q "M a i n   M e n u" && ok "main menu" || bad "main menu"
echo "$out" | grep -q "Task Monitor" && ok "task monitor" || bad "task monitor"
echo "$out" | grep -q $'\e\[38;2;' && ok "24-bit color output" || bad "24-bit color output"
echo "$out" | grep -q "NO CARRIER" && ok "log off: NO CARRIER" || bad "log off: NO CARRIER"

# 2. exec and no-pty sessions get a plain-text pointer, not escape codes
out=$(timeout 10 sshpass -p bbs ssh $OPTS caller@127.0.0.1 "hello" 2>/dev/null)
echo "$out" | grep -q "interactive board" && ok "exec refused politely" || bad "exec refused politely"

# 3. idle timeout (3 s here) still fires while ticks animate the screen
start=$(date +%s)
# (process substitution: a pipeline would also wait for the feeding sleep)
timeout 15 sshpass -p bbs ssh -tt $OPTS caller@127.0.0.1 < <(sleep 12) >/dev/null 2>&1
el=$(( $(date +%s) - start ))
[ $el -ge 3 ] && [ $el -le 8 ] && ok "idle timeout with ticks (${el}s)" || bad "idle timeout with ticks (${el}s)"

kill $SRV 2>/dev/null
pkill -x bbs_host 2>/dev/null
grep -qE "ERROR: (Address|Leak)Sanitizer|runtime error" bbs.log && bad "sanitizer clean" || ok "sanitizer clean"
echo "RESULT: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
