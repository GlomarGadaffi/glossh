#!/bin/bash
# littlessh integration tests against a real OpenSSH client
cd "$(dirname "$0")"
PORT=${1:-2222}
BASE="-p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
OPTS="$BASE -o LogLevel=ERROR"
PASS=0; FAIL=0
ok(){ echo "PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "FAIL: $1"; FAIL=$((FAIL+1)); }

pkill -f './harness' 2>/dev/null; sleep 0.3
LSSH_AUTH_TIMEOUT_MS=2000 setsid ./harness $PORT >server.log 2>&1 </dev/null &
SRV=$!
sleep 0.5

# 1. exec with password auth
out=$(timeout 10 sshpass -p hunter2 ssh $OPTS admin@127.0.0.1 "status please" 2>c1.log)
rc=$?
[ "$out" = "exec:status please" ] && [ $rc -eq 0 ] && ok "exec+password (rc=$rc out='$out')" \
  || bad "exec+password (rc=$rc out='$out')"

# 2. userauth banner (OpenSSH only prints banners at LogLevel INFO or above;
#    ssh keeps the first value per option, so this can't reuse $OPTS)
timeout 10 sshpass -p hunter2 ssh $BASE -o LogLevel=INFO admin@127.0.0.1 true 2>c2.log
grep -q "authorized use only" c2.log && ok "userauth banner delivered" || bad "banner missing"

# 3. wrong password rejected
timeout 10 sshpass -p wrong ssh $OPTS -o NumberOfPasswordPrompts=1 admin@127.0.0.1 true 2>/dev/null
[ $? -ne 0 ] && ok "wrong password rejected" || bad "wrong password accepted!"

# 4. interactive shell with pty
out=$(printf 'hello world\rexit\r' | timeout 10 sshpass -p hunter2 ssh -tt $OPTS admin@127.0.0.1 2>/dev/null)
echo "$out" | grep -q "echo:hello world" && echo "$out" | grep -q "bye" \
  && ok "interactive pty shell" || bad "interactive pty shell: '$out'"

# 5. ECDSA publickey auth
rm -f id_ecdsa id_ecdsa.pub
ssh-keygen -q -t ecdsa -b 256 -N "" -f id_ecdsa
out=$(timeout 10 ssh $OPTS -i id_ecdsa -o IdentitiesOnly=yes \
      -o PasswordAuthentication=no keyuser@127.0.0.1 "whoami-test" 2>c5.log)
[ "$out" = "exec:whoami-test" ] && ok "ecdsa publickey auth" || { bad "ecdsa publickey auth: '$out'"; tail -3 c5.log; }

# 6. unauthorized key for wrong user falls through and fails
timeout 10 ssh $OPTS -i id_ecdsa -o IdentitiesOnly=yes -o PasswordAuthentication=no \
   -o KbdInteractiveAuthentication=no nobody@127.0.0.1 true 2>/dev/null
[ $? -ne 0 ] && ok "unauthorized key rejected" || bad "unauthorized key accepted!"

# 7. a 5000-byte line: inbound arrives in several CHANNEL_DATA packets and the
#    echo exceeds one outbound packet, so lssh_write() has to fragment
big=$(python3 -c "print('x'*5000)")
out=$(printf "$big\rexit\r" | timeout 10 sshpass -p hunter2 ssh -tt $OPTS admin@127.0.0.1 2>/dev/null)
echo "$out" | grep -q "echo:$big" && ok "5000-byte line round-trip" || bad "5000-byte line round-trip"

# 8. ^B writes 3 MiB from inside on_data: more than the client's window, so
#    lssh_write() pumps inbound packets mid-callback. The rest of the same
#    data packet ("hello\r") must survive that, and exactly 3 MiB arrives.
out=$(printf '\002hello\rexit\r' | timeout 30 sshpass -p hunter2 ssh -tt $OPTS admin@127.0.0.1 2>/dev/null)
dots=$(printf '%s' "$out" | tr -cd . | wc -c)
[ "$dots" -eq 3145728 ] && echo "$out" | grep -q "echo:hello" && echo "$out" | grep -q "bye" \
  && ok "on_data input intact across window pump (dots=$dots)" \
  || bad "on_data input intact across window pump (dots=$dots)"

# 9. client-initiated rekey mid-stream (RekeyLimit 16K vs 3 MiB of output)
#    (ssh -E appends, so a stale log would satisfy the count on a rerun)
rm -f c9.log
out=$(printf '\002hello\rexit\r' | timeout 30 sshpass -p hunter2 ssh -tt $BASE -o LogLevel=DEBUG1 \
      -o RekeyLimit=16K -E c9.log admin@127.0.0.1)
dots=$(printf '%s' "$out" | tr -cd . | wc -c)
kex=$(grep -c "SSH2_MSG_KEXINIT sent" c9.log)
[ "$dots" -eq 3145728 ] && [ "$kex" -ge 2 ] && echo "$out" | grep -q "echo:hello" \
  && ok "rekey mid-stream (kexinits=$kex dots=$dots)" || bad "rekey mid-stream (kexinits=$kex dots=$dots)"

# 10. a silent / trickling pre-auth client must not hold the one slot: it is
#     dropped at the auth deadline (2 s here) and a real client gets in
python3 -c '
import socket,time
s=socket.create_connection(("127.0.0.1",'$PORT'))
for b in b"SSH-2.0-slowloris": s.send(bytes([b])); time.sleep(1)
' 2>/dev/null &
LORIS=$!
sleep 0.5
start=$(date +%s)
out=$(timeout 15 sshpass -p hunter2 ssh $OPTS admin@127.0.0.1 "after loris" 2>c10.log)
el=$(( $(date +%s) - start ))
kill $LORIS 2>/dev/null
[ "$out" = "exec:after loris" ] && [ $el -le 6 ] && ok "pre-auth deadline frees the slot (${el}s)" \
  || { bad "pre-auth deadline frees the slot (${el}s, out='$out')"; tail -3 c10.log; }

# 11. with no host key configured, the ephemeral key holds across connections
LSSH_EPHEMERAL=1 setsid ./harness $((PORT+1)) >server-eph.log 2>&1 </dev/null &
EPH=$!
sleep 0.5
k1=$(ssh-keyscan -t ecdsa -p $((PORT+1)) 127.0.0.1 2>/dev/null | awk '{print $3}')
k2=$(ssh-keyscan -t ecdsa -p $((PORT+1)) 127.0.0.1 2>/dev/null | awk '{print $3}')
kill $EPH 2>/dev/null
[ -n "$k1" ] && [ "$k1" = "$k2" ] && ok "ephemeral host key stable across connections" \
  || bad "ephemeral host key changed between connections"

kill -0 $SRV 2>/dev/null && ok "server survived every client" || bad "server died (see server.log)"
kill $SRV 2>/dev/null
pkill -f './harness' 2>/dev/null
echo "=== server.log ==="; tail -20 server.log
grep -qE "ERROR: (Address|Leak)Sanitizer|runtime error" server.log server-eph.log \
  && bad "sanitizer clean" || ok "sanitizer clean"
echo "RESULT: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
