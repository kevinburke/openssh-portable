# Placed in the public domain.

tid="ML-KEM-768 with P-256 login and rekey"
kex=mlkem768nistp256-sha256

supported=$(${SSH} -Q kex) || fatal "cannot list key exchanges"
case " $supported " in
*"$kex"*) ;;
*) skip "$kex is not supported by this build" ;;
esac

echo "KexAlgorithms $kex" >> "$OBJ/sshd_proxy"
echo "RekeyLimit 16k" >> "$OBJ/sshd_proxy"

# A forced algorithm prevents fallback from hiding a missing dispatcher.
# Enough data to exercise the server's post-authentication rekey handler.
dd if=/dev/zero of="$COPY" bs=1024 count=128 2>/dev/null || fatal "create data"
${SSH} -vv -F "$OBJ/ssh_proxy" -oKexAlgorithms="$kex" \
    -oRekeyLimit=16k somehost cat < "$COPY" > "$COPY.out" || fail "hybrid login"
cmp "$COPY" "$COPY.out" || fail "hybrid transfer corrupted"
count=$(grep -c "kex: algorithm: $kex" "$TEST_SSH_LOGFILE") || \
    fail "hybrid algorithm was not negotiated"
[ "$count" -ge 2 ] || fail "hybrid exchange did not rekey"
