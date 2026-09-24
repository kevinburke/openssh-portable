#	$OpenBSD: cfgparse.sh,v 1.12 2026/07/22 00:37:24 dtucker Exp $
#	Placed in the Public Domain.

tid="sshd config parse"

# We need to use the keys generated for the regression test because sshd -T
# will fail if we're not running with SUDO (no permissions for real keys) or
# if we are running tests on a system that has never had sshd installed
# because the keys won't exist.

grep "HostKey " $OBJ/sshd_config > $OBJ/sshd_config_minimal
SSHD_KEYS="`cat $OBJ/sshd_config_minimal`"

verbose "reparse minimal config"
($SUDO ${SSHD} -T -f $OBJ/sshd_config_minimal >$OBJ/sshd_config.1 &&
 $SUDO ${SSHD} -T -f $OBJ/sshd_config.1 >$OBJ/sshd_config.2 &&
 diff $OBJ/sshd_config.1 $OBJ/sshd_config.2) || fail "reparse minimal config"

verbose "reparse regress config"
($SUDO ${SSHD} -T -f $OBJ/sshd_config >$OBJ/sshd_config.1 &&
 $SUDO ${SSHD} -T -f $OBJ/sshd_config.1 >$OBJ/sshd_config.2 &&
 diff $OBJ/sshd_config.1 $OBJ/sshd_config.2) || fail "reparse regress config"

# Detect IPv6 support and if found, define variables for the needed
# config lines.  This allows tests to also work on Portable platforms
# lacking IPv6 support without having diffs that make syncs harder.
if $SUDO ${SSHD} -tq -f $OBJ/sshd_config_minimal -oListenAddress=::1 ; then
	trace "IPv6 support detected"
	LISTENADDRESS_IPV6_LOOPBACK="listenaddress ::1"
	LISTENADDRESS_IPV6_LOOPBACK_1234="listenaddress [::1]:1234"
	LISTENADDRESS_IPV6_LOOPBACK_5678="listenaddress [::1]:5678"
else
	trace "IPv6 support NOT detected"
fi

verbose "listenaddress order"
# expected output
egrep -v '^$' > $OBJ/sshd_config.0 <<EOD
listenaddress 1.2.3.4:1234
listenaddress 1.2.3.4:5678
$LISTENADDRESS_IPV6_LOOPBACK_1234
$LISTENADDRESS_IPV6_LOOPBACK_5678
EOD

# test input sets.  should all result in the output above.
# test 1: addressfamily and port first
egrep -v '^$' > $OBJ/sshd_config.1 <<EOD
${SSHD_KEYS}
addressfamily any
port 1234
port 5678
listenaddress 1.2.3.4
$LISTENADDRESS_IPV6_LOOPBACK
EOD
($SUDO ${SSHD} -T -f $OBJ/sshd_config.1 | \
 grep -i '^listenaddress ' >$OBJ/sshd_config.2 &&
 diff -i $OBJ/sshd_config.0 $OBJ/sshd_config.2) || \
 fail "listenaddress order 1"

# test 2: listenaddress first
cat > $OBJ/sshd_config.1 <<EOD
${SSHD_KEYS}
listenaddress 1.2.3.4
$LISTENADDRESS_IPV6_LOOPBACK
port 1234
port 5678
addressfamily any
EOD
($SUDO ${SSHD} -T -f $OBJ/sshd_config.1 | \
 grep -i '^ListenAddress ' >$OBJ/sshd_config.2 &&
 diff -i $OBJ/sshd_config.0 $OBJ/sshd_config.2) || \
 fail "listenaddress order 2"

# Check idempotence of MaxStartups
verbose "maxstartups idempotent"
echo "maxstartups 1:2:3" > $OBJ/sshd_config.0
cat > $OBJ/sshd_config.1 <<EOD
${SSHD_KEYS}
MaxStartups 1:2:3
MaxStartups 8:16:32
EOD
($SUDO ${SSHD} -T -f $OBJ/sshd_config.1 | \
 grep -i '^maxstartups ' >$OBJ/sshd_config.2 &&
 diff -i $OBJ/sshd_config.0 $OBJ/sshd_config.2) || \
 fail "maxstartups idempotence"

# Shared Rust formatters must retain sshd's keyword casing and new fields.
verbose "configuration output names and public key limit"
$SUDO ${SSHD} -T -f $OBJ/sshd_config_minimal \
    -oListenAddress=127.0.0.1:2222 -oIPQoS='af21 cs1' \
    -oRekeyLimit='1M 1h' -oPermitUserEnvironment=FOO,BAR \
    -oPubkeyAuthOptions='touch-required max-pk-ok:3' \
    -oTCPKeepAlive=all -oWarnWeakCrypto=no-pq-kex \
    >$OBJ/sshd_config.1 || fail "dump explicit configuration"
for expected in \
    'ListenAddress 127.0.0.1:2222' \
    'IPQoS af21 cs1' \
    'RekeyLimit 1048576 3600' \
    'PermitUserEnvironment FOO,BAR' \
    'PubkeyAuthOptions touch-required max-pk-ok:3' \
    'TCPKeepAlive all' \
    'WarnWeakCrypto false'; do
	grep -qxF "$expected" $OBJ/sshd_config.1 || \
	    fail "missing configuration output: $expected"
done

verbose "reject invalid TCPKeepAlive value"
if $SUDO ${SSHD} -T -f $OBJ/sshd_config_minimal \
    -oTCPKeepAlive=no-pq-kex >$OBJ/sshd_config.1 2>/dev/null; then
	fail "TCPKeepAlive accepted a WarnWeakCrypto value"
fi

verbose "client TCPKeepAlive output"
${SSH} -G -F /dev/null -oTCPKeepAlive=all localhost >$OBJ/sshd_config.1 || \
    fail "dump client TCPKeepAlive"
grep -qxF 'tcpkeepalive all' $OBJ/sshd_config.1 || \
    fail "client TCPKeepAlive all output"

# cleanup
rm -f $OBJ/sshd_config.[012]
