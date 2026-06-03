#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EXPORTER_BIN="$PROJECT_DIR/ssl_exporter"
EXPORTER_PID=""
COMPOSE_PROJECT="ssl_exporter_e2e"

cleanup() {
    echo "Cleaning up..."
    [ -n "$EXPORTER_PID" ] && kill $EXPORTER_PID 2>/dev/null || true
    docker compose -p "$COMPOSE_PROJECT" -f "$SCRIPT_DIR/docker-compose.yml" down -v --remove-orphans 2>/dev/null || true
}

trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    exit 1
}

pass() {
    echo "PASS: $1"
}

wait_for_service() {
    local service=$1
    local max_attempts=${2:-30}
    local attempt=0

    echo "Waiting for $service to be ready..."
    while [ $attempt -lt $max_attempts ]; do
        if docker compose -p "$COMPOSE_PROJECT" -f "$SCRIPT_DIR/docker-compose.yml" exec -T "$service" echo "ready" &>/dev/null; then
            if docker compose -p "$COMPOSE_PROJECT" -f "$SCRIPT_DIR/docker-compose.yml" ps "$service" | grep -q "healthy"; then
                return 0
            fi
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    return 1
}

probe() {
    local target=$1
    local module=$2
    curl -sf "http://localhost:9219/probe?target=$target&module=$module" 2>/dev/null
}

check_probe() {
    local target=$1
    local module=$2
    local result
    local errors=""

    result=$(probe "$target" "$module")

    if ! echo "$result" | grep -q 'ssl_probe_success 1'; then
        errors="${errors}ssl_probe_success != 1; "
    fi

    local not_after
    not_after=$(echo "$result" | grep 'ssl_cert_not_after{' | head -1 | awk '{print $NF}')
    if [ -z "$not_after" ]; then
        errors="${errors}ssl_cert_not_after missing; "
    else
        local now
        now=$(date +%s)
        local not_after_int
        not_after_int=$(printf "%.0f" "$not_after")
        if [ "$not_after_int" -le "$now" ]; then
            errors="${errors}ssl_cert_not_after is in the past; "
        fi
    fi

    if ! echo "$result" | grep -q 'ssl_cert_not_before{'; then
        errors="${errors}ssl_cert_not_before missing; "
    fi

    if ! echo "$result" | grep -q 'ssl_tls_version_info{'; then
        errors="${errors}ssl_tls_version_info missing; "
    fi

    if [ -n "$errors" ]; then
        echo "Errors: $errors"
        echo "Full output:"
        echo "$result"
        return 1
    fi
    return 0
}

check_probe_fails() {
    local target=$1
    local module=$2
    local result

    result=$(probe "$target" "$module")
    if echo "$result" | grep -q 'ssl_probe_success 0'; then
        return 0
    fi
    echo "Expected ssl_probe_success 0"
    echo "Full output:"
    echo "$result"
    return 1
}

check_probe_expired() {
    local target=$1
    local module=$2
    local result
    local errors=""

    result=$(probe "$target" "$module")

    if ! echo "$result" | grep -q 'ssl_probe_success 1'; then
        errors="${errors}ssl_probe_success != 1; "
    fi

    local not_after
    not_after=$(echo "$result" | grep 'ssl_cert_not_after{' | head -1 | awk '{print $NF}')
    if [ -z "$not_after" ]; then
        errors="${errors}ssl_cert_not_after missing; "
    else
        local now
        now=$(date +%s)
        local not_after_int
        not_after_int=$(printf "%.0f" "$not_after")
        if [ "$not_after_int" -gt "$now" ]; then
            errors="${errors}ssl_cert_not_after should be in the past; "
        fi
    fi

    if [ -n "$errors" ]; then
        echo "Errors: $errors"
        echo "Full output:"
        echo "$result"
        return 1
    fi
    return 0
}

check_probe_keystore() {
    local target=$1
    local result
    local errors=""

    result=$(probe "$target" "keystore")

    if ! echo "$result" | grep -q 'ssl_probe_success 1'; then
        errors="${errors}ssl_probe_success != 1; "
    fi

    local not_after
    not_after=$(echo "$result" | grep 'ssl_keystore_cert_not_after{' | head -1 | awk '{print $NF}')
    if [ -z "$not_after" ]; then
        errors="${errors}ssl_keystore_cert_not_after missing; "
    else
        local now
        now=$(date +%s)
        local not_after_int
        not_after_int=$(printf "%.0f" "$not_after")
        if [ "$not_after_int" -le "$now" ]; then
            errors="${errors}ssl_keystore_cert_not_after is in the past; "
        fi
    fi

    if ! echo "$result" | grep -q 'ssl_keystore_cert_not_before{'; then
        errors="${errors}ssl_keystore_cert_not_before missing; "
    fi

    if [ -n "$errors" ]; then
        echo "Errors: $errors"
        echo "Full output:"
        echo "$result"
        return 1
    fi
    return 0
}

check_probe_keystore_expired() {
    local target=$1
    local result
    local errors=""

    result=$(probe "$target" "keystore")

    # Reading an expired keystore still succeeds; only the expiry is in the past.
    if ! echo "$result" | grep -q 'ssl_probe_success 1'; then
        errors="${errors}ssl_probe_success != 1; "
    fi

    local not_after
    not_after=$(echo "$result" | grep 'ssl_keystore_cert_not_after{' | head -1 | awk '{print $NF}')
    if [ -z "$not_after" ]; then
        errors="${errors}ssl_keystore_cert_not_after missing; "
    else
        local now
        now=$(date +%s)
        local not_after_int
        not_after_int=$(printf "%.0f" "$not_after")
        if [ "$not_after_int" -gt "$now" ]; then
            errors="${errors}ssl_keystore_cert_not_after should be in the past; "
        fi
    fi

    if [ -n "$errors" ]; then
        echo "Errors: $errors"
        echo "Full output:"
        echo "$result"
        return 1
    fi
    return 0
}

check_probe_keystore_mixed() {
    local target=$1
    local result

    result=$(probe "$target" "keystore")

    if ! echo "$result" | grep -q 'ssl_probe_success 1'; then
        echo "Expected ssl_probe_success 1"
        echo "$result"
        return 1
    fi

    # A mixed keystore holds more than one certificate, so it must export more
    # than one not_after series.
    local count
    count=$(echo "$result" | grep -c 'ssl_keystore_cert_not_after{')
    if [ "$count" -lt 2 ]; then
        echo "Expected >= 2 ssl_keystore_cert_not_after series, got $count"
        echo "$result"
        return 1
    fi
    return 0
}

echo "Building ssl_exporter..."
cd "$PROJECT_DIR"
go build -o "$EXPORTER_BIN" .

echo "Generating certificates..."
mkdir -p "$SCRIPT_DIR/certs"
openssl req -x509 -newkey rsa:2048 -keyout "$SCRIPT_DIR/certs/valid.key" -out "$SCRIPT_DIR/certs/valid.crt" \
    -days 365 -nodes -subj "/CN=localhost" 2>/dev/null

CERTS_DIR="$SCRIPT_DIR/certs" python3 << 'PYEOF'
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone
import os

certs_dir = os.environ["CERTS_DIR"]
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
    .not_valid_after(datetime(2020, 1, 2, tzinfo=timezone.utc))
    .sign(key, hashes.SHA256())
)
with open(f"{certs_dir}/expired.key", "wb") as f:
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
with open(f"{certs_dir}/expired.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
PYEOF

echo "Generating keystores (JKS + PKCS12)..."
go run "$PROJECT_DIR/e2e/genkeystores" \
    -cert "$SCRIPT_DIR/certs/valid.crt" \
    -key "$SCRIPT_DIR/certs/valid.key" \
    -expired-cert "$SCRIPT_DIR/certs/expired.crt" \
    -out "$SCRIPT_DIR/certs"

cat > "$SCRIPT_DIR/config.yml" << 'EOF'
modules:
  mysql:
    prober: tcp
    tcp:
      starttls: mysql
    tls_config:
      insecure_skip_verify: true
  postgres:
    prober: tcp
    tcp:
      starttls: postgres
    tls_config:
      insecure_skip_verify: true
  https:
    prober: https
    tls_config:
      insecure_skip_verify: true
  tcp:
    prober: tcp
    tls_config:
      insecure_skip_verify: true
  keystore:
    prober: keystore
    keystore:
      password: changeit
  keystore_wrongpass:
    prober: keystore
    keystore:
      password: wrongpassword
EOF

echo "Starting services..."
docker compose -p "$COMPOSE_PROJECT" -f "$SCRIPT_DIR/docker-compose.yml" up -d

echo "Starting ssl_exporter..."
"$EXPORTER_BIN" --config.file="$SCRIPT_DIR/config.yml" &
EXPORTER_PID=$!
sleep 2

wait_for_service mysql || fail "MySQL did not become ready"
wait_for_service mariadb || fail "MariaDB did not become ready"
wait_for_service postgres || fail "PostgreSQL did not become ready"
wait_for_service proxysql || fail "ProxySQL did not become ready"
wait_for_service nginx_ssl || fail "nginx_ssl did not become ready"
wait_for_service nginx_nossl || fail "nginx_nossl did not become ready"
wait_for_service nginx_expired || fail "nginx_expired did not become ready"

sleep 5

echo ""
echo "Running tests..."
echo "================"

FAILED=0

echo -n "Test MySQL 8.0 STARTTLS: "
if check_probe "127.0.0.1:13306" "mysql"; then
    pass "MySQL 8.0 STARTTLS"
else
    echo "FAIL: MySQL 8.0 STARTTLS probe failed"
    FAILED=1
fi

echo -n "Test MariaDB 11 STARTTLS: "
if check_probe "127.0.0.1:13307" "mysql"; then
    pass "MariaDB 11 STARTTLS"
else
    echo "FAIL: MariaDB 11 STARTTLS probe failed"
    FAILED=1
fi

echo -n "Test PostgreSQL 16 STARTTLS: "
if check_probe "127.0.0.1:15432" "postgres"; then
    pass "PostgreSQL 16 STARTTLS"
else
    echo "FAIL: PostgreSQL 16 STARTTLS probe failed"
    FAILED=1
fi

echo -n "Test ProxySQL STARTTLS: "
if check_probe "127.0.0.1:16033" "mysql"; then
    pass "ProxySQL STARTTLS"
else
    echo "FAIL: ProxySQL STARTTLS probe failed"
    FAILED=1
fi

echo -n "Test nginx HTTPS: "
if check_probe "https://127.0.0.1:18443" "https"; then
    pass "nginx HTTPS"
else
    echo "FAIL: nginx HTTPS probe failed"
    FAILED=1
fi

echo -n "Test nginx TCP SSL: "
if check_probe "127.0.0.1:18443" "tcp"; then
    pass "nginx TCP SSL"
else
    echo "FAIL: nginx TCP SSL probe failed"
    FAILED=1
fi

echo -n "Test nginx no SSL (expect fail): "
if check_probe_fails "127.0.0.1:18080" "tcp"; then
    pass "nginx no SSL correctly failed"
else
    echo "FAIL: nginx no SSL should have failed"
    FAILED=1
fi

echo -n "Test nginx expired cert: "
if check_probe_expired "https://127.0.0.1:18444" "https"; then
    pass "nginx expired cert"
else
    echo "FAIL: nginx expired cert probe failed"
    FAILED=1
fi

echo -n "Test keystore JKS (valid): "
if check_probe_keystore "$SCRIPT_DIR/certs/keystore.jks"; then
    pass "keystore JKS (valid)"
else
    echo "FAIL: keystore JKS probe failed"
    FAILED=1
fi

echo -n "Test keystore PKCS12 truststore (valid): "
if check_probe_keystore "$SCRIPT_DIR/certs/truststore.p12"; then
    pass "keystore PKCS12 truststore (valid)"
else
    echo "FAIL: keystore PKCS12 truststore probe failed"
    FAILED=1
fi

echo -n "Test keystore PKCS12 with private key (valid): "
if check_probe_keystore "$SCRIPT_DIR/certs/keystore.p12"; then
    pass "keystore PKCS12 with private key (valid)"
else
    echo "FAIL: keystore PKCS12 with private key probe failed"
    FAILED=1
fi

echo -n "Test keystore JKS expired: "
if check_probe_keystore_expired "$SCRIPT_DIR/certs/expired.jks"; then
    pass "keystore JKS expired"
else
    echo "FAIL: keystore JKS expired probe failed"
    FAILED=1
fi

echo -n "Test keystore JKS mixed (valid + expired): "
if check_probe_keystore_mixed "$SCRIPT_DIR/certs/mixed.jks"; then
    pass "keystore JKS mixed"
else
    echo "FAIL: keystore JKS mixed probe failed"
    FAILED=1
fi

echo -n "Test keystore PKCS12 mixed (valid + expired): "
if check_probe_keystore_mixed "$SCRIPT_DIR/certs/mixed.p12"; then
    pass "keystore PKCS12 mixed"
else
    echo "FAIL: keystore PKCS12 mixed probe failed"
    FAILED=1
fi

echo -n "Test keystore wrong password (expect fail): "
if check_probe_fails "$SCRIPT_DIR/certs/keystore.jks" "keystore_wrongpass"; then
    pass "keystore wrong password correctly failed"
else
    echo "FAIL: keystore wrong password should have failed"
    FAILED=1
fi

echo -n "Test keystore unrecognized format (expect fail): "
if check_probe_fails "$SCRIPT_DIR/certs/valid.crt" "keystore"; then
    pass "keystore unrecognized format correctly failed"
else
    echo "FAIL: keystore unrecognized format should have failed"
    FAILED=1
fi

echo ""
if [ $FAILED -eq 0 ]; then
    echo "All tests passed!"
else
    echo "Some tests failed!"
    exit 1
fi
