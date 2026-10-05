#!/bin/sh
#
# Generates throwaway certificates for src/test/tests.c into the given directory:
#   ca.pem, other-ca.pem         two unrelated CAs
#   agent.pem, agent-key.pem     signed by ca, SAN DNS:localhost, IP:127.0.0.1, IP:::1
#   wrong-name.pem, ...-key.pem  signed by ca, SAN DNS:agent.invalid
#

set -e

if [ -z "$1" ]; then
	echo "usage: $0 <output-dir>" >&2
	exit 1
fi

mkdir -p "$1"
cd "$1"

run() {
	if ! openssl "$@" >openssl.log 2>&1; then
		cat openssl.log >&2
		exit 1
	fi
}

ca() {
	printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$1.ext"
	run req -new -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout "$1-key.pem" -out "$1.csr"
	run x509 -req -days 2 -in "$1.csr" -signkey "$1-key.pem" -extfile "$1.ext" -out "$1.pem"
}

leaf() {
	printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" >"$1.ext"
	run req -new -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout "$1-key.pem" -out "$1.csr"
	run x509 -req -days 2 -in "$1.csr" -CA "$2.pem" -CAkey "$2-key.pem" -CAcreateserial -extfile "$1.ext" -out "$1.pem"
}

ca ca
ca other-ca
leaf agent ca "DNS:localhost,IP:127.0.0.1,IP:::1"
leaf wrong-name ca "DNS:agent.invalid"
