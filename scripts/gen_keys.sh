#!/usr/bin/env sh

pack() {
    while read -r line; do
      printf '%s\\n' "$line"
    done
    echo "$line"
}

SECRET_KEY=$(openssl genpkey -algorithm ed25519)
PUBLIC_KEY=$(echo "$SECRET_KEY" | openssl pkey -pubout)

echo "POSER_AUTH_SECRET_KEY=\"$(echo "$SECRET_KEY" | pack)\""
echo "POSER_AUTH_PUBLIC_KEY=\"$(echo "$PUBLIC_KEY" | pack)\""
