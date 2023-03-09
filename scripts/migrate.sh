#!/usr/bin/env sh

DATABASE_URI=${POSER_AUTH_DATABASE_URI:-postgresql://poser@localhost/poser}

psql "$DATABASE_URI" < "$1"
