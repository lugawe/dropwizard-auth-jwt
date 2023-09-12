#!/bin/sh

set -e

./mvnw --batch-mode spotless:apply >/dev/null
