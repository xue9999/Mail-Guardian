#!/bin/bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
COMPOSE_FILE="${PROJECT_DIR}/deploy/compose.yaml"

/usr/bin/ruby -r yaml - "${COMPOSE_FILE}" <<'RUBY'
path = ARGV.fetch(0)
document = YAML.safe_load(File.read(path), aliases: true)
abort "compose.yaml is missing a services map" unless document.is_a?(Hash) && document["services"].is_a?(Hash)

services = document.fetch("services")
required = %w[unbound redis rspamd]
abort "missing services: #{(required - services.keys).join(', ')}" unless (required - services.keys).empty?

required.each do |name|
  service = services.fetch(name)
  image = service["image"].to_s
  abort "image #{name} has no pinned SHA-256" unless image.match?(/@sha256:[0-9a-f]{64}\z/)
  abort "service #{name} is missing read_only" unless service["read_only"] == true
  abort "service #{name} may gain new privileges" unless Array(service["security_opt"]).include?("no-new-privileges:true")
  abort "service #{name} does not drop all capabilities" unless Array(service["cap_drop"]).include?("ALL")
end

ports = Array(services.fetch("rspamd")["ports"])
expected_ports = ["127.0.0.1:11333:11333", "127.0.0.1:11334:11334"]
abort "Rspamd nie jest ograniczony do localhost" unless ports.sort == expected_ports.sort
abort "Redis must not publish host ports" if services.fetch("redis").key?("ports")
abort "Unbound must not publish host ports" if services.fetch("unbound").key?("ports")

bayes = File.read(File.join(File.dirname(path), "rspamd/local.d/classifier-bayes.conf"))
abort "Bayes autolearning is not disabled" unless bayes.match?(/^autolearn\s*=\s*false;/)
abort "Bayes does not require 100 examples" unless bayes.match?(/^min_learns\s*=\s*100;/)
fuzzy = File.read(File.join(File.dirname(path), "rspamd/local.d/fuzzy_check.conf"))
abort "public fuzzy checks are not disabled" unless fuzzy.match?(/^enabled\s*=\s*false;/)
neural = File.read(File.join(File.dirname(path), "rspamd/local.d/neural.conf"))
abort "automatic neural learning is not disabled" unless neural.match?(/^enabled\s*=\s*false;/)

puts "Statyczne zabezpieczenia Compose/Rspamd: OK"
RUBY

# Compose verifies interpolation and the full model without starting containers.
# Without Docker, static checks still enforce the main invariants; the installer
# performs full validation after prerequisites are installed.
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  TEST_ROOT="$(/usr/bin/mktemp -d /tmp/o2-guardian-compose-test.XXXXXX)"
  cleanup() {
    case "${TEST_ROOT}" in
      /tmp/o2-guardian-compose-test.*) /bin/rm -rf -- "${TEST_ROOT}" ;;
    esac
  }
  trap cleanup EXIT
  /bin/mkdir -p "${TEST_ROOT}/rspamd"
  printf '%s\n' 'password = "$2$test";' 'enable_password = "$2$test";' > "${TEST_ROOT}/rspamd/worker-controller.inc"
  GUARDIAN_RUNTIME_DIR="${TEST_ROOT}" docker compose --file "${COMPOSE_FILE}" config --quiet
  printf '%s\n' "Docker Compose config: OK"
else
  printf '%s\n' "Docker Compose unavailable — the installer will perform full validation."
fi

/usr/bin/grep -Fq 'rspamadm configtest' "${PROJECT_DIR}/scripts/02-uruchom-silnik.command"
printf '%s\n' "Post-start Rspamd configtest: present"
/usr/bin/grep -Fxq 'appendfsync always' "${PROJECT_DIR}/deploy/redis/redis.conf"
/usr/bin/grep -Fxq 'auto-aof-rewrite-min-size 4mb' "${PROJECT_DIR}/deploy/redis/redis.conf"
/usr/bin/grep -Fq 'guardian_check_guest_storage' "${PROJECT_DIR}/scripts/02-uruchom-silnik.command"
printf '%s\n' "Synchroniczny AOF, rotacja i kontrola dysku przed restartem: OK"
