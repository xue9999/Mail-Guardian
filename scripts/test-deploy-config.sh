#!/bin/bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
COMPOSE_FILE="${PROJECT_DIR}/deploy/compose.yaml"

/usr/bin/ruby -r yaml - "${COMPOSE_FILE}" <<'RUBY'
path = ARGV.fetch(0)
document = YAML.safe_load(File.read(path), aliases: true)
abort "compose.yaml nie zawiera mapy usług" unless document.is_a?(Hash) && document["services"].is_a?(Hash)

services = document.fetch("services")
required = %w[unbound redis rspamd]
abort "brakuje usług: #{(required - services.keys).join(', ')}" unless (required - services.keys).empty?

required.each do |name|
  service = services.fetch(name)
  image = service["image"].to_s
  abort "obraz #{name} nie ma przypiętego SHA-256" unless image.match?(/@sha256:[0-9a-f]{64}\z/)
  abort "usługa #{name} nie ma read_only" unless service["read_only"] == true
  abort "usługa #{name} może uzyskać nowe uprawnienia" unless Array(service["security_opt"]).include?("no-new-privileges:true")
  abort "usługa #{name} nie usuwa wszystkich capabilities" unless Array(service["cap_drop"]).include?("ALL")
end

ports = Array(services.fetch("rspamd")["ports"])
expected_ports = ["127.0.0.1:11333:11333", "127.0.0.1:11334:11334"]
abort "Rspamd nie jest ograniczony do localhost" unless ports.sort == expected_ports.sort
abort "Redis nie może wystawiać portów na hosta" if services.fetch("redis").key?("ports")
abort "Unbound nie może wystawiać portów na hosta" if services.fetch("unbound").key?("ports")

bayes = File.read(File.join(File.dirname(path), "rspamd/local.d/classifier-bayes.conf"))
abort "autolearning Bayesa nie jest wyłączony" unless bayes.match?(/^autolearn\s*=\s*false;/)
abort "Bayes nie wymaga 100 przykładów" unless bayes.match?(/^min_learns\s*=\s*100;/)
fuzzy = File.read(File.join(File.dirname(path), "rspamd/local.d/fuzzy_check.conf"))
abort "publiczne fuzzy nie jest wyłączone" unless fuzzy.match?(/^enabled\s*=\s*false;/)
neural = File.read(File.join(File.dirname(path), "rspamd/local.d/neural.conf"))
abort "automatyczna sieć neuronowa nie jest wyłączona" unless neural.match?(/^enabled\s*=\s*false;/)

puts "Statyczne zabezpieczenia Compose/Rspamd: OK"
RUBY

# Docker Compose potrafi zweryfikować interpolację i pełny model bez
# uruchamiania kontenerów. Na komputerze deweloperskim bez Dockera test
# statyczny powyżej nadal chroni najważniejsze inwarianty; instalator wykonuje
# tę pełną kontrolę po zainstalowaniu wymaganych narzędzi.
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
  printf '%s\n' "Docker Compose nie jest dostępny — pełną kontrolę wykona instalator."
fi

/usr/bin/grep -Fq 'rspamadm configtest' "${PROJECT_DIR}/scripts/02-uruchom-silnik.command"
printf '%s\n' "Końcowy configtest Rspamd po uruchomieniu: obecny"
/usr/bin/grep -Fxq 'appendfsync always' "${PROJECT_DIR}/deploy/redis/redis.conf"
/usr/bin/grep -Fxq 'auto-aof-rewrite-min-size 4mb' "${PROJECT_DIR}/deploy/redis/redis.conf"
/usr/bin/grep -Fq 'guardian_check_guest_storage' "${PROJECT_DIR}/scripts/02-uruchom-silnik.command"
printf '%s\n' "Synchroniczny AOF, rotacja i kontrola dysku przed restartem: OK"
