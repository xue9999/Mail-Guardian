#!/bin/bash
# Shared release contract. No Python, Go, Swift or Xcode needed to verify a ZIP.
safe_go_version() {
  local value="$1" major minor patch
  [[ "$value" =~ ^go([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 1
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  patch="${BASH_REMATCH[3]}"
  (( major > 1 || (major == 1 && minor > 27) ||
     (major == 1 && minor == 27 && patch >= 3) ||
     (major == 1 && minor == 26 && patch >= 10) ))
}
release_error() { printf 'Nieprawidłowa paczka: %s\n' "$*" >&2; return 1; }
release_hashes() (
  cd "$1" || exit 1
  # Payloads contain regular files only. Newlines/backslashes are disallowed.
  [[ -z "$(find . ! -type d ! -type f -print)" ]] || exit 1
  while IFS= read -r -d '' path; do
    case "$path" in *$'\n'*|*\\*) exit 1 ;; esac
  done < <(find . -type f -print0)
  paths=()
  while IFS= read -r path; do paths+=("$path"); done < <(find . -type f ! -path './RELEASE-MANIFEST' -print | LC_ALL=C sort)
  (( ${#paths[@]} > 0 )) || exit 1
  /usr/bin/shasum -a 256 "${paths[@]}"
)
release_manifest() {
  local root="$1" version="$2"
  printf 'format=1\ndistribution=prebuilt\nversion=%s\narchitecture=arm64\nminimum_macos=13.0\n--files--\n' "$version"
  release_hashes "$root"
}
verify_release() {
  local root="$1" version="$2" actual expected
  [[ "$(cat "$root/DISTRIBUTION" 2>/dev/null)" == prebuilt ]] || { release_error 'brak typu dystrybucji'; return 1; }
  [[ -f "$root/RELEASE-MANIFEST" ]] || { release_error 'brak manifestu'; return 1; }
  [[ -x "$root/prebuilt/guardian" && -x "$root/prebuilt/O2 Mail Guardian.app/Contents/MacOS/O2MailGuardianApp" ]] || { release_error 'brak gotowych programów'; return 1; }
  actual="$(release_manifest "$root" "$version")" || { release_error 'nieprawidłowe pliki payloadu'; return 1; }
  expected="$(cat "$root/RELEASE-MANIFEST")" || return 1
  [[ "$actual" == "$expected" ]] || { release_error 'niezgodne sumy, lista plików lub metadane'; return 1; }
}
verify_prebuilt() {
  local root="$1" version="$2" app="$1/prebuilt/O2 Mail Guardian.app" binary build_info
  for binary in "$root/prebuilt/guardian" "$app/Contents/MacOS/O2MailGuardianApp"; do
    /usr/bin/file "$binary" | /usr/bin/grep -Eq 'Mach-O 64-bit executable arm64$' || return 1
    /usr/bin/codesign --verify --strict "$binary" || return 1
  done
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")" == "$version" ]] || return 1
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$app/Contents/Info.plist")" == 13.0 ]] || return 1
  /usr/bin/codesign --verify --deep --strict "$app" || return 1
  build_info="$("$root/prebuilt/guardian" version)" || return 1
  printf '%s\n' "$build_info" | /usr/bin/grep -F "O2 Mail Guardian $version (" || return 1
  safe_go_version "$(printf '%s\n' "$build_info" | /usr/bin/awk '/^Go: / {print $2}')" || { release_error 'podatna lub nieznana wersja Go w gotowym programie'; return 1; }
  "$root/prebuilt/guardian" self-test || return 1
  "$app/Contents/MacOS/O2MailGuardianApp" --self-test || return 1
}
