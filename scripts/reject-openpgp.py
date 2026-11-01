"""Keep the unmaintained OpenPGP implementation out of the dependency closure."""
import sys

packages = [line.strip() for line in sys.stdin]
forbidden = [p for p in packages if p == "golang.org/x/crypto/openpgp" or p.startswith("golang.org/x/crypto/openpgp/")]
if forbidden:
    raise SystemExit("Forbidden unmaintained OpenPGP package imported: " + ", ".join(forbidden))
print("OpenPGP is absent from all compiled package dependencies.")
