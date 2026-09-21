#!/usr/bin/env bash
# Install the external wireless toolchain wifipilot drives.
#
#   ./scripts/install-tools.sh            # install what is missing
#   ./scripts/install-tools.sh --check    # only report what is missing
#
# Only run this on a machine you are allowed to turn into an audit box.
set -uo pipefail

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

need_pkgs=()
tool_pkgs=(
  "aircrack-ng:aircrack-ng"
  "reaver:reaver"          # also provides wash
  "bully:bully"
  "pixiewps:pixiewps"
  "hcxdumptool:hcxtools"
  "hcxpcapngtool:hcxtools"
  "hashcat:hashcat"
  "iw:iw"
  "rfkill:rfkill"
  "ethtool:ethtool"
  "nmcli:network-manager"
)

missing_tools=()
for entry in "${tool_pkgs[@]}"; do
  tool="${entry%%:*}"
  pkg="${entry##*:}"
  if command -v "$tool" >/dev/null 2>&1; then
    printf '  \033[32m✓\033[0m %-16s %s\n' "$tool" "$(command -v "$tool")"
  else
    printf '  \033[31m✗\033[0m %-16s missing (package: %s)\n' "$tool" "$pkg"
    missing_tools+=("$tool")
    need_pkgs+=("$pkg")
  fi
done

# de-duplicate package names
if ((${#need_pkgs[@]})); then
  mapfile -t need_pkgs < <(printf '%s\n' "${need_pkgs[@]}" | sort -u)
fi

echo
if ((${#missing_tools[@]} == 0)); then
  echo "Everything wifipilot can use is installed."
  exit 0
fi
echo "${#missing_tools[@]} tool(s) missing: ${missing_tools[*]}"

if ((CHECK_ONLY)); then
  exit 1
fi

if command -v apt >/dev/null 2>&1; then
  echo "→ sudo apt update && sudo apt install -y ${need_pkgs[*]}"
  sudo apt update && sudo apt install -y "${need_pkgs[@]}"
elif command -v pacman >/dev/null 2>&1; then
  echo "→ sudo pacman -S --needed ${need_pkgs[*]}"
  sudo pacman -S --needed "${need_pkgs[@]}"
elif command -v dnf >/dev/null 2>&1; then
  echo "→ sudo dnf install -y ${need_pkgs[*]}"
  sudo dnf install -y "${need_pkgs[@]}"
else
  echo "Unknown package manager. Install manually: ${need_pkgs[*]}" >&2
  exit 1
fi

echo
echo "Done. Verify with: wifipilot tools"
echo "Note: wifipilot is Linux-only — it drives nl80211 monitor mode, rfkill and"
echo "      the aircrack-ng suite, none of which exist elsewhere in a usable form."
