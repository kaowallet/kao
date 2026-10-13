#!/usr/bin/env bash
# Build a single-file Flatpak from a Linux release binary.
#
#   ./flatpak/build.sh target/release/kao dist
#
# Requires flatpak and flatpak-builder >= 1.15.11 (so --device=usb is
# recorded) and will install org.freedesktop.Platform//26.08 from Flathub
# if it is missing. KAO_FLATPAK_VERSION, when it looks like 1.2.3, is
# written into the AppStream release entry; otherwise the Cargo.toml
# version is used.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
binary=${1:?usage: flatpak/build.sh BINARY OUT_DIR}
out_dir=${2:?usage: flatpak/build.sh BINARY OUT_DIR}
runtime_version=26.08
app_id=com.kaowallet.kao

if ! command -v flatpak >/dev/null 2>&1 || ! command -v flatpak-builder >/dev/null 2>&1; then
    echo "flatpak and flatpak-builder are required" >&2
    exit 1
fi

ver=$(flatpak --version | awk '{print $2}')
oldest=$(printf '%s\n%s\n' "$ver" "1.15.11" | sort -V | head -n1)
if [ "$oldest" != "1.15.11" ]; then
    echo "flatpak $ver is too old to record --device=usb (need >= 1.15.11)" >&2
    exit 1
fi

if [ ! -f "$binary" ]; then
    echo "binary not found: $binary" >&2
    exit 1
fi
binary=$(realpath "$binary")
mkdir -p "$out_dir"
out_dir=$(realpath "$out_dir")

if [ -n "${KAO_FLATPAK_VERSION:-}" ] && [[ $KAO_FLATPAK_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.]+)?$ ]]; then
    version=$KAO_FLATPAK_VERSION
else
    version=$(awk '
        $0 == "[package]" { in_pkg = 1; next }
        in_pkg && /^version = / { gsub(/"/, "", $3); print $3; exit }
        in_pkg && /^\[/ { exit }
    ' "$root/Cargo.toml")
fi
if [ -z "$version" ]; then
    echo "could not read the package version from Cargo.toml" >&2
    exit 1
fi
release_date=$(git -c safe.directory="$root" -C "$root" log -1 --format=%cs 2>/dev/null || true)
if ! printf '%s' "$release_date" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
    release_date=$(date -u +%F)
fi

fp_user=()
if ! flatpak info "org.freedesktop.Platform//$runtime_version" >/dev/null 2>&1 \
    || ! flatpak info "org.freedesktop.Sdk//$runtime_version" >/dev/null 2>&1; then
    if [ "$(id -u)" -ne 0 ]; then
        fp_user=(--user)
    fi
    flatpak remote-add --if-not-exists "${fp_user[@]}" flathub \
        https://dl.flathub.org/repo/flathub.flatpakrepo
    flatpak install -y --noninteractive "${fp_user[@]}" flathub \
        "org.freedesktop.Platform//$runtime_version" \
        "org.freedesktop.Sdk//$runtime_version"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp "$binary" "$work/kao"
chmod 755 "$work/kao"
cp "$root/flatpak/$app_id.desktop" "$work/"
cp "$root/assets/icons/icon.png" "$work/$app_id.png"
cp "$root/flatpak/$app_id.yml" "$work/"
sed "s/version=\"[^\"]*\" date=\"[^\"]*\"/version=\"$version\" date=\"$release_date\"/" \
    "$root/flatpak/$app_id.metainfo.xml" > "$work/$app_id.metainfo.xml"

cd "$work"
flatpak-builder \
    "${fp_user[@]}" \
    --disable-rofiles-fuse \
    --force-clean \
    --disable-updates \
    --default-branch=stable \
    --repo="$work/repo" \
    --state-dir="$work/state" \
    "$work/build" \
    "$work/$app_id.yml"

# Resolve the binary against the Platform users run, not the larger Sdk that
# `flatpak-builder --run` uses (which also needs rofiles-fuse, absent in
# containers). stderr is kept: a too-new glibc symbol shows up there as
# "version `GLIBC_x' not found".
ldd_out=$(flatpak run \
    --filesystem="$work/build/files:ro" \
    --command=ldd \
    "org.freedesktop.Platform//$runtime_version" \
    "$work/build/files/bin/kao" 2>&1)
printf '%s\n' "$ldd_out"
if printf '%s\n' "$ldd_out" | grep -q 'not found'; then
    echo "binary is missing libraries inside the Flatpak runtime" >&2
    exit 1
fi

bundle=$out_dir/kao.flatpak
flatpak build-bundle \
    --runtime-repo=https://dl.flathub.org/repo/flathub.flatpakrepo \
    "$work/repo" \
    "$bundle" \
    "$app_id" \
    stable
chmod a+r "$bundle"
if [ -n "${KAO_FLATPAK_OWNER:-}" ]; then
    chown "$KAO_FLATPAK_OWNER" "$bundle"
fi
echo "wrote $bundle"
