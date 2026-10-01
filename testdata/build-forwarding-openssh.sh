#!/bin/sh
# Build pinned test binaries in a disposable directory; nothing is installed.
set -eu
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/sshx-openssh-XXXXXX")
log_file="$build_dir/build.log"
trap 'result=$?; if [ "$result" -ne 0 ]; then tail -60 "$log_file" >&2; fi' EXIT
: > "$log_file"
curl --fail --silent --show-error --location \
  https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.5p1.tar.gz \
  -o "$build_dir/source.tar.gz"
printf '%s  %s\n' \
  d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11 \
  "$build_dir/source.tar.gz" | sha256sum --check >> "$log_file" 2>&1
tar -xzf "$build_dir/source.tar.gz" -C "$build_dir"
cd "$build_dir"
./openssh-10.5p1/configure --prefix="$build_dir" --libexecdir="$build_dir" \
  --with-privsep-path="$build_dir/empty" --without-pam >> "$log_file" 2>&1
make -j2 ssh sshd sshd-session sshd-auth ssh-add >> "$log_file" 2>&1
printf '%s\n' "$build_dir"
