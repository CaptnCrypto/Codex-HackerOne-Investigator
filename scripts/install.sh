#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
    printf 'install: %s\n' "$*" >&2
    exit 1
}

[[ ${EUID} -eq 0 ]] || fail 'run as root'

prefix=/opt/codex-hackerone-investigator
bin_dir=/usr/local/bin
while (($#)); do
    case "$1" in
        --prefix) (($# >= 2)) || fail '--prefix requires a value'; prefix=$2; shift 2 ;;
        --bin-dir) (($# >= 2)) || fail '--bin-dir requires a value'; bin_dir=$2; shift 2 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[[ ${prefix} == /* && ${bin_dir} == /* ]] || fail 'installation paths must be absolute'
[[ ${prefix} != / && ${bin_dir} != / ]] || fail 'refusing broad installation path'
[[ ! -L ${prefix} && ! -L ${bin_dir} ]] || fail 'symlink installation path refused'

source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ -f ${source_root}/README.md && -d ${source_root}/src ]] || fail 'invalid source tree'

install -d -o root -g root -m 0755 "${prefix}" "${prefix}/src" "${prefix}/scripts"
install -d -o root -g root -m 0755 "${prefix}/config" "${prefix}/systemd" "${prefix}/docs"
install -d -o root -g root -m 0755 "${bin_dir}"

for package in h1ro filesprep; do
    install -d -o root -g root -m 0755 "${prefix}/src/${package}"
    install -o root -g root -m 0644 "${source_root}/src/${package}/"*.py "${prefix}/src/${package}/"
done

for command in h1-ro files-preflight files-request-broker files-broker-client; do
    install -o root -g root -m 0755 "${source_root}/scripts/${command}" "${prefix}/scripts/${command}"
    [[ ! -e ${bin_dir}/${command} || -L ${bin_dir}/${command} ]] || fail "command path already exists: ${bin_dir}/${command}"
    ln -sfn "${prefix}/scripts/${command}" "${bin_dir}/${command}"
done

install -o root -g root -m 0644 "${source_root}/config/"*.json "${prefix}/config/"
install -o root -g root -m 0644 "${source_root}/systemd/"*.example "${prefix}/systemd/"
install -o root -g root -m 0644 "${source_root}/docs/"*.md "${prefix}/docs/"
install -o root -g root -m 0644 "${source_root}/README.md" "${source_root}/INSTALL.md" "${source_root}/SECURITY.md" "${prefix}/"

install -d -o root -g root -m 0700 /var/lib/files-research/runtime
install -o root -g root -m 0600 /dev/null /var/lib/files-research/runtime/STOP

printf '%s\n' \
    "Installed code and disabled templates at ${prefix}." \
    'Emergency STOP is present.' \
    'No service was installed, enabled, or started.' \
    'Read INSTALL.md before creating any private configuration.'
