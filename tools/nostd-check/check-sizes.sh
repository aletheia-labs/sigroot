#!/usr/bin/env bash
# Build each size profile for thumbv7em-none-eabihf and check initialized
# code+data (.text + .rodata + .data) against committed upper limits.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

target="thumbv7em-none-eabihf"
limits_file="$(dirname "$0")/size-limits.tsv"
bin="target/${target}/release/sigroot-nostd-check"
required_profiles=(address offline full)

llvm_size="$(find "$(rustc --print sysroot)" -name llvm-size -type f | head -n 1 || true)"
if [[ -z "${llvm_size}" ]]; then
	echo "llvm-size not found; install llvm-tools-preview for this toolchain" >&2
	exit 1
fi

is_decimal() {
	[[ "$1" =~ ^[0-9]+$ ]]
}

section_size() {
	local sizes="$1"
	local section="$2"
	local values
	values="$(awk -v section="${section}" '$1 == section { print $2 }' <<<"${sizes}")"
	if [[ -z "${values}" ]]; then
		printf '%s\n' 0
		return 0
	fi
	if [[ "${values}" == *$'\n'* ]] || ! is_decimal "${values}"; then
		echo "FAIL: invalid ${section} size from llvm-size: ${values}" >&2
		return 1
	fi
	printf '%s\n' "${values}"
}

declare -A limits=()
declare -A seen=()

while IFS= read -r line || [[ -n "${line}" ]]; do
	[[ -z "${line}" || "${line}" == \#* ]] && continue

	read -r profile limit extra <<<"${line}" || true
	if [[ -z "${profile}" || -z "${limit}" ]]; then
		echo "FAIL: malformed limits line: ${line}" >&2
		exit 1
	fi
	if [[ -n "${extra:-}" ]]; then
		echo "FAIL: unexpected extra fields for profile ${profile}" >&2
		exit 1
	fi
	case "${profile}" in
		address | offline | full) ;;
		*)
			echo "FAIL: unknown profile ${profile}" >&2
			exit 1
			;;
	esac
	if ! is_decimal "${limit}"; then
		echo "FAIL: non-decimal limit for ${profile}: ${limit}" >&2
		exit 1
	fi
	if [[ -n "${seen[${profile}]:-}" ]]; then
		echo "FAIL: profile ${profile} appears more than once" >&2
		exit 1
	fi
	seen["${profile}"]=1
	limits["${profile}"]="${limit}"
done <"${limits_file}"

for profile in "${required_profiles[@]}"; do
	if [[ -z "${limits[${profile}]:-}" ]]; then
		echo "FAIL: missing required profile ${profile} in ${limits_file}" >&2
		exit 1
	fi
done

status=0
measured=0
summary_rows=()

for profile in "${required_profiles[@]}"; do
	cargo build -p sigroot-nostd-check --release --target "${target}" --locked \
		--no-default-features --features "${profile}"

	if ! sizes="$("${llvm_size}" -A "${bin}")"; then
		echo "FAIL: ${profile}: llvm-size failed" >&2
		status=1
		continue
	fi
	if ! text="$(section_size "${sizes}" .text)" ||
		! rodata="$(section_size "${sizes}" .rodata)" ||
		! data="$(section_size "${sizes}" .data)"; then
		echo "FAIL: ${profile}: could not parse llvm-size output" >&2
		status=1
		continue
	fi
	if ((10#${text} == 0)); then
		echo "FAIL: ${profile}: missing or empty .text" >&2
		status=1
		continue
	fi

	sum=$((10#${text} + 10#${rodata} + 10#${data}))
	limit="${limits[${profile}]}"
	echo "${profile}	.text=${text}	.rodata=${rodata}	.data=${data}	sum=${sum}	limit=${limit}"
	summary_rows+=("| \`${profile}\` | ${text} | ${rodata} | ${data} | ${sum} | ${limit} |")
	measured=$((measured + 1))

	if ((10#${sum} > 10#${limit})); then
		echo "FAIL: ${profile}: sum ${sum} exceeds limit ${limit}" >&2
		status=1
	fi
done

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
	{
		echo "### Bare-metal size profiles"
		echo
		echo "Sum is \`.text\` + \`.rodata\` + \`.data\`: code and initialized data in the measurement binary (not a finished firmware size)."
		echo
		echo "| profile | .text | .rodata | .data | sum | limit |"
		echo "| --- | ---: | ---: | ---: | ---: | ---: |"
		printf '%s\n' "${summary_rows[@]}"
	} >>"${GITHUB_STEP_SUMMARY}"
fi

if ((measured != ${#required_profiles[@]})); then
	echo "FAIL: completed ${measured}/${#required_profiles[@]} required measurements" >&2
	exit 1
fi

exit "${status}"
