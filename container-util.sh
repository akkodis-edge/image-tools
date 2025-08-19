#!/bin/sh

ENOENT=2
EBADF=9
EFAULT=14
EINVAL=22

TMPDIR="NONE"

cleanup() {
	if [ "$TMPDIR" != "NONE" ]; then
		rm -r "$TMPDIR" || echo "Failed removing TMPDIR: $TMPDIR"
		TMPDIR="NONE"
	fi
}

die () {
	echo "$2"
	cleanup
	exit $1
}

# Expects arguments:
#   $1: public key
calculate_pubkey_sha256() {
	if [ ! -f "$1" ]; then
		return 1
	fi
	if ! openssl pkey -in "$1" -pubin -check -noout >/dev/null 2>&1; then
		return 1
	fi
	local sha256="$(openssl pkey -in "$1" -pubin -outform DER | sha256sum)"
	if [ $? != 0 ]; then
		return 1
	fi
	echo "$sha256"
	return 0
}

# Expects arguments
#   $1: public key
#   $2: sha256 to compare with
compare_pubkey_sha256() {
	local sha256="$(calculate_pubkey_sha256 "$1")"
	if [ $? != 0 ]; then
		return 1
	fi
	if [ "$sha256" = "$2" ]; then
		return 0
	fi
	return 1
}

print_usage() {
	echo "Usage: container-util [OPTIONS] FILE"
	echo "Add or verify signatures and optionally create dm-verity volume."
	echo ""
	echo "Options:"
	echo "  -f,--force         Replace existing header"
	echo "  -d,--debug         Debug output"
	echo " --verify            Verify signature"
	echo " --create            Create signature"
	echo " --keyfile           Path to signing key"
	echo " --pubkey            Path to validation key"
	echo " --pubkey-dir        Path to directory with valid keys"
	echo " --pubkey-any        Use pubkey from header"
	echo ""
	echo "Return value:"
	echo " 0 for success or error code"
	echo "Error codes:"
	echo " 2  (ENOENT): No such file (or no permission)"
	echo " 9  (EBADF):  Corrupt input FILE"
	echo " 14 (EFAULT): Operation failed"
	echo " 22 (EINVAL): Invalid argument"
}

arg_force="no"
arg_dump="no"
arg_file=""
arg_cmd=""
arg_pubkey=""
arg_pubkey_dir=""
arg_pubkey_any="no"

while [ "$#" -gt 0 ]; do
	case $1 in
	-f|--force)
		arg_force="yes"
		shift # past argument
		;;
	--verify)
		arg_cmd="verify"
		shift # past argument
		;;
	--create)
		arg_cmd="create"
		shift # past argument
		;;
	--keyfile)
		[ "$#" -gt 1 ] || die $EINVAL "Invalid argument --keyfile"
		arg_keyfile="$2"
		shift # past argument
		shift # past value
		;;
	--pubkey)
		[ "$#" -gt 1 ] || die $EINVAL "Invalid argument --pubkey"
		arg_pubkey="$2"
		shift # past argument
		shift # past value
		;;
	--pubkey-dir)
		[ "$#" -gt 1 ] || die $EINVAL "Invalid argument --pubkey-dir"
		arg_pubkey_dir="$2"
		shift # past argument
		shift # past value
		;;
	--pubkey-any)
		arg_pubkey_any="yes"
		shift # past argument
		;;
	-d|--debug)
		arg_debug="yes"
		shift # past argument
		;;
	-*|--*)
		print_usage
		exit $EINVAL
		;;
	*)
		arg_file="$1"
		shift # past argument
		;;
  esac
done

[ "x$arg_file" != "x" ] ||  die $EINVAL "Missing mandatory argument FILE"
[ "x$arg_cmd" != "x" ] ||  die $EINVAL "No operation specified, see --verify"
if [ "$arg_cmd" = "create" ]; then
	[ "x$arg_keyfile" != "x" ] || die $EINVAL "--create requires --keyfile"
	# Do not care who signed input file (if already signed)
	arg_pubkey_any="yes"
fi

[ "$arg_pubkey_any" != "yes" -a "x$arg_pubkey" = "x" -a "x$arg_pubkey_dir" = "x" ] && die $EINVAL "No pubkey method provided, see --pubkey*"

# Create workspace
TMPDIR="$(mktemp -d)" || die $EFAULT "Failed creating temp dir"

# Check if FILE has existing header
file_state="UNKNOWN"
total_size="$(stat -L -c %s "$arg_file")" || die $ENOENT "Failed getting container size"
file_size="$total_size"
if [ "$total_size" -gt 64 ]; then
	# Validate header magic
	tail --bytes 64 "$arg_file" > "${TMPDIR}/offsets" || die $ENOENT  "Failed extracting offset blob"
	magic="$(od -N 4 -A none --endian=little --format=u4 "${TMPDIR}/offsets")" || die $EFAULT "Failed extracting header magic"
	magic="$(printf '0x%08x' "$magic")" || die $EFAULT "Failed processing header magic"
	if [ "$magic" = 0x494d4721 ]; then
		# Set state as invalid until verified
		file_state="INVALID"
		# Extract offsets
		tree_offset="$(od -N 8 -j 32 -A none --endian=little --format=u8 "${TMPDIR}/offsets")" || die $EFAULT "Failed extracting tree offset"
		tree_offset="$(echo "$tree_offset" | tr -d ' ')" || die $EFAULT "Failed processing tree offset"
		root_offset="$(od -N 8 -j 40 -A none --endian=little --format=u8 "${TMPDIR}/offsets")" || die $EFAULT "Failed extracting root offset"
		root_offset="$(echo "$root_offset" | tr -d ' ')" || die $EFAULT "Failed processing root offset"
		digest_offset="$(od -N 8 -j 48 -A none --endian=little --format=u8 "${TMPDIR}/offsets")" || die $EFAULT "Failed extracting digest offset"
		digest_offset="$(echo "$digest_offset" | tr -d ' ')" || die $EFAULT "Failed processing digest offset"
		key_offset="$(od -N 8 -j 56 -A none --endian=little --format=u8 "${TMPDIR}/offsets")" || die $EFAULT "Failed extracting key offset"
		key_offset="$(echo "$key_offset" | tr -d ' ')" || die $EFAULT "Failed processing key offset"

		# Validate offsets
		if [ "$tree_offset" -ge "$root_offset" ]; then
			echo "Invalid header, header tree offset not less than root offset"
		elif [ "$root_offset" -ge "$digest_offset" ]; then
			echo "Invalid container, header root offset not less than digest offset"
		elif [ "$digest_offset" -ge "$key_offset" ]; then
			echo "Invalid container, digest offset not less than key offset"
		elif [ "$key_offset" -ge $(( $total_size - 64 )) ]; then
			echo "Invalid container, key offset less than container size"
		else
			# Calculate section sizes
			tree_size=$(( $root_offset - $tree_offset ))
			root_size=$(( $digest_offset - $root_offset ))
			digest_size=$(( $key_offset - $digest_offset ))
			key_size=$(( $total_size - $key_offset - 64 ))
			file_size="$tree_offset"

			if [ "$arg_debug" = "yes" ]; then
				echo "$arg_file:"
				printf " 0x%08x file   - %d b\n" 0 "$file_size"
				printf " 0x%08x tree   - %d b\n" "$tree_offset" "$tree_size"
				printf " 0x%08x root   - %d b\n" "$root_offset" "$root_size"
				printf " 0x%08x digest - %d b\n" "$digest_offset" "$digest_size"
				printf " 0x%08x key    - %d b\n" "$key_offset" "$key_size"
			fi

			# Extract blobs
			dd "if=$arg_file" "of=${TMPDIR}/roothash" "bs=$root_size" count=1 iflag=skip_bytes \
				"skip=$root_offset" status=none || die $EFAULT "Failed extracting root blob"
			dd "if=$arg_file" "of=${TMPDIR}/digest" "bs=$digest_size" count=1 iflag=skip_bytes \
				"skip=$digest_offset" status=none || die $EFAULT "Failed extracting digest blob"
			dd "if=$arg_file" "of=${TMPDIR}/pubkey" "bs=$key_size" count=1 iflag=skip_bytes \
				"skip=$key_offset" status=none || die $EFAULT "Failed extracting key blob"

			# Find pubkey to use for validation
			validation_pubkey=""
			# Validate header key and calculate checksum
			header_pubkey_sha256="$(calculate_pubkey_sha256 "${TMPDIR}/pubkey")"
			if [ $? != 0 ]; then
				echo "Invalid container, pubkey corrupt"
			else
				if [ "$arg_pubkey_any" = "yes" ]; then
					validation_pubkey="${TMPDIR}/pubkey"
				elif [ "x$arg_pubkey" != "x" ]; then
					if compare_pubkey_sha256 "$arg_pubkey" "$header_pubkey_sha256"; then
						validation_pubkey="$arg_pubkey"
					else
						echo "Invalid container, provided --pubkey verification failed"
					fi
				elif [ "x$arg_pubkey_dir" != "x" ]; then
					for candidate in "$arg_pubkey_dir"/*; do
						if compare_pubkey_sha256 "$candidate" "$header_pubkey_sha256"; then
							validation_pubkey="$candidate"
							break
						fi
					done
				else
					die $EINVAL "No pubkey method provided, see --pubkey*"
				fi
			fi

			if [ "x$validation_pubkey" != "x" ]; then
				echo "public key used for validation: $validation_pubkey"
				# Validate dm-verity header:roothash signature header:digest with header:pubkey
				openssl_result="$(openssl dgst -sha256 -verify "$validation_pubkey" -signature "${TMPDIR}/digest" "${TMPDIR}/roothash")"
				if [ "$openssl_result" = "Verified OK" ]; then
					[ "$arg_debug" = "yes" ] && echo "roothash signature valid"
					file_state="VALID"
				else
					echo "Invalid container, failed veriying roothash digest"
				fi
			fi
		fi
	else
		file_state="UNSIGNED"
	fi
else
	file_state="UNSIGNED"
fi

# VERIFY
if [ "$arg_cmd" = "verify" ]; then
	# Validate file with dm-verity header:tree and header:roothash
	[ "$file_state" != "VALID" ] && die $EBADF "File verification failed"
	PATH="${PATH}:/usr/sbin" veritysetup verify "$arg_file" "$arg_file" "--hash-offset=$tree_offset" \
		"--root-hash-file=${TMPDIR}/roothash" || die $EBADF "File verification failed"
	echo "File verified OK"
# CREATE
elif [ "$arg_cmd" = "create" ]; then
	if [ "$file_state" = "VALID" ]; then
		if [ "$arg_force" != "yes" ]; then
			die $ENOENT "Valid header found, not overwriting. Use --force to override."
		else
			[ "$arg_debug" = "yes" ] && echo "Deleting existing header"
			truncate --size "$file_size" "$arg_file" || die $EFAULT "Failed truncating FILE"
		fi
	fi

	# Cleanup tmpdir contents
	rm -f "${TMPDIR}/roothash" || die $EFAULT "Failed removing tmpfile"
	rm -f "${TMPDIR}/digest" || die $EFAULT "Failed removing tmpfile"
	rm -f "${TMPDIR}/pubkey"  || die $EFAULT "Failed removing tmpfile"
	rm -f "${TMPDIR}/tree"  || die $EFAULT "Failed removing tmpfile"
	rm -f "${TMPDIR}/offsets"  || die $EFAULT "Failed removing tmpfile"
	# Generate roothash and hashtree
	PATH="${PATH}:/usr/sbin" veritysetup --data-block-size=4096 --hash-block-size=4096 format \
		--root-hash-file "${TMPDIR}/roothash" "$arg_file" "${TMPDIR}/tree" || die $EFAULT "Failed dm-verify formatting"
	# Sign roothash and extract public key
	if [ "x$arg_keyfile" != "x" ]; then
		openssl pkey -in "$arg_keyfile" -out "${TMPDIR}/pubkey" -pubout -outform DER || die $ENOENT "Failed extracting --keyfile pubkey"
		openssl dgst -sha256 -out "${TMPDIR}/digest" -sign "$arg_keyfile" "${TMPDIR}/roothash" || die $EFAULT "Failed signing roothash"
	else
		die $EINVAL "No signing method provided"
	fi

	# Get section sizes
	tree_size="$(stat -c %s ${TMPDIR}/tree)" || die $EFAULT "Failed getting hashtree size"
	root_size="$(stat -c %s ${TMPDIR}/roothash)" || die $EFAULT "Failed getting roothash size"
	digest_size="$(stat -c %s ${TMPDIR}/digest)" || die $EFAULT "Failed getting digest size"
	key_size="$(stat -c %s ${TMPDIR}/pubkey)" || die $EFAULT "Failed getting public key size"

	# Calculate offsets in file
	tree_offset="$file_size"
	root_offset=$(( $tree_offset  + $tree_size ))
	digest_offset=$(( $root_offset + $root_size ))
	key_offset=$(( $digest_offset + $digest_size ))

	if [ "$arg_debug" = "yes" ]; then
		echo "$arg_file:"
		printf " 0x%08x file   - %d b\n" 0 "$file_size"
		printf " 0x%08x tree   - %d b\n" "$tree_offset" "$tree_size"
		printf " 0x%08x root   - %d b\n" "$root_offset" "$root_size"
		printf " 0x%08x digest - %d b\n" "$digest_offset" "$digest_size"
		printf " 0x%08x key    - %d b\n" "$key_offset" "$key_size"
	fi

	# Serialize offsets
	printf "%08x" 0x21474d49 | xxd -r -p > "${TMPDIR}/offsets" || die $EFAULT "Failed writing offset"
	dd if=/dev/zero of="${TMPDIR}/offsets" bs=28 count=1 oflag=append conv=notrunc
	printf "%016x" "$tree_offset" | sed 's@\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)@0x\8\7\6\5\4\3\2\1@' \
		| xxd -r -p >> "${TMPDIR}/offsets" || die $EFAULT "Failed writing offset"
	printf "%016x" "$root_offset" | sed 's@\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)@0x\8\7\6\5\4\3\2\1@' \
		| xxd -r -p >> "${TMPDIR}/offsets" || die $EFAULT "Failed writing offset"
	printf "%016x" "$digest_offset" | sed 's@\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)@0x\8\7\6\5\4\3\2\1@' \
		| xxd -r -p >> "${TMPDIR}/offsets" || die $EFAULT "Failed writing offset"
	printf "%016x" "$key_offset" | sed 's@\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)@0x\8\7\6\5\4\3\2\1@' \
		| xxd -r -p >> "${TMPDIR}/offsets" || die $EFAULT "Failed writing offset"

	# Assembly output file
	cat "${TMPDIR}/tree" "${TMPDIR}/roothash" "${TMPDIR}/digest" "${TMPDIR}/pubkey" "${TMPDIR}/offsets" \
		>> "$arg_file" || die $EFAULT "Failed appending header"
else
	die $EINVAL "Invalid argument"
fi

cleanup
exit 0
