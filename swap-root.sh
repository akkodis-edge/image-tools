#!/bin/bash
# Require bash due to builtin read

die() {
	>&2 echo "${1}"
	exit 1
}

exit_success() {
	exit 0
}

# Parse arguments
cmd_update=""
cmd_state=""
cmd_commit=""
cmd_cancel=""
cmd_rollback=""
cmd_counter=""
image=""
type="tar.bz2"
filesystem="ext4"

print_usage() {
    echo "Usage: ${1} [OPTIONS] COMMAND ARGS..."
    echo
    echo "Commands:"
    echo " update IMAGE         Write IMAGE to not-used rootfs partition"
   	echo " state                Return current state"
	echo "                         NORMAL:    Normal boot"
	echo "                         SWAPPING:  Swap in progress"
	echo "                         ROLLBACK:  Bootloader performed rollback"
	echo "                         INIT:      swap initiated (this boot)"
   	echo " commit               Commit change from state \"SWAPPING\" or \"ROLLBACK\" to \"NORMAL\""
   	echo "                      Commit from state \"NORMAL\" returns success."
   	echo " rollback             Rollback from SWAPPING to NORMAL"
	echo " cancel               Cancel from INIT to NORMAL"
	echo " has-manual-counter   Check if counter is controlled by firmware"
	echo "                         0: controlled by firmware"
	echo "                         1: has to be manually incremented by caller"
	echo " counter [VALUE]      Read or write counter. Writing counter not allowed when has-manual-counter is false"
	echo ""
    echo "Options:"
    echo " -t/--type            Type of image (default: ${type})"
    echo " -f/--filesystem      Type of filesystem (default: ${filesystem})"
    echo " -h/--help:           This help message"
}

while [ $# -gt 0 ]; do
	case $1 in
	-t|--type)
		[ $# -gt 1 ] || die "Invalid argument -t/--type"
		type="$2"
		shift # past argument
		shift # past value
		;;
	-f|--filesystem)
		[ $# -gt 1 ] || die "Invalid argument -f/--filesystem"
		filesystem="$2"
		shift # past argument
		shift # past value
		;;
	-h|--help)
		print_usage
		exit 1
		;;
	update)
		[ $# -gt 1 ] || die "Invalid arguments for command update"
		cmd_update="true"
		image="${2}"
		shift # past argument
		shift # past value
		;;
	state)
		cmd_state="true"
		shift # past argument
		;;
	commit)
		cmd_commit="true"
		shift # past argument
		;;
	cancel)
		cmd_cancel="true"
		shift # past argument
		;;
	rollback)
		cmd_rollback="true"
		shift # past argument
		;;
	has-manual-counter)
		echo "no"
		exit 0
		;;
	counter)
		cmd_counter="true"
		shift # past argument
		;;
	*)
		die "Invalid argument"
		;;	
  esac
done

current_root_label="$(findmnt -no PARTLABEL /)" || die "Failed finding current root partition label"
case "${current_root_label}" in
	rootfs1)
		new_root_label="rootfs2"
		;;
	rootfs2)
		new_root_label="rootfs1"
		;;
	*)
		# Early abort wanted in case of non-rootfs boot
		die "Unsupported root partition: ${current_root}"
		;;
esac

state="UNKNOWN"
part="$(nvram --sys --get SYS_BOOT_PART)" || die "Failed reading nvram variable SYS_BOOT_PART"
swap="$(nvram --sys --get SYS_BOOT_SWAP)" || die "Failed reading nvram variable SYS_BOOT_SWAP"
attempts="0"
if [ "$part" = "$swap" ]; then
	attempts="$(nvram --sys --get SYS_BOOT_ATTEMPTS)"
	if [ $? -ne 0 ]; then
		state="NORMAL"
	else
		state="ROLLBACK"
	fi
else
	attempts="$(nvram --sys --get SYS_BOOT_ATTEMPTS)"
	if [ $? -ne 0 ]; then
		state="INIT"
	else
		state="SWAPPING"
	fi
fi

if [ "$state" = "UNKNOWN" ]; then
	die "Could not determine state"
fi

# COMMAND state
if [ "$cmd_state" = "true" ]; then
	echo "$state"
	exit_success
fi

# COMMAND commit
if [ "$cmd_commit" = "true" ]; then
	if [ "$state" = "NORMAL" ]; then
		exit_success
	fi
	if [ "$state" != "SWAPPING" -a "$state" != "ROLLBACK" ]; then
		die "Invalid state \""$state"\" for commit"
	fi
	NVRAM_SYSTEM_UNLOCK=16440 nvram --sys \
		--del SYS_BOOT_ATTEMPTS \
		--set SYS_BOOT_PART ${swap} || die "Failed setting nvram variables"
	exit_success
fi

# COMMAND cancel
if [ "$cmd_cancel" = "true" ]; then
	if [ "$state" != "INIT" ]; then
		die "Invalid state \""$state"\" for cancel"
	fi
	NVRAM_SYSTEM_UNLOCK=16440 nvram --sys --set SYS_BOOT_SWAP "$part" || die "Failed setting nvram variable SYS_BOOT_SWAP"
	exit_success
fi

# COMMAND rollback
if [ "$cmd_rollback" = "true" ]; then
	if [ "$state" != "SWAPPING" ]; then
		die "Invalid state \""$state"\" for rollback"
	fi
	NVRAM_SYSTEM_UNLOCK=16440 nvram --sys --set SYS_BOOT_SWAP "$part" || die "Failed setting nvram variable SYS_BOOT_SWAP"
	exit_success
fi

# COMMAND update
if [ "$cmd_update" = "true" ]; then
	if [ "$state" != "NORMAL" ]; then
		die "Invalid state \""$state"\" for update"
	fi
	echo "Current root: ${current_root_label}"
	echo "New root: ${new_root_label}"
	# Create partitions and install image
	read -r -d '' config <<- EOM
partitions:
   - label: "${new_root_label}"
     type: ${filesystem}

images:
   - name: image
     type: ${type}
     target: "label:${new_root_label}"
EOM

	args="--force-unmount --config - image=${image}"
	echo "Partition device and install images.."
	printf '%s\n' "$config"
	if printf '%s\n' "$config" | image-install $args; then
		echo "Success!"
	else
		die "Failed installation"
	fi	
	NVRAM_SYSTEM_UNLOCK=16440 nvram --sys --set SYS_BOOT_SWAP "$new_root_label" || die "Failed setting nvram variable SYS_BOOT_SWAP"
	echo "Image written to new root partition."
	echo "Reboot to swap"
	exit_success
fi

# COMMAND counter
if [ "$cmd_counter" = "true" ]; then
	if [ "x$attempts" = "x" ]; then
		echo 0
	else
		echo "$attempts"
	fi
	exit_success
fi

die "Should not be here"
