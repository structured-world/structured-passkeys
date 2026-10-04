#!/usr/bin/env bash
# Runs the checks that need Ledger's Linux dev-tools image on the project's
# Linux check host over SSH, without pushing anything.
#
#   STRUCTURED_PASSKEYS_LINUX=<ssh destination> scripts/linux/check.sh device|speculos|golden
#
# `device` builds and lints the device application for every target
# (scripts/device-build.sh) and copies the artifacts back into
# target/device/<target>/ of this checkout. `speculos` does the same, then runs
# every build in Speculos (scripts/speculos-check.sh). `golden` runs Speculos
# writing the screen snapshots and copies them into tests/snapshots/.
#
# The working tree is snapshotted as it is, uncommitted and untracked files
# included (ignored files excluded), through a temporary index: HEAD, the index
# and the files of the checkout stay untouched. The snapshot travels as a git
# bundle into a directory of this run's own, so runs started at the same time
# do not meet. Everything the run put on the host is removed afterwards
# whatever the result, and a failed removal fails the run, since the host is
# shared. The dev-tools image itself stays: it is a tool the host keeps, like a
# toolchain.
#
# The connection to the host may drop at any time, so the run does not live in
# an SSH session: it starts detached on the host and writes its log and exit
# status into its directory there. This side follows the log by polling and
# reconnects after a dropped connection, for up to CHECK_RECONNECT_SECONDS
# (default 1800) without a successful connection. A stopped run (Ctrl-C) stops
# the remote run and its containers too.
#
# STRUCTURED_PASSKEYS_LINUX is an SSH destination that can run docker.
set -euo pipefail

destination="${STRUCTURED_PASSKEYS_LINUX:?set STRUCTURED_PASSKEYS_LINUX to the SSH destination of the Linux check host}"
action="${1:?action: device}"
reconnect_seconds="${CHECK_RECONNECT_SECONDS:-1800}"
# Decimal seconds up to a week: the value goes into arithmetic, where a leading
# zero reads as octal and anything else is no number.
if [[ ! "$reconnect_seconds" =~ ^(0|[1-9][0-9]{0,5})$ ]] || ((reconnect_seconds > 604800)); then
    echo "CHECK_RECONNECT_SECONDS must be whole seconds from 0 to 604800" >&2
    exit 2
fi

case "$action" in
    device | speculos | golden) ;;
    *)
        echo "unknown action $action: device, speculos, golden" >&2
        exit 2
        ;;
esac

root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
ref="refs/structured-passkeys-check/snapshot-$$"
# ConnectTimeout bounds only the connection setup; the server-alive probes end a
# session whose network went silent instead of waiting for the TCP timeout.
ssh_options=(-o BatchMode=yes -o LogLevel=ERROR -o ConnectTimeout=15
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3)
# Random, not the local process id: runs from different machines must not meet
# under one name. The directory is taken below only if it does not exist yet.
# CHECK_RUN_ID names the run instead, for the tests of this script.
run_id="${CHECK_RUN_ID:-structured-passkeys-check-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')}"
remote_dir="/tmp/$run_id"
# Marks the remote directory as this run's.
owner=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
# The run directory is built here before it is renamed into place; the token
# keeps it this run's alone.
staging="$remote_dir.new.$owner"
# Set while the remote directory may exist.
remote_pending=0

# Runs one idempotent command on the host, reconnecting after a dropped
# connection until it ran or the connection stayed down for $reconnect_seconds;
# returns the command's status, 255 when it never ran (ssh exits 255 when the
# connection failed). The command reads the file $2 (nothing without it) and
# writes into the file $3 (this script's output without it); both are opened
# anew for every attempt, so a retry neither sends nor keeps a partial stream.
# shellcheck disable=SC2029 # the commands are built here, paths expanded on purpose
remote() {
    local since=$SECONDS rc
    while :; do
        rc=0
        if [[ -n "${3:-}" ]]; then
            ssh "${ssh_options[@]}" "$destination" "$1" <"${2:-/dev/null}" >"$3" || rc=$?
        else
            ssh "${ssh_options[@]}" "$destination" "$1" <"${2:-/dev/null}" || rc=$?
        fi
        if [[ $rc -ne 255 ]]; then
            return "$rc"
        fi
        if ((SECONDS - since >= reconnect_seconds)); then
            echo "no connection to $destination for ${reconnect_seconds}s" >&2
            return 255
        fi
        sleep 5
    done
}

# Uploads the local file $1 to the remote path $2. Every attempt writes a file of
# its own and installs it only when it arrived whole (cksum, which counts the
# bytes too): an attempt whose connection was cut can still run on the host
# after its retry, and must not replace the file with a truncated one.
# shellcheck disable=SC2029 # the command is built here, paths expanded on purpose
upload() {
    local sum
    sum=$(cksum <"$1")
    # Installed only into a directory that is still this run's.
    remote "part=$2.part.\$\$; cat > \$part && [ \"\$(cksum < \$part)\" = \"$sum\" ] &&
        [ \"\$(cat $remote_dir/owner 2>/dev/null)\" = $owner ] &&
        mv -f \$part $2 || { rm -f \$part; exit 1; }" "$1"
}

# Removes the local snapshot and the remote directory, through `remote.sh stop`
# once it is there, which first stops a run still alive and its containers; a
# failed remote removal fails the run.
# Older shellcheck releases report this as SC2317, newer ones as SC2329.
# shellcheck disable=SC2317,SC2329 # called by the EXIT trap
cleanup() {
    local rc=$?
    # The ref is absent when the run stopped before creating it.
    git -C "$root" update-ref -d "$ref" 2>/dev/null || true
    rm -rf "$work"
    if [[ $remote_pending -eq 1 ]]; then
        # Only a directory this run owns goes; remote.sh runs with bash explicitly,
        # since the account's login shell may be any POSIX shell.
        # The staging directory carries this run's token and holds nothing else.
        # A setup or upload cut off here may still finish on the host after this,
        # leaving the token and the snapshot or remote.sh but never a run, which
        # this project's own host clears with its /tmp ageing.
        if ! remote "rm -rf $staging; if [ \"\$(cat $remote_dir/owner 2>/dev/null)\" != $owner ]; then exit 0;
            elif [ -f $remote_dir/remote.sh ]; then bash $remote_dir/remote.sh stop $remote_dir $owner;
            else find $remote_dir -mindepth 1 -maxdepth 1 ! -name owner -exec rm -rf {} + &&
                rm -f $remote_dir/owner && rmdir $remote_dir; fi"; then
            echo "remote directory $remote_dir could not be removed" >&2
            rc=1
        fi
    fi
    exit "$rc"
}
trap cleanup EXIT
# A stopped run cleans up too: the signal ends the script through `exit`, which runs the EXIT
# trap, instead of killing it before the host is cleared.
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Snapshot through a temporary index so the real index is not touched.
export GIT_INDEX_FILE="$work/index"
git -C "$root" read-tree HEAD
git -C "$root" add -A
tree=$(git -C "$root" write-tree)
unset GIT_INDEX_FILE
# The snapshot commit never leaves this run and represents no one, so it carries a
# fixed identity: a machine without user.name/user.email must still run the gate.
# It has no parent: the host checks out the tree alone, so the bundle carries no
# history, which a shallow clone (CI) would not have to give.
commit=$(GIT_AUTHOR_NAME=snapshot GIT_AUTHOR_EMAIL=snapshot@localhost \
    GIT_COMMITTER_NAME=snapshot GIT_COMMITTER_EMAIL=snapshot@localhost \
    git -C "$root" commit-tree "$tree" -m "working tree snapshot")
git -C "$root" update-ref "$ref" "$commit"
git -C "$root" bundle create "$work/snapshot.bundle" "$ref" 2>/dev/null
# The remote half comes from the snapshot, so the run executes exactly the tree
# it reports.
git -C "$root" show "$commit:scripts/linux/remote.sh" >"$work/remote.sh"

# Pending before the directory is made: its connection may drop after it
# exists, and the cleanup removes a directory only when it holds this run's
# owner token. The directory is built with its token under a staging name and
# renamed into place in one step, so it never exists without the token; a retry
# finds it marked as this run's, or rebuilds the staging directory and renames
# again. The rename takes an empty directory, which holds nothing of any run,
# and fails on a directory an earlier run left with its files, which is refused.
remote_pending=1
# An attempt cut off on this side may still run on the host and rename first,
# so a failed rename looks at the owner again.
if ! remote "[ \"\$(cat $remote_dir/owner 2>/dev/null)\" = $owner ] || {
    mkdir -p -m 700 $staging && echo $owner > $staging/owner &&
    mv -T $staging $remote_dir 2>/dev/null; } ||
    [ \"\$(cat $remote_dir/owner 2>/dev/null)\" = $owner ]"; then
    echo "$destination:$remote_dir exists already and is not this run's" >&2
    exit 1
fi
upload "$work/snapshot.bundle" "$remote_dir/snapshot.bundle"
upload "$work/remote.sh" "$remote_dir/remote.sh"

echo "snapshot ${commit:0:12} of $(git -C "$root" rev-parse --short HEAD) with local changes"
echo "remote run in $destination:$remote_dir"
launch="bash $remote_dir/remote.sh launch $remote_dir $ref $action"
remote "$launch"

# Shows the log from the byte already shown; returns non-zero when the host
# stayed out of reach.
shown=0
follow() {
    local chunk="$work/chunk" size
    remote "tail -c +$((shown + 1)) $remote_dir/run.log 2>/dev/null || true" "" "$chunk" || return 1
    size=$(wc -c <"$chunk" | tr -d ' ')
    cat "$chunk"
    shown=$((shown + size))
}
# The status appears after the last line of the log, so one more read after it
# shows the rest. A run that is not there yet is launched again: the launch may
# have been lost with its connection, and a second one exits at once when the
# first runs. A run that ended without a status (killed on the host) fails the
# check instead of being waited for.
status=""
starting_since=$SECONDS
while :; do
    if ! follow || ! remote "bash $remote_dir/remote.sh state $remote_dir" "" "$work/state"; then
        echo "lost $destination; stopping the remote run" >&2
        exit 1
    fi
    state=$(cat "$work/state")
    case "$state" in
        "done "*)
            status=${state#done }
            follow || true
            break
            ;;
        running) ;;
        starting)
            if ((SECONDS - starting_since >= 120)); then
                echo "the remote run did not start" >&2
                exit 1
            fi
            remote "$launch"
            ;;
        *)
            follow || true
            echo "the remote run ended without a status ($state)" >&2
            exit 1
            ;;
    esac
    sleep 5
done

# Artifacts come back even from a failed run: the targets that built are worth
# looking at.
artifacts="$root/target/device"
rm -rf "$artifacts"
mkdir -p "$artifacts"
if remote "test -f $remote_dir/artifacts.tar && cat $remote_dir/artifacts.tar" "" "$work/artifacts.tar" &&
    [[ -s "$work/artifacts.tar" ]]; then
    tar -x -f "$work/artifacts.tar" -C "$artifacts"
    echo "artifacts in $artifacts"
else
    echo "no artifacts came back" >&2
    status=1
fi
if [[ "$action" == golden ]]; then
    if remote "test -f $remote_dir/snapshots.tar && cat $remote_dir/snapshots.tar" "" "$work/snapshots.tar" &&
        [[ -s "$work/snapshots.tar" ]]; then
        mkdir -p "$root/tests"
        tar -x -f "$work/snapshots.tar" -C "$root/tests"
        echo "snapshots in $root/tests/snapshots"
    else
        echo "no snapshots came back" >&2
        status=1
    fi
fi
exit "$status"
