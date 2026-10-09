#!/usr/bin/env bash
# Remote half of scripts/linux/check.sh, run on the Linux check host; it owns
# everything about a run on the host, so the local side only calls it.
#
#   remote.sh launch <run dir> <bundle ref> device|speculos|golden
#   remote.sh state <run dir>
#   remote.sh stop <run dir> <owner token>
#
# `launch` starts the run detached from the SSH session (setsid, nohup), its
# output appended to <run dir>/run.log; launching again is harmless, because the
# run takes <run dir>/pid exclusively and a second one exits at once. The run
# checks the snapshot out into <run dir>/src, runs the action there and packs
# the device artifacts into <run dir>/artifacts.tar. `speculos` builds as
# `device` does, then runs every build in Speculos (scripts/speculos-check.sh).
# `golden` runs Speculos writing the screen snapshots instead of comparing them,
# and packs tests/snapshots into <run dir>/snapshots.tar. However the run ends,
# its exit status lands in <run dir>/status.
#
# `state` prints `starting` (not launched yet), `running`, `done <status>` or
# `lost` (ended without a status). `stop` stops a live run and its containers,
# then removes <run dir>; a run launched after the stop began does not start;
# the stop fails when anything could not be removed. It acts
# only while <run dir>/owner holds the token it was given, checked again before
# every step that destroys something: a stop delayed past its retry may meet a
# later run under the same name, which it leaves alone.
set -uo pipefail

mode="${1:?mode: launch, state or stop}"
dir="${2:?run dir}"
# Containers carry the run's name, so a stop removes exactly its own.
name=$(basename "$dir")

# Whether <run dir>/pid names a live process of this run: a process id the run
# no longer holds may belong to another process by now.
alive() {
    local pid cmdline
    pid=$(cat "$dir/pid" 2>/dev/null) || return 1
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    # stderr goes first, so a process gone between the checks stays quiet.
    cmdline=$(tr '\0' ' ' 2>/dev/null <"/proc/$pid/cmdline") || return 1
    [[ "$cmdline" == *"$dir/remote.sh run $dir "* ]]
}

# Whether a process of this run is still running: its leader, by its command
# line, or any other member of its process group, by the run name its
# environment carries (CHECK_CONTAINER_PREFIX, exported before the run starts
# anything). Members outlive a leader killed on its own, and a process id or
# group id the run no longer holds may belong to another process by now. A
# zombie does not count: `kill -0` still finds it until its parent reaps it,
# which an orphan in a container without a reaping init never gets.
run_running() {
    alive && return 0
    local group file stat state pgrp pid environment
    group=$(cat "$dir/pid" 2>/dev/null) || return 1
    [[ "$group" =~ ^[0-9]+$ ]] || return 1
    for file in /proc/[0-9]*/stat; do
        # Read by the shell itself: one process per entry would make a scan of a
        # busy host take seconds, and the stop's wait many times its ten seconds.
        { read -r stat <"$file"; } 2>/dev/null || continue
        # The fields after the command name, which may hold spaces and parentheses.
        read -r state _ pgrp _ <<<"${stat##*) }"
        [[ "$pgrp" == "$group" && "$state" != Z ]] || continue
        pid=${file#/proc/}
        pid=${pid%/stat}
        environment=$(tr '\0' '\n' 2>/dev/null <"/proc/$pid/environ") || continue
        if [[ $'\n'"$environment"$'\n' == *$'\n'"CHECK_CONTAINER_PREFIX=$name"$'\n'* ]]; then
            return 0
        fi
    done
    return 1
}

case "$mode" in
    launch)
        setsid nohup bash "$dir/remote.sh" run "$dir" "${3:?ref}" "${4:?action}" \
            >>"$dir/run.log" 2>&1 </dev/null &
        exit 0
        ;;
    state)
        if [[ -f "$dir/status" ]]; then
            echo "done $(cat "$dir/status")"
        elif [[ ! -f "$dir/pid" ]]; then
            echo starting
        elif alive; then
            echo running
        # The run may have written its status just now.
        elif [[ -f "$dir/status" ]]; then
            echo "done $(cat "$dir/status")"
        else
            echo lost
        fi
        exit 0
        ;;
    stop)
        token="${3:?owner token}"
        # The name the run directory is moved to before it is removed.
        removing="$dir.removing"
        # Whether directory $1 carries the owner token this stop was given.
        owned_at() {
            [[ "$(cat "$1/owner" 2>/dev/null)" == "$token" ]]
        }
        # Whether the run directory is still the one this stop was given.
        owned() {
            owned_at "$dir"
        }
        # Removes the moved run directory, its owner token last, so a removal cut
        # off half way still marks it as this run's for a retry. A tree already
        # gone was removed by a concurrent stop of the same run: the host is clean.
        remove_moved() {
            # Files a container wrote as root into the checkout are handed back
            # first: the build returns app/target only when its command ends,
            # which a container removed by force never reaches, and a user other
            # than root cannot remove them. The image is the one the run used.
            if [[ $(id -u) -ne 0 && -d "$removing/src" ]] &&
                ! docker run --rm --security-opt label=disable \
                    --volume "$removing/src:/app" --entrypoint chown \
                    "$(bash "$removing/src/scripts/dev-tools-image.sh")" \
                    -R "$(id -u):$(id -g)" /app >/dev/null; then
                echo "cannot hand back the files containers wrote in $removing" >&2
            fi
            if ! { find "$removing" -mindepth 1 -maxdepth 1 ! -name owner -exec rm -rf {} + &&
                rm -f "$removing/owner" && rmdir "$removing"; } 2>/dev/null &&
                [[ -e "$removing" ]]; then
                echo "cannot remove $removing" >&2
                return 1
            fi
        }
        if ! owned; then
            # A stop cut off during the removal left the run directory under the
            # name it was moved to; this retry finishes it.
            if owned_at "$removing"; then
                remove_moved
                exit
            fi
            exit 0
        fi
        status=0
        # A launch may be under way without its process id file yet. The stop
        # takes that file first, the way a run takes it (a hard link fails on an
        # existing name), so a run arriving later exits at once instead of
        # starting after this stop found nothing running. The file it leaves
        # names no process.
        echo stopped >"$dir/pid.stop.$$" &&
            ln "$dir/pid.stop.$$" "$dir/pid" 2>/dev/null
        rm -f "$dir/pid.stop.$$"
        if run_running; then
            # The run leads its process group (setsid), which its docker clients are in.
            group=$(cat "$dir/pid")
            # SIGTERM first, SIGKILL for what is left after the grace; a run
            # still running after both fails the stop, so its directory and
            # containers are not removed from under it. A run's own self-test
            # (scripts/linux/check-test.sh) keeps fake runs in sessions of their
            # own and stops them on SIGTERM with this same stop, so the stops it
            # makes (CHECK_TEST_NESTED) get ten seconds and a real run's stop
            # thirty, longer than such a nested stop with its escalation.
            grace=30
            if [[ -n "${CHECK_TEST_NESTED:-}" ]]; then
                grace=10
            fi
            for signal in TERM KILL; do
                owned || exit 0
                kill "-$signal" -- "-$group" 2>/dev/null
                # Measured by the clock: a scan of a busy host takes time of its own.
                deadline=$((SECONDS + grace))
                while ((SECONDS < deadline)); do
                    run_running || break 2
                    sleep 0.2
                done
            done
            if run_running; then
                echo "the run's process group $group survived SIGKILL" >&2
                exit 1
            fi
        fi
        # Only a container that does not exist is no error: a daemon that cannot
        # answer leaves the containers unknown. A removal that fails is checked
        # again, since a container run with --rm removes itself when it exits,
        # which can happen between listing and removing it.
        owned || exit 0
        for container in "$name-build" "$name-speculos"; do
            if ! found=$(docker ps --all --quiet --filter "name=^/$container\$"); then
                echo "cannot list containers to remove $container" >&2
                status=1
                continue
            fi
            if [[ -z "$found" ]] || docker rm --force "$container" >/dev/null; then
                continue
            fi
            if ! found=$(docker ps --all --quiet --filter "name=^/$container\$") || [[ -n "$found" ]]; then
                echo "cannot remove container $container" >&2
                status=1
            fi
        done
        # The directory (and its owner token) stays while a container may be
        # left, so a stop retried after a dropped connection tries again instead
        # of finding nothing to clean.
        # The directory is moved away from its name before anything in it is
        # removed: a launch whose run has not taken the process id file yet then
        # finds no run directory and exits, so nothing starts in it while it is
        # removed, the marker this stop left in it included. A move that fails on
        # a directory already gone met a concurrent stop of the same run (a retry
        # while this one still ran), which moved it; this one removes it too.
        # Run names carry 64 random bits, so no other run takes this path between
        # the owner check and the move unless CHECK_RUN_ID names it on purpose.
        if [[ $status -eq 0 ]] && owned; then
            if ! mv -T "$dir" "$removing" 2>/dev/null && [[ -e "$dir" ]]; then
                echo "cannot move $dir away to remove it" >&2
                status=1
            elif ! remove_moved; then
                status=1
            fi
        fi
        exit "$status"
        ;;
    run) ;;
    *)
        echo "unknown mode $mode" >&2
        exit 2
        ;;
esac

ref="${3:?ref}"
action="${4:?action}"

# The process id file is taken exclusively (a hard link fails on an existing
# name), complete from its first moment: a second launch exits here.
echo "$$" >"$dir/pid.$$" || exit 1
if ! ln "$dir/pid.$$" "$dir/pid" 2>/dev/null; then
    rm -f "$dir/pid.$$"
    exit 0
fi
rm -f "$dir/pid.$$"
# Older shellcheck releases report this as SC2317, newer ones as SC2329.
# shellcheck disable=SC2317,SC2329 # called by the EXIT trap
write_status() {
    local code=$?
    # Renamed into place, so a status file is always complete and the log before it final.
    echo "$code" >"$dir/status.tmp" && mv "$dir/status.tmp" "$dir/status"
}
trap write_status EXIT
CHECK_CONTAINER_PREFIX="$name"
export CHECK_CONTAINER_PREFIX

src="$dir/src"
mkdir "$src" || exit 1
cd "$src" || exit 1
git init -q || exit 1
git fetch -q "$dir/snapshot.bundle" "$ref" || exit 1
git checkout -q --detach FETCH_HEAD || exit 1

status=0
case "$action" in
    device | speculos | golden)
        # The check script itself, against a fake host on this machine; not
        # again inside the runs that test makes.
        if [[ -z "${CHECK_TEST_NESTED:-}" ]]; then
            bash scripts/linux/check-test.sh || status=1
        fi
        bash scripts/device-build.sh || status=1
        if [[ "$action" == speculos && $status -eq 0 ]]; then
            bash scripts/speculos-check.sh || status=1
        fi
        if [[ "$action" == golden && $status -eq 0 ]]; then
            SPECULOS_GOLDEN=1 bash scripts/speculos-check.sh || status=1
            tar -c -f "$dir/snapshots.tar" -C tests snapshots || status=1
        fi
        # One directory per target: the ELF and what cargo-ledger derived from it.
        files=()
        for target in nanosplus nanox stax flex apex_p; do
            release="app/target/$target/release"
            for file in "$release"/structured-passkeys-app "$release"/structured-passkeys-app.{hex,apdu,sha256}; do
                [[ -f "$file" ]] && files+=("${file#app/target/}")
            done
        done
        if [[ ${#files[@]} -gt 0 ]]; then
            tar -c -f "$dir/artifacts.tar" -C app/target "${files[@]}" || status=1
        fi
        ;;
    *)
        echo "unknown action $action" >&2
        status=2
        ;;
esac

if [[ $status -eq 0 ]]; then
    echo "== PASSED"
else
    echo "== FAILED"
fi
exit "$status"
