#!/usr/bin/env bash
# Tests scripts/linux/check.sh against a fake check host on this machine: an
# `ssh` that runs each command locally and drops chosen connections, and a
# `docker` whose build writes the artifacts after a delay. Linux only, like the
# check host itself (setsid, /proc).
#
#   scripts/linux/check-test.sh
#
# Cases:
#   - connections dropped before and after their command ran, the start of the
#     run among them: the run completes once, its artifacts come back and the
#     host is left clean;
#   - a run that dies without writing its status: the check fails instead of
#     polling forever, and the host is left clean;
#   - a stopped check (SIGTERM; a background job of this script ignores
#     SIGINT) whose run ignores SIGTERM: the remote run and its directory are
#     gone;
#   - a run whose leader is killed while its container runs: the check fails
#     and the container is stopped;
#   - a run directory left on the host under the same name is neither taken
#     over nor removed, while an empty one without an owner is taken;
#   - a container that goes between its listing and its removal does not fail
#     the cleanup, and a cleanup that cannot remove the containers keeps
#     failing across a dropped connection;
#   - a stop that carries another run's owner token touches nothing;
#   - a run launched after its stop began exits without starting;
#   - a stop that finds its run directory removed by a concurrent stop of the
#     same run succeeds;
#   - a process group whose only member is a zombie counts as stopped;
#   - the checkout the test runs from keeps its artifacts: the checks run in a
#     copy of the scripts.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d)
check=""
# A stop the concurrent-stop case holds in the fake find, the directory it
# waits in, and the run directory it works on; the late-launch case's run
# directory, which lives outside $tmp.
held_stop=""
hold=""
twice=""
late=""
# A check still running is stopped before the fake host it uses goes: without
# its fake ssh it could not clean up its run. A held stop is released and
# reaped first, since removing $tmp would leave it waiting for good.
# Older shellcheck releases report this as SC2317, newer ones as SC2329.
# shellcheck disable=SC2317,SC2329 # called by the EXIT trap
finish() {
    local code=$?
    if [[ -n "$held_stop" ]] && kill -0 "$held_stop" 2>/dev/null; then
        touch "$hold/release" 2>/dev/null || true
        kill -TERM "$held_stop" 2>/dev/null || true
        wait "$held_stop" 2>/dev/null || true
    fi
    if [[ -n "$check" ]] && kill -0 "$check" 2>/dev/null; then
        kill -TERM "$check" 2>/dev/null || true
        wait "$check" 2>/dev/null || true
    fi
    [[ -n "$twice" ]] && rm -rf "$twice"
    [[ -n "$late" ]] && rm -rf "$late"
    rm -rf "$tmp"
    exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$tmp/bin"

# The checks run in a copy of the scripts as a repository of its own, so the
# fake artifacts they fetch never replace the artifacts of the checkout under
# test.
repo="$tmp/repo"
mkdir "$repo"
cp -R "$root/scripts" "$repo/"
git -C "$repo" init -q
git -C "$repo" add -A
git -C "$repo" -c user.name=check-test -c user.email=check-test@localhost commit -qm scripts

# ssh [options] <destination> <command>: runs the command here. The calls whose
# numbers FAKE_SSH_DROPS lists ("3b,5a": call 3 drops before its command runs,
# call 5 after) end with 255, as ssh does on a lost connection.
cat >"$tmp/bin/ssh" <<'EOF'
#!/usr/bin/env bash
command="${!#}"
count_file="$FAKE_HOST_STATE/ssh-calls"
call=$(( $(cat "$count_file" 2>/dev/null || echo 0) + 1 ))
echo "$call" >"$count_file"
# The first command containing FAKE_SSH_DROP_AFTER runs, then its connection drops.
if [[ -n "${FAKE_SSH_DROP_AFTER:-}" && "$command" == *"$FAKE_SSH_DROP_AFTER"* &&
    ! -e "$FAKE_HOST_STATE/dropped-after" ]]; then
    touch "$FAKE_HOST_STATE/dropped-after"
    bash -c "$command" >/dev/null 2>&1 || true
    exit 255
fi
for drop in ${FAKE_SSH_DROPS//,/ }; do
    if [[ "$drop" == "${call}b" ]]; then
        exit 255
    fi
    if [[ "$drop" == "${call}a" ]]; then
        bash -c "$command" >/dev/null 2>&1 || true
        exit 255
    fi
done
exec bash -c "$command"
EOF

# docker pull|run|ps|rm: `run` writes every target's artifacts into the mounted
# checkout after FAKE_DOCKER_SECONDS, ignoring SIGTERM with FAKE_DOCKER_IGNORE_TERM;
# `ps` knows no containers.
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    run)
        if [[ -n "${FAKE_DOCKER_IGNORE_TERM:-}" ]]; then
            trap '' TERM
        fi
        shift
        app=""
        while [[ $# -gt 0 ]]; do
            if [[ "$1" == --volume ]]; then
                app="${2%%:*}"
                shift
            fi
            shift
        done
        echo "fake container"
        sleep "${FAKE_DOCKER_SECONDS:-0}"
        for target in nanosplus nanox stax flex apex_p; do
            release="$app/app/target/$target/release"
            mkdir -p "$release"
            for file in structured-passkeys-app structured-passkeys-app.hex structured-passkeys-app.apdu structured-passkeys-app.sha256; do
                echo "$target" >"$release/$file"
            done
        done
        ;;
    # With FAKE_DOCKER_RACE a container is listed once and gone when removed, as
    # one that exits in between under --rm.
    ps)
        # With FAKE_DOCKER_PS_FAIL the daemon cannot answer.
        if [[ -n "${FAKE_DOCKER_PS_FAIL:-}" ]]; then
            echo "Cannot connect to the Docker daemon" >&2
            exit 1
        fi
        if [[ -n "${FAKE_DOCKER_RACE:-}" && ! -e "$FAKE_HOST_STATE/listed" ]]; then
            touch "$FAKE_HOST_STATE/listed"
            echo 0123456789ab
        fi
        ;;
    rm)
        if [[ -n "${FAKE_DOCKER_RACE:-}" ]]; then
            echo "Error response from daemon: No such container" >&2
            exit 1
        fi
        ;;
    pull) ;;
    *) exit 1 ;;
esac
EOF
# find: with FAKE_FIND_HOLD (a directory) it marks itself held there and waits
# for a release file before running, so a test can finish a second stop inside
# a first one's removal; without it, the real find, wherever this host's PATH
# has it.
FAKE_REAL_FIND=$(command -v find)
export FAKE_REAL_FIND
cat >"$tmp/bin/find" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${FAKE_FIND_HOLD:-}" ]]; then
    touch "$FAKE_FIND_HOLD/held"
    until [[ -e "$FAKE_FIND_HOLD/release" ]]; do
        sleep 0.1
    done
fi
exec "$FAKE_REAL_FIND" "$@"
EOF
chmod +x "$tmp/bin/ssh" "$tmp/bin/docker" "$tmp/bin/find"
export PATH="$tmp/bin:$PATH"
export STRUCTURED_PASSKEYS_LINUX=fake-host
# The fake host is this machine, so its runs see this: they skip this test.
export CHECK_TEST_NESTED=1
# A connection that stays down ends the check quickly here.
export CHECK_RECONNECT_SECONDS=20

# The checkout this test runs from keeps its own artifacts.
artifacts_before=$(ls -lR "$root/target/device" 2>&1 || true)

failures=0
fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

# Starts one check in the background with fresh fake host state; sets `check`
# (its process id) and `out` (its output file).
start_check() {
    local name=$1
    export FAKE_HOST_STATE="$tmp/$name"
    mkdir -p "$FAKE_HOST_STATE"
    out="$tmp/$name.out"
    (cd "$repo" && exec scripts/linux/check.sh device) >"$out" 2>&1 &
    check=$!
}

# The remote directory the check reported, once it did.
run_dir() {
    sed -n 's/^remote run in fake-host://p' "$out"
}

# Waits up to $1 seconds for the command after it to succeed.
wait_for() {
    local deadline=$((SECONDS + $1))
    shift
    until "$@"; do
        if ((SECONDS >= deadline)); then
            return 1
        fi
        sleep 0.2
    done
}

# The run reported its directory and took its process id file there.
run_started() {
    local dir
    dir=$(run_dir)
    [[ -n "$dir" && -f "$dir/pid" ]]
}

# The run's fake container has started.
container_started() {
    grep -qs '^fake container$' "$(run_dir)/run.log"
}

# The check process has ended.
check_ended() {
    ! kill -0 "$check" 2>/dev/null
}

# The process group $1 has no process left running. A zombie member does not
# count: `kill -0` still finds it until its parent reaps it, which an orphan in
# a container without a reaping init never gets.
group_gone() {
    local file stat state pgrp
    for file in /proc/[0-9]*/stat; do
        # Read by the shell itself: one process per entry makes a scan slow.
        { read -r stat <"$file"; } 2>/dev/null || continue
        # The fields after the command name, which may hold spaces and parentheses.
        read -r state _ pgrp _ <<<"${stat##*) }"
        if [[ "$pgrp" == "$1" && "$state" != Z ]]; then
            return 1
        fi
    done
}

# A group whose only process is a zombie has nothing left running: where no init
# reaps orphans (a container), a stopped run stays a zombie. The setsid child
# below leads its own group and exits; its parent, replaced by sleep, never
# reaps it.
bash -c 'setsid sleep 0 & echo "$!" >"$1"; exec sleep 3' _ "$tmp/zombie" &
holder=$!
sleep 0.5
zombie=$(cat "$tmp/zombie")
if kill -0 -- "-$zombie" 2>/dev/null; then
    group_gone "$zombie" || fail "zombie: a group of a zombie counts as running"
fi
wait "$holder" || true

# Dropped connections: the snapshot upload, the start (after it ran), and polls.
FAKE_SSH_DROPS="2b,4a,6b,7a,9b" FAKE_DOCKER_SECONDS=3 start_check drops
if wait "$check"; then
    dir=$(run_dir)
    [[ $(grep -c '^== PASSED' "$out") -eq 1 ]] || fail "drops: the run did not complete exactly once"
    [[ -f "$repo/target/device/apex_p/release/structured-passkeys-app" ]] || fail "drops: no artifacts"
    [[ -n "$dir" && ! -e "$dir" ]] || fail "drops: $dir left on the host"
else
    fail "drops: the check failed"
    cat "$out" >&2
fi

# A run killed before it writes its status.
FAKE_SSH_DROPS="" FAKE_DOCKER_SECONDS=30 start_check lost
if wait_for 30 run_started; then
    dir=$(run_dir)
    kill -KILL -- "-$(cat "$dir/pid")"
    if wait_for 40 check_ended; then
        wait "$check" && fail "lost: the check passed"
        [[ ! -e "$dir" ]] || fail "lost: $dir left on the host"
    else
        fail "lost: the check kept polling a dead run"
        kill -TERM "$check"
        wait "$check" || true
    fi
else
    fail "lost: the run did not start"
    kill -TERM "$check" 2>/dev/null || true
    wait "$check" || true
fi

# A run whose leader is killed while its container still runs: the check
# fails, and stopping it ends what is left of the run.
FAKE_SSH_DROPS="" FAKE_DOCKER_SECONDS=30 start_check orphaned
if wait_for 30 run_started && wait_for 30 container_started; then
    dir=$(run_dir)
    group=$(cat "$dir/pid")
    kill -KILL "$group"
    if wait_for 40 check_ended; then
        wait "$check" && fail "orphaned: the check passed"
        [[ ! -e "$dir" ]] || fail "orphaned: $dir left on the host"
        wait_for 10 group_gone "$group" || fail "orphaned: the run's container is still alive"
    else
        fail "orphaned: the check kept polling a run without its leader"
        kill -TERM "$check"
        wait "$check" || true
    fi
else
    fail "orphaned: the run did not start"
    kill -TERM "$check" 2>/dev/null || true
    wait "$check" || true
fi

# A run directory already on the host under the run's name (left by an earlier
# run that was cut off) is not taken over, nor removed.
stale="/tmp/structured-passkeys-check-test-stale-$$"
mkdir -m 700 "$stale"
echo 0 >"$stale/status"
echo stale >"$stale/artifacts.tar"
FAKE_SSH_DROPS="" CHECK_RUN_ID=$(basename "$stale") start_check stale
wait "$check" && fail "stale: the check took over $stale"
[[ "$(cat "$stale/status" 2>/dev/null)" == 0 ]] || fail "stale: $stale was changed or removed"
rm -rf "$stale"

# An empty run directory without an owner, as a first attempt cut off between
# creating it and marking it leaves, is taken; the run passes and nothing stays.
empty="/tmp/structured-passkeys-check-test-empty-$$"
mkdir -m 700 "$empty"
FAKE_SSH_DROPS="" CHECK_RUN_ID=$(basename "$empty") start_check empty
wait "$check" || fail "empty: the check failed on its own unmarked directory"
if [[ -e "$empty" ]] || compgen -G "$empty.new.*" >/dev/null; then
    fail "empty: $empty left on the host"
fi
rm -rf "$empty" "$empty".new.*

# A container that goes between listing and removal is no cleanup failure.
FAKE_SSH_DROPS="" FAKE_DOCKER_RACE=1 start_check race
wait "$check" || fail "race: a container gone before its removal failed the cleanup"

# A cleanup that cannot remove the containers keeps failing when its connection
# drops after it ran: the retry finds the run still to clean, not a clean host.
FAKE_SSH_DROPS="" FAKE_DOCKER_PS_FAIL=1 FAKE_SSH_DROP_AFTER="remote.sh stop" start_check cleanup
if wait "$check"; then
    fail "cleanup: the check passed with its containers unknown"
fi
dir=$(run_dir)
[[ -n "$dir" ]] && rm -rf "$dir"

# A stop that carries another run's owner token touches nothing: a cleanup
# delayed past its retry may meet a later run under the same name.
foreign="/tmp/structured-passkeys-check-test-foreign-$$"
mkdir -m 700 "$foreign"
cp "$repo/scripts/linux/remote.sh" "$foreign/remote.sh"
echo later-run >"$foreign/owner"
# A stand-in for the later run: its command line names it as remote.sh run does.
setsid bash -c 'sleep 30; : '"$foreign/remote.sh run $foreign "'x' >/dev/null 2>&1 &
launched=$!
# Killed by this test below: no job report for it.
disown
stand_in=""
# Sets `stand_in` once the stand-in runs under its command line.
find_stand_in() {
    stand_in=$(pgrep -f "$foreign/remote.sh run $foreign " | head -n 1) || return 1
    [[ -n "$stand_in" ]]
}
if wait_for 10 find_stand_in; then
    echo "$stand_in" >"$foreign/pid"
    bash "$foreign/remote.sh" stop "$foreign" earlier-run || true
    kill -0 "$stand_in" 2>/dev/null || fail "foreign: a stop with another token stopped the run"
    [[ -f "$foreign/owner" ]] || fail "foreign: a stop with another token removed the run directory"
    kill -KILL -- "-$stand_in" 2>/dev/null || true
else
    fail "foreign: the stand-in never started"
    kill -KILL -- "-$launched" 2>/dev/null || kill -KILL "$launched" 2>/dev/null || true
fi
rm -rf "$foreign"

# A stop that meets a launch which has not taken the process id file yet: the
# stop takes it first, so the late run exits at once instead of starting after
# the stop declared it gone. The containers stay unknown here, so the stop keeps
# the directory and the late run has somewhere to start.
late="/tmp/structured-passkeys-check-test-late-$$"
mkdir -m 700 "$late"
cp "$repo/scripts/linux/remote.sh" "$late/remote.sh"
echo this-run >"$late/owner"
FAKE_DOCKER_PS_FAIL=1 bash "$late/remote.sh" stop "$late" this-run 2>/dev/null &&
    fail "late: a stop with its containers unknown passed"
bash "$late/remote.sh" run "$late" ref device >/dev/null 2>&1 || true
if [[ -e "$late/src" || -e "$late/status" ]]; then
    fail "late: a run launched after the stop started"
fi
rm -rf "$late"

# Two stops of one run, as a retry after a dropped connection leaves the first
# still going: the one that finds the directory already removed by the other
# succeeds, since the host is clean.
twice="/tmp/structured-passkeys-check-test-twice-$$"
mkdir -m 700 "$twice"
cp "$repo/scripts/linux/remote.sh" "$twice/remote.sh"
echo this-run >"$twice/owner"
hold="$tmp/twice-hold"
mkdir "$hold"
FAKE_FIND_HOLD="$hold" bash "$twice/remote.sh" stop "$twice" this-run &
held_stop=$!
if wait_for 10 test -e "$hold/held"; then
    bash "$twice/remote.sh" stop "$twice" this-run || fail "twice: the second stop failed"
    touch "$hold/release"
    wait "$held_stop" || fail "twice: a stop failed on a directory the other stop removed"
    [[ ! -e "$twice" ]] || fail "twice: $twice left on the host"
else
    fail "twice: the first stop never reached the removal"
    touch "$hold/release"
    wait "$held_stop" || true
fi
held_stop=""
rm -rf "$twice"
twice=""

# A stopped check, its run ignoring SIGTERM.
FAKE_SSH_DROPS="" FAKE_DOCKER_SECONDS=30 FAKE_DOCKER_IGNORE_TERM=1 start_check stopped
if wait_for 30 run_started && wait_for 30 container_started; then
    dir=$(run_dir)
    group=$(cat "$dir/pid")
    kill -TERM "$check"
    wait "$check" && fail "stopped: the check passed"
    [[ ! -e "$dir" ]] || fail "stopped: $dir left on the host"
    wait_for 10 group_gone "$group" || fail "stopped: the remote run is still alive"
else
    fail "stopped: the run did not start"
    kill -TERM "$check" 2>/dev/null || true
    wait "$check" || true
fi

[[ "$(ls -lR "$root/target/device" 2>&1 || true)" == "$artifacts_before" ]] ||
    fail "the artifacts of the checkout under test changed"

if [[ $failures -ne 0 ]]; then
    echo "$failures check-test failures" >&2
    exit 1
fi
echo "check-test: all cases pass"
