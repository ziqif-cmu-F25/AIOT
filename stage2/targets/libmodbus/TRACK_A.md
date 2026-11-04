# Track A tooling — traditional (human) investigation of the libmodbus target

Track A is the human-led workflow that Track B's AI assistance is compared
against. This file is the tooling guide: how to start the target, drive it,
and log an investigation in the shared run-directory shape. The analysis is
the analyst's; this just makes the hands-on steps repeatable.

A worked, light example is committed at `results/track-a/run-001/`
(notes.md walks the seven pipeline steps and marks where AI assists).

## Set up

```sh
python -m venv ../../.venv            # if not already (repo-root .env holds the key for Track B)
../../.venv/Scripts/python -m pip install -r ../../requirements.txt
```

Build the targets (once):

```sh
docker compose build                              # v3.1.10 (CVE-2024-10918, source-review case)
docker compose --profile fuzz build target-0367   # v3.1.6  (CVE-2022-0367, network-reachable)
```

## Start a run

```sh
python run_new.py --track track-a        # prints results/track-a/run-NNN
```

Each run dir has `inputs/`, `outputs/`, `run.yaml`, `notes.md`, `findings.md`,
`commands.log`. Record commands and observations as you go; `modbus_client.py`
appends to `commands.log` when given `--run-dir`.

## Drive the target (black-box)

The stock server binds 127.0.0.1, so drive it from inside the container. It
serves one connection then exits, so use a fresh instance per attempt (this is
also the correct replay discipline). Pattern used by run-001:

```sh
# inside the v3.1.6 container: start server in background, then send a frame
/usr/local/bin/unit-test-server tcp &
python3 /opt/lab/modbus_client.py \
  --run-dir /workspace/results/track-a/run-001 --timeout 2 \
  send --input <frame.hex> \
  --output-dir /workspace/results/track-a/run-001/outputs --stem <name>
```

The observation JSON records `response_hex` (a normal reply), `timed_out`, or
`server_dropped`/`eof`/`connection_reset`. A dropped connection is the
black-box crash signal; confirm it is a real memory-safety crash (white-box)
by checking the server's ASan output, not by the dropped connection alone.

Seed frames in `harness/inputs/` (benign Read Holding Registers, Write Single
Coil, Read/Write Multiple Registers). Build malformed/boundary frames by hand
or with `harness/modbus_fuzz.py`.

## White-box evidence (oracle)

Both images are ASan builds, so a memory-safety violation aborts the server
with a sanitizer report (the runtime oracle). Capture the server's stderr and
look for `AddressSanitizer: … in modbus_reply`. Validate a finding by replaying
the saved input against a freshly started instance and confirming the same
report (Procedure Phase 2).

## Where this feeds Stage 2

`results/track-a/run-001/notes.md` maps the AI-assist opportunity at each of
the seven pipeline steps and records, for the steps Track B measured, how well
AI actually did (strong at explaining the ASan crash; weak at source-only
discovery and at generating a working reproducer). That map is the Stage 2
shortlist input.
