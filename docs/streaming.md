# PostgreSQL export completion protocol

## What is checked

A clean Docker frame-boundary EOF plus a successful `exec` exit does not prove the entire stdout arrived. An isolated regression against the previous implementation delivered only 32768 of 40960 bytes while `StreamDump` returned success. This is a production-path unit counterexample; it does not establish corruption of a particular historical hosted snapshot.

The export now uses a fixed `/bin/sh -c` script and positional arguments:

1. Execute the existing `/usr/local/bin/pg_dump` with the original literal conninfo and custom-format/compression arguments.
2. Set `BAKABEL_RUN_ID` and `PGAPPNAME` only for that child. The shell itself has empty run tags, so source process scanning still selects only `pg_dump`.
3. Preserve a nonzero child exit code without printing completion.
4. After child exit zero, append `NUL BAKABEL_EXPORT_COMPLETE_V1: <run ID> NUL` on the **same stdout**, using the shell builtin `printf`. Its failure also makes the wrapper fail. Nothing follows on stdout.

The helper validates the exact source/exec and fixed script/full argument list, forwards archive bytes under backpressure, and retains only a trailer-sized tail plus the five-byte `PGDMP` header check. It requires the exact final trailer and terminal exec exit zero. The trailer is removed before Restic sees the stream. Missing/partial/wrong-run trailers, trailing stdout, malformed/truncated Docker frames, downstream write failure and nonzero/unknown exec status fail export. No full-dump staging, new source binary, daemon, FIFO, source file or configuration knob is added.

Cancellation still signals only a verified child PID/start time/run, never the shell or source container. A running wrapper can temporarily have no visible child before launch or after exit. That observation requires bounded re-observation; it is not terminal proof. Ownership may be released only after exact exec termination, no run-tagged export processes and no run-tagged PostgreSQL sessions, or proven termination of the original source. Unavailable/ambiguous evidence retains quarantine. Tightly matched legacy direct-`pg_dump` execs can be cleaned up, but cannot enter the new successful streaming path.

## Guarantee and assumptions

This is a **run-correlated completion check for suffix loss on a trusted ordered byte stream**, not a cryptographic byte-count/digest or arbitrary-corruption proof. The production workflow creates run IDs from 16 bytes of `crypto/rand` (`internal/app/workflow.go`), not source labels. The exact exec, full argv and run are checked together.

The check assumes the producer/archive is not adaptively constructed to contain this run's exact completion marker. Arbitrary binary data has no intrinsically reserved NUL sequence: a prefix ending in an embedded identical marker could pass a suffix check. Random per-run identity makes accidental collision implausible, not mathematically impossible. Middle-byte deletion/reordering preserving the final marker and an adversarial rewriting Docker proxy are not detected by this protocol. Do not describe it as an authenticated archive or a deterministic integrity proof for every possible binary payload. Restic protects the bytes it actually receives; it cannot prove upstream bytes were never omitted.

## Verification boundaries

Focused unit tests exercise full 40960-byte delivery, 32768-byte frame-boundary and mid-frame cuts, every suffix cut/split of a control stream, wrong-run/trailing markers, sink errors and child failure. A POSIX-shell test executes the actual fixed script with a synthetic `pg_dump` replacement and hostile literal connection values; it is not a real PostgreSQL acceptance test.

The changed Go source invalidates reuse of the old Astra R3 fingerprint or old image as certification of this candidate. A fresh exact-source build, independent review and real `pg_dump → helper → Restic → restore` plus cancellation/fault acceptance are required. Historical failed runs remain failed; local tests do not close hosted release gates.
