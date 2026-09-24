# lease-lint

`lease-lint` is a small Rust CLI for auditing distributed lease and fencing-token logs. It catches actions from stale owners, expired leases, invalid renewals and revocations, regressing epochs, and out-of-order event streams before those records disappear into a larger observability system.

It is intentionally offline: provide newline-delimited JSON and receive a deterministic human or JSON report. No service credentials, database, or network access are required.

## Install

Build from a clone with stable Rust:

```console
cargo install --path .
```

Or run it directly:

```console
cargo run -- examples/healthy.jsonl
```

## Use

Audit a file:

```console
$ lease-lint examples/healthy.jsonl
clean: 5 events across 1 resources
```

Find a stale owner after failover:

```console
$ lease-lint examples/stale-owner.jsonl
2 violations: 3 events across 1 resources
line 3 seq 3 resource "gateway/us-east" [ACTION_WRONG_OWNER] operation "dispatch-job-7" owner "node-a" does not match active owner "node-b"
line 3 seq 3 resource "gateway/us-east" [ACTION_STALE_EPOCH] operation "dispatch-job-7" epoch 41 is stale; active epoch is 42
$ echo $?
2
```

Read standard input and emit structured output:

```console
journal-export | lease-lint - --format json
```

If your system has a documented maximum clock-skew allowance, make it explicit:

```console
lease-lint events.jsonl --grace-ms 25
```

Exit codes are stable for automation:

- `0`: parsed successfully with no violations
- `1`: input, I/O, or JSON error
- `2`: parsed successfully and found at least one violation

## Event format

Every non-empty line is one JSON object with globally increasing `seq`, nondecreasing `at_ms`, and a `resource`. Supported event types are:

```json
{"seq":1,"at_ms":1000,"resource":"gateway","type":"grant","owner":"node-a","epoch":7,"lease_until_ms":5000}
{"seq":2,"at_ms":2000,"resource":"gateway","type":"renew","owner":"node-a","epoch":7,"lease_until_ms":7000}
{"seq":3,"at_ms":3000,"resource":"gateway","type":"action","owner":"node-a","epoch":7,"operation":"dispatch"}
{"seq":4,"at_ms":4000,"resource":"gateway","type":"revoke","owner":"node-a","epoch":7}
```

A new `grant` must use an epoch greater than every earlier grant for that resource. A higher epoch immediately fences the former owner, even if its time lease had not expired. Renewals and revocations must exactly match the current owner and epoch. Actions must match that owner and epoch and occur no later than the deadline plus any explicitly configured grace.

The auditor reports multiple independent problems on one event when useful—for example, a stale owner's action normally violates both owner and epoch rules.

## Development

The repository forbids unsafe Rust and CI runs the same required checks used before publication:

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Scope

`lease-lint` audits recorded events; it does not issue leases, synchronize clocks, enforce fencing at the storage layer, or prove that a log is complete. Correct distributed-system safety still requires the protected resource to reject stale fencing epochs.

## License

MIT
