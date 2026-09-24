#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Stdio};

const CLEAN_STREAM: &str = r#"{"seq":1,"at_ms":100,"resource":"gateway","type":"grant","owner":"node-a","epoch":1,"lease_until_ms":200}
{"seq":2,"at_ms":120,"resource":"gateway","type":"action","owner":"node-a","epoch":1,"operation":"dispatch"}
"#;

fn run_with_stdin(args: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lease-lint"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(input.as_bytes())
        .expect("fixture should be written");
    child.wait_with_output().expect("binary should exit")
}

#[test]
fn clean_stream_exits_zero_with_json_summary() {
    let output = run_with_stdin(&["--format", "json"], CLEAN_STREAM);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(stdout.contains("\"events_read\": 2"));
    assert!(stdout.contains("\"violations\": []"));
}

#[test]
fn violation_stream_exits_two() {
    let input = format!(
        "{CLEAN_STREAM}{}\n",
        r#"{"seq":3,"at_ms":220,"resource":"gateway","type":"action","owner":"node-a","epoch":1,"operation":"late-write"}"#
    );
    let output = run_with_stdin(&[], &input);
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(stdout.contains("[ACTION_AFTER_EXPIRY]"));
}

#[test]
fn malformed_stream_exits_one() {
    let output = run_with_stdin(&[], "not-json\n");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(stderr.contains("invalid JSON on non-empty line 1"));
}
