//! E7 codec micro-benchmarks over the Z1 pinned wire fixtures
//! (docs/interop/zapi-10.2-pinned.md capture corpus — the same
//! ground truth `tests/golden.rs` asserts byte-identical re-encode
//! against). Descriptive numbers only; recorded in
//! docs/benchmarks.md §R (plan decision D2: criterion on the zapi
//! crate first).
//!
//! `cargo bench -p zapi`

use bytes::BytesMut;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::path::Path;
use zapi::ZapiMessage;

struct FixtureMessage {
    cmd: u16,
    body: Vec<u8>,
}

/// The zapi-sniff capture log format (see tests/golden.rs): lines
/// carrying `cmd=` `hdr=` `body=` hex.
fn parse_fixture(path: &Path) -> Vec<FixtureMessage> {
    let text = std::fs::read_to_string(path).expect("fixture readable");
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains(" msg=") {
            continue;
        }
        let mut cmd = None;
        let mut body = None;
        for tok in line.split_whitespace() {
            if let Some(v) = tok.strip_prefix("cmd=") {
                cmd = Some(v.parse().expect("cmd is numeric"));
            } else if let Some(v) = tok.strip_prefix("body=") {
                body = Some(unhex(v));
            }
        }
        if let (Some(cmd), Some(body)) = (cmd, body) {
            if !body.is_empty() {
                out.push(FixtureMessage { cmd, body });
            }
        }
    }
    out
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn corpus() -> Vec<(&'static str, Vec<FixtureMessage>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    ["staticd-10.2.2.log", "bgpd-10.2.2.log", "ospfd-10.2.2.log"]
        .iter()
        .map(|f| {
            let msgs = parse_fixture(&dir.join(f));
            (*f, msgs)
        })
        .collect()
}

fn bench_decode(c: &mut Criterion) {
    for (name, msgs) in corpus() {
        c.bench_with_input(BenchmarkId::new("zapi_decode", name), &msgs, |b, msgs| {
            b.iter(|| {
                for m in msgs {
                    let _ = ZapiMessage::decode(
                        criterion::black_box(m.cmd),
                        criterion::black_box(&m.body),
                    );
                }
            })
        });
    }
}

fn bench_encode(c: &mut Criterion) {
    for (name, msgs) in corpus() {
        let decoded: Vec<(u16, ZapiMessage)> = msgs
            .iter()
            .map(|m| {
                (
                    m.cmd,
                    ZapiMessage::decode(m.cmd, &m.body).expect("fixture decodes"),
                )
            })
            .collect();
        c.bench_with_input(
            BenchmarkId::new("zapi_encode_body", name),
            &decoded,
            |b, msgs| {
                b.iter(|| {
                    for (_, m) in msgs {
                        let mut buf = BytesMut::with_capacity(256);
                        m.encode_body(&mut buf).expect("encodes");
                        criterion::black_box(&buf);
                    }
                })
            },
        );
    }
}

criterion_group!(benches, bench_decode, bench_encode);
criterion_main!(benches);
