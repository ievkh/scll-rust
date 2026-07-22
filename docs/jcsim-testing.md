# Testing `scll` with the Oracle Java Card simulator

Zero-to-first-test setup for running `scll` — and applications built on it —
against the Oracle Java Card simulator through
[`javacard-simulator-apdu-bridge`](https://github.com/ievkh/javacard-simulator-apdu-bridge).

> **Disclaimer — the bridge is raw.** `javacard-simulator-apdu-bridge` is an
> early, minimally tested helper: no test suite, no reconnect logic, no
> hardening, single-client only, and its error handling is thin. Treat it as a
> development convenience for exercising `scll` against the simulator, **not**
> as a production or trustworthy component. Unexpected behaviour is at least as
> likely to come from the bridge or the simulator as from `scll` — see
> [§9](#9-limits-of-this-setup) and [PDD §10.7](pdd.md#107-known-card--simulator-limitations--verification-status)
> before filing a library bug.

## 1. How the pieces fit

```text
scll (cargo test / examples / your app)
   │  TCP 127.0.0.1:10000 — frame = uint32_be length ‖ APDU bytes
   ▼
javacard-simulator-apdu-bridge          (Java, single client at a time)
   │  socket:localhost:9025 — Oracle socket card provider (javax.smartcardio)
   ▼
Oracle Java Card simulator
```

`scll` never talks to the simulator directly: `scll-transport-jcsim` speaks the
bridge's length-prefixed framing
([`docs/protocol.md`](https://github.com/ievkh/javacard-simulator-apdu-bridge/blob/main/docs/protocol.md),
[`docs/architecture.md`](https://github.com/ievkh/javacard-simulator-apdu-bridge/blob/main/docs/architecture.md)).

## 2. Prerequisites

| Component | Note |
|---|---|
| Oracle Java Card Development Kit **Simulator** | verified with `java_card_devkit_simulator-linux-bin-v25.1-b_627-26-OCT-2025` |
| JDK | the bridge's `scripts/env.sh.example` assumes Java 21 |
| Rust toolchain | ≥ 1.81 (the SDK's MSRV) |

The bridge builds against two jars shipped with the simulator kit:
`${JC_HOME_SIMULATOR}/client/AMService/amservice.jar` and
`${JC_HOME_SIMULATOR}/client/COMService/socketprovider.jar`.

## 3. Start the simulator

Start it per the Oracle JCDK user guide for your kit version — the launch
command differs between releases and is not reproduced here.

The only thing this setup requires is that the simulator's **socket interface**
is listening. For
`java_card_devkit_simulator-linux-bin-v25.1-b_627-26-OCT-2025` that is TCP
port **9025**, which is also the bridge's default (`SIM_HOST=socket:localhost:9025`).

```sh
ss -ltn 'sport = :9025'      # expect one LISTEN row
```

## 4. Build the bridge

```sh
git clone https://github.com/ievkh/javacard-simulator-apdu-bridge
cd javacard-simulator-apdu-bridge
cp scripts/env.sh.example scripts/env.sh
# edit scripts/env.sh: set JAVA_HOME and JC_HOME_SIMULATOR
./scripts/build.sh           # → build/javacard-simulator-apdu-bridge.jar
```

## 5. Configure the bridge

```sh
cp config/simulatorservice.properties.example config/simulatorservice.properties
```

Use **the same ISD keys** you will give `scll`, so both sides agree:

```properties
A000000151000000_scp03enc_01=90379A3E7116D455E55F9398736A01CA
A000000151000000_scp03mac_01=473F36161A7F7F60CC3A766EA4BE5247
A000000151000000_scp03dek_01=D3749ED4FF42FD58B39EEB562B017CD9
```

Notes:

- The `_01` suffix is the ISD **key version** the bridge's AMService client
  addresses. Keep the example's value unless your simulator's ISD keyset sits
  at a different version.
- These keys are used **only** by the bridge's optional startup CAP deployment
  ([§8](#8-getting-an-applet-onto-the-simulator)). They are *not* used for
  plain APDU forwarding — but the properties file must still exist:
  `SimulatorService.main` loads `-props` unconditionally.
- **Leave the `apdu.response.*` mock entries out.** A mocked response is
  answered by the bridge and never reaches the card, which desynchronises
  secure-channel sequence counters and MAC chaining.

## 6. Run the bridge

```sh
./scripts/run.sh
```

Defaults taken from `scripts/env.sh`: `SIM_HOST=socket:localhost:9025`,
`LISTEN_PORT=10000`, `LOG_MODE=console`.

**Recommendation:** run with applet deployment disabled (leave `CAP_PATHS`,
`CAP_AIDS`, `APPLET_CLASS_AIDS`, `APPLET_INSTANCE_AIDS` commented out) unless
you specifically need a pre-installed applet. `scll` loads and installs applets
itself, and that path is part of what you want under test.

## 7. Run the `scll` test suite against it

```sh
export SCLL_JCSIM_ADDR=127.0.0.1:10000
export SCLL_JCSIM_KEY_ENC=90379A3E7116D455E55F9398736A01CA
export SCLL_JCSIM_KEY_MAC=473F36161A7F7F60CC3A766EA4BE5247
export SCLL_JCSIM_KEY_DEK=D3749ED4FF42FD58B39EEB562B017CD9

cargo test-jcsim -- --nocapture
```

`cargo test-jcsim` is the workspace alias in [`.cargo/config.toml`](../.cargo/config.toml).
It runs two integration tests:

| Test | Needs |
|---|---|
| `scll-transport-jcsim :: connect_selects_isd` | `SCLL_JCSIM_ADDR` |
| `scll :: jcsim_open_channel_and_read_status` | `SCLL_JCSIM_ADDR` + all three keys |

Both **skip silently** when the variables are unset, so a plain
`cargo test --workspace` stays green with no simulator running.

### Example binaries

```sh
cd examples
export SCLL_TRANSPORT=jcsim          # or rely on SCLL_JCSIM_ADDR being the only one set
export SCLL_CAP=/path/to/scpapplet.cap   # lifecycle demos only — see below
./run.sh card-info                   # read-only
./run.sh isd-lifecycle               # load + install + keyset rotation + teardown
```

Full binary list and environment table: [`examples/README.md`](../examples/README.md).
Building the CAP that `SCLL_CAP` points at (prerequisites, the reference
`jc305-gp2.2` artifact, AIDs, the `HELLO` command):
[`examples/README.md` § Target applet](../examples/README.md#target-applet).
Set `SCLL_APDU_TRACE=1` to hex-dump every C-APDU/R-APDU to stderr.

## 8. Getting an applet onto the simulator

Two mutually exclusive routes:

**(a) Via `scll` — recommended.** `load_package` + `install_applet`, as driven
by the `ssd-lifecycle` and `isd-lifecycle` example binaries. This exercises
`scll`'s own CAP parsing, `'C4'` LOAD block chaining and INSTALL commands, and
the demos clean up after themselves. The reference applet and the steps to
build its CAP are documented in
[`examples/README.md` § Target applet](../examples/README.md#target-applet);
only `SCLL_CAP` has to be set.

**(b) Via the bridge at startup.** Set the deployment lists in `scripts/env.sh`
(semicolon-separated, same order in every list):

```sh
export CAP_PATHS=applets/example.cap
export CAP_AIDS=aid:A00000006203010C01
export APPLET_CLASS_AIDS=aid:A00000006203010C0101
export APPLET_INSTANCE_AIDS=aid:A00000006203010C0101
```

Deployment runs through Oracle's AMService (`GP2.2`, ISD
`aid:A000000151000000`) using the keys from §5, **before** the TCP listener
starts. Use it only when an applet must already be present when `scll`
connects. Do not combine it with a lifecycle demo that installs the same
instance AID.

## 9. Limits of this setup

- **One client at a time.** A second connection is closed immediately. Stop the
  previous test/example before starting the next.
- **No card reset, no real ATR.** `JcSimTransport::reset()` only drops and
  re-opens the TCP connection and returns a synthetic empty ATR tagged `T=1`;
  the bridge has no reset channel. For a genuinely clean card, restart the
  simulator (and the bridge).
- **Frame ceiling 65535 bytes.** Never a factor: `scll` uses short APDUs only.
- **Simulator ≠ card.** The Oracle simulator deviates from GlobalPlatform in
  documented ways (no R-MAC/R-ENC on SSD `SecureChannel.wrap()` paths; bare
  `63 10` GET STATUS responses; a dangling default-KVN pointer after key
  deletion). All catalogued in
  [PDD §10.7](pdd.md#107-known-card--simulator-limitations--verification-status).
  Check there first when simulator results differ from real hardware.

## 10. Using `scll` from your own application

Minimal third-party crate — probe, discover, open an ISD channel over the
bridge:

`Cargo.toml`

```toml
[package]
name = "my-card-tool"
version = "0.1.0"
edition = "2021"
rust-version = "1.81"

[dependencies]
scll = { version = "1.0", features = ["jcsim", "std"] }
# RustCryptoBackend is generic over R: RngCore + CryptoRng — same rand_core
# 0.x line the backend uses.
rand_core = { version = "0.6", features = ["getrandom"] }
```

`src/main.rs`

```rust
use rand_core::OsRng;
use scll::backend::{KeyBackend, KeyKind};
use scll::backend_rustcrypto::RustCryptoBackend;
use scll::report::{ScpTargetKind, TransportName};
use scll::transport_jcsim::JcSimTransport;
use scll::workflow::{OpenScpArgs, SdKeys};
use scll::CardManager;

const ENC: [u8; 16] = [
    0x90, 0x37, 0x9A, 0x3E, 0x71, 0x16, 0xD4, 0x55,
    0xE5, 0x5F, 0x93, 0x98, 0x73, 0x6A, 0x01, 0xCA,
];
const MAC: [u8; 16] = [
    0x47, 0x3F, 0x36, 0x16, 0x1A, 0x7F, 0x7F, 0x60,
    0xCC, 0x3A, 0x76, 0x6E, 0xA4, 0xBE, 0x52, 0x47,
];
const DEK: [u8; 16] = [
    0xD3, 0x74, 0x9E, 0xD4, 0xFF, 0x42, 0xFD, 0x58,
    0xB3, 0x9E, 0xEB, 0x56, 0x2B, 0x01, 0x7C, 0xD9,
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("SCLL_JCSIM_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:10000".to_string());
    let transport = JcSimTransport::connect(&addr)?;

    // Import the static ISD keys BEFORE the backend moves into the manager;
    // the handles stay valid (key bytes never cross the API again).
    let backend = RustCryptoBackend::new(OsRng);
    let enc = backend.import_key(KeyKind::Aes128, &ENC)?;
    let mac = backend.import_key(KeyKind::Aes128, &MAC)?;
    let dek = backend.import_key(KeyKind::Aes128, &DEK)?;

    let mut mgr = CardManager::new(transport, backend);

    mgr.probe(TransportName::Jcsim)?;
    let info = mgr.discover(None)?;
    println!("ISD AID : {:02X?}", info.isd_aid.as_bytes());
    println!("SCP     : {:?}", info.scp_default);

    let params = mgr.open_scp(&OpenScpArgs {
        target_aid: info.isd_aid.as_bytes(),
        target_kind: ScpTargetKind::SecurityDomainAid,
        sd_keys: SdKeys { enc, mac, dek },
        advertised: &info.scp_supported,
        force_scp: None,          // §4.3 auto-selection: SCP03 preferred
        kvn: 0x00,                // let the card pick its default keyset
        requested_level: 0x03,    // C-MAC | C-DECRYPTION
    })?;
    println!("channel : {params:?}");

    println!("status  : {:?}", mgr.get_card_status()?);
    Ok(())
}
```

```sh
cargo run
```

Errors are printed with `Display` (`{e}`) so status words render as hex; use
`{e:?}` only when you want the structural form.

For the full API surface — SSD creation, CAP loading, applet install, key
rotation, applet APDU exchange — see [`examples/`](../examples/) and
[PDD §5](pdd.md#5-workflow-specifications).

## 11. References

- `javacard-simulator-apdu-bridge` —
  [README](https://github.com/ievkh/javacard-simulator-apdu-bridge/blob/main/README.md),
  [`docs/protocol.md`](https://github.com/ievkh/javacard-simulator-apdu-bridge/blob/main/docs/protocol.md),
  [`docs/architecture.md`](https://github.com/ievkh/javacard-simulator-apdu-bridge/blob/main/docs/architecture.md)
- `scll` design document — [`docs/pdd.md`](pdd.md), §3.2 (Transport), §5 (workflows), §10.7 (target quirks)
- Example binaries, environment table, and applet CAP build —
  [`examples/README.md`](../examples/README.md)
- Reference cooperative SCP03 applet —
  [`ievkh/javacard-scp03-cooperative-applet`](https://github.com/ievkh/javacard-scp03-cooperative-applet)
- GlobalPlatform Card Specification v2.3.1 and Amendment D v1.1.2 —
  <https://globalplatform.org/specs-library/>
