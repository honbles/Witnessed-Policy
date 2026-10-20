# Witnessed Policy

Code, specifications, data and paper sources for **Witnessed Policy: Quorum-Committed, Edge-Validated Policy for SD-WAN** (Blessing Honmane, SafeLinx Technology).

An SD-WAN controller is a single point of policy authority. Witnessed Policy keeps the controller trusted for availability only. Policy is a signed hash chain validated at every edge (layer 1), and a two-phase quorum commit with administrator-started round change makes the chain fork-free at enforcement (layer 2). With `n` edges, at most `b` Byzantine and `c` further offline, the quorum `T = ceil((n+b+1)/2)` is safe and live exactly when `n >= 3b + 2c + 1`.

The paper is in [`paper/main.pdf`](paper/main.pdf) (LaTeX source in `paper/`).

## What is in the repository

| Path | Contents |
|---|---|
| `spec/` | TLA+ specifications (`WitnessedPolicy`, `WitnessedPolicyAbs`, `OnePhase`, `WPLiveness`), TLC configurations, generated trace modules, `RESULTS.md` |
| `proto/` | Python prototype: protocol core (`wpcore.py`, `wp2.py`), emulated network harness, real-process edges with WireGuard and nftables (`real_dp.py`, `dp.py`, `edge_daemon.py`, `realnet.py`), baselines S0 to S3, property-based fuzz, trace-to-TLA+ validation |
| `model/` | Independent Python model of the TLA+ core and the recovery check |
| `sim/` | Monte Carlo simulations for the divergence window (E1) and availability under outages (E3) |
| `e4/` | Incident corpus (30 records), codebook, second-coder agreement script, provenance notes |
| `plots/`, `paper/` | Figure scripts and the paper sources |
| `paper_data/` | Data behind the data-plane figures and tables, and the real-process trace used for validation |
| `setup.sh`, `run_*.sh`, `diag_wg.sh`, `collect_results.sh` | One-time setup, experiment drivers, WireGuard check, result collection |
| `EXPECTED.md` | Reference results to compare a run against |

## Requirements

- Linux with root access for the real-process experiments (Ubuntu 22.04 or later; the reported runs used Ubuntu 25.10, kernel 6.17).
- 8 vCPU and 16 GiB RAM or more is comfortable. Each edge process takes about 30 MB.
- Python 3.10+ with `cryptography` and `matplotlib` (see `requirements.txt`), Java 17+ for TLC, `iproute2`, `nftables`, `wireguard-tools`, optionally `wireguard-go` and the `sch_netem` kernel module.

`sudo ./setup.sh` installs all of this on Ubuntu or Debian and downloads `tla2tools.jar` if it is missing.

## Quick start

```bash
sudo ./setup.sh              # once
sudo ./diag_wg.sh            # about a minute: checks WireGuard tunnels on this host
sudo ./run_real.sh           # real-process scenarios, about 10-15 minutes on 8 vCPU
./collect_results.sh         # writes witnessed_policy_results_<hostname>.zip
```

To keep a long run alive after the terminal closes:

```bash
sudo -v
sudo nohup bash -c './run_real.sh; ./collect_results.sh' > run_real.out 2>&1 < /dev/null &
```

Everything from scratch (emulated checks, real processes, trace validation and TLC, roughly 2 to 3 hours on 8 vCPU): `sudo ./run_all.sh` (`sudo ./run_all.sh quick` skips the long n=7 TLC run).

## Reproducing the paper

| Paper | Command | Output |
|---|---|---|
| Table II (TLC) | `./run_tlc.sh` | `results/tlc/*.txt`, `results/tlc_results.json` |
| Trace validation (Section VIII) | `python3 proto/validate_traces.py` | `proto/trace_validation.json` |
| Fuzz, baselines, E1 sweep (Section VIII, Table IV, Fig. 5) | `./run_checks.sh` | `proto/*_results.json`, `proto/e1_sweep.json` |
| E1 and E3 simulations (Figs. 4, 6, Tables III, V; Table V uses 20 seeds) | `cd sim && python3 e1_sim.py && python3 e3_sim.py` | `sim/e1_results.txt`, `sim/e3_results.json`, `sim/e3_multiseed.json` |
| Table VI, Figs. 7-8 (real processes) | `sudo ./run_real.sh` | `real_dp_out/dp_results.json` |
| Table VII (cost) | `sudo ./run_real.sh` and `python3 proto/scale_emu.py 100,200,500` | `real_dp_out/dp_results.json`, `proto/scale_emu_*.json` |
| Incident corpus (E4) | `python3 e4/kappa.py` | agreement per field |
| Figures and PDF | `./make_paper.sh` | `paper/main.pdf` |

`EXPECTED.md` lists the values to expect. Timings in the real-process runs depend on the host; compare orders of magnitude and the qualitative outcomes (what is blocked, what commits, what diverges).

## Notes

- **AppArmor on Ubuntu.** Recent Ubuntu releases enforce an AppArmor profile for `/usr/bin/wg` that blocks key-file reads and the `wireguard-go` socket. The run scripts source `wg_unconfine.sh`, which puts an identical copy of `wg` in `/usr/local/lib/wp/bin` ahead of `PATH`; AppArmor does not confine it. Set `WP_NO_UNCONFINE=1` to disable.
- **WireGuard mode.** The harness uses the kernel module when `ip link add type wireguard` works and falls back to `wireguard-go`. The `wg_start` events in the edge traces record which one ran.
- **Link delay.** With root and `sch_netem`, link delay is real (`tc netem`, 25 ms per side); otherwise it is applied inside the application.
- **Network namespaces.** Real runs create and delete namespaces `e0..eN`, `fin`, `guest`, `sales`, bridges `br0` (control) and `br1` (WireGuard underlay), and kill stray `edge_daemon.py` and `wireguard-go` processes. Run them on a machine where that is acceptable.
- **Scale.** Scale runs use addresses `10.9.0.10+i`, so `n <= 230`. The paper reports real-process runs up to `n = 32`; larger `n` uses the emulator (`proto/scale_emu.py`).
- **Data plane.** The nftables rule compiler targets IPv4.

## Troubleshooting

- *Tunnels do not come up, or `diag_wg.sh` prints FAIL.* Re-run `sudo DELAY=25 ./diag_wg.sh`. A `Permission denied` from `wg` usually means AppArmor: check `sudo journalctl -k -b | grep 'apparmor="DENIED"'` and that `wg_unconfine.sh` is being sourced.
- *`validate_traces.py` reports REJECTED for traces that should pass.* Stale root-owned TLC scratch folders from earlier `sudo` runs can cause this in old checkouts; this version uses private temporary folders and reports `ERROR` unless TLC gives a verdict. If needed: `sudo rm -rf /tmp/m_*` and `sudo chown -R "$USER": .`.
- *`PermissionError` writing under `spec/`.* Files were created by an earlier `sudo` run: `sudo chown -R "$USER": .`.

## Incident corpus

`e4/e4_incidents.csv` holds 30 disclosed vulnerabilities and incidents in SD-WAN and network-management planes (2020 to 2026, nine vendors), coded by capability, policy-write and layer-1 effect. `e4/CODEBOOK.md` defines the codes, `e4/kappa.py` computes agreement between the two coders, `e4/summarize_e4.py` writes the corpus summary, and `e4/PROVENANCE.md` records how the corpus was assembled and corrected.

## Citation

> Blessing Honmane. *Witnessed Policy: Quorum-Committed, Edge-Validated Policy for SD-WAN.* SafeLinx Technology.

Contact: blessing.honmane@safelinx.ng
