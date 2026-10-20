# Incident corpus: provenance

The corpus is a search-based sample of disclosed vulnerabilities and incidents in SD-WAN and network-management planes, not an exhaustive census. Each record has a source URL (`source`) and is coded with `capability`, `policy_write` and `layer1` (see `CODEBOOK.md`).

## Coding
- First coder: all 30 records (`*_A` columns).
- Second coder: all 30 records from the cited sources (`*_B` columns, notes in `notes_B`, `notes_B2`, sources used in `source_used_B2`). Nine records were checked against sources after a first pass from the summaries; the other 21 were coded independently from the sources.
- Agreement (`python3 kappa.py`): Cohen's kappa 1.00 on capability, policy_write and layer1 (30/30).
- Judgment calls that both coders resolved the same way: I02 and I04 (C1, from "escalated privileges on the underlying OS"), I06 (C2, limited write), I25 (C2; chains to code execution with a separate file-delete flaw).

## Source corrections
- I08 (CVE-2026-20182): source is Rapid7's analysis. An earlier source URL pointed to a different CVE; Cisco's advisory for CVE-2026-20182 is `cisco-sa-sdwan-rpa2-v69WY2SW`.
- I09 (CVE-2026-20245): source is the Mandiant report. Access is `auth` (authenticated netadmin to root).
- I13 (CVE-2024-2973): source is the NCSC-IE copy of Juniper's advisory text.
- I21 (CVE-2025-37184): marked in the wild. HPE advisory HPESBNW04992 revision 4 (25 June 2026) states that HPE is aware of public exploitation attempts.
- I24: CVE-2020-12146 (path traversal; coded C1 only as part of the chain with a second flaw).

## Notes
- I26 to I29 belong to the 2020 Realmode Labs series and rest on one SecurityWeek summary; the CVE ids published for the Citrix flaws (CVE-2020-8271, -8272, -8273) do not map one-to-one onto the four flaws the article describes, so these records carry no CVE id.
- Exploitation in the wild is stated in the cited sources for nine records (I07, I08, I09, I10, I11, I14, I15, I16, I21); all nine are policy-originating.
- CVE-2026-76504 (Cisco Catalyst SD-WAN Manager API authentication bypass, Sept. 2026) postdates the sample and is not included.
