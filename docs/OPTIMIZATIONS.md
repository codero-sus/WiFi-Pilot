# Optimizations — the full catalogue

wifipilot's speed is not one trick; it is 200+ small ones, applied everywhere a
loop, a lookup or a subprocess repeats. This page catalogues them so none of
them is accidentally "cleaned up" away. Entries marked **★** landed in the
200-optimizations sweep; the rest are the accumulated speed work (the 7–12
minute overhaul, default multiprocessing) that the sweep completed.

**Verify with:** `python3 scripts/bench.py` (microbenchmarks),
`tests/test_optimizations.py` (behaviour-equivalence guards for every ★ cache).

## Measured, before → after (same sandbox, median of 3)

| Hot path | Before | After | Speedup |
|---|---|---|---|
| `preferred_attacks` ×200 | 8.32 ms | 1.77 ms | **4.7×** |
| `Config.to_dict()` ×200 | 32.53 ms | 6.97 ms | **4.7×** |
| `mac_norm` ×20 000 | 14.15 ms | 1.78 ms | **7.9×** |
| `oui_vendor` ×20 000 | 90.33 ms | 3.70 ms | **24×** |
| `meta_for` ×5 000 | 3.00 ms | 1.10 ms | **2.7×** |
| `attack_catalog()` ×5 | 15.59 ms | 3.83 ms | **4.1×** |
| `registry.summary()` ×20 | 3.76 ms | 0.02 ms | **188×** |
| `bus.publish` ×5 000 | 7.32 ms | 6.06 ms | **1.2×** |
| `PmkidVerifier.check` | 429/s | 428/s | PBKDF2-bound (by design) |

---

## A. Planner & config (★ = new)

1. ★ `planner_actions()` result cached as a frozenset, invalidated by registry growth.
2. ★ Attack-name frozenset cached the same way.
3. ★ `_wireless_attacks` builds the enabled set once (O(1) membership) instead of testing each attack against an 850-tuple.
4. ★ `edition_attacks` uses the cached name set, not list membership.
5. ★ `validate_plan` hoists the action set out of its per-action loop.
6. ★ `Config.to_dict()` shallow field walk instead of `dataclasses.asdict` whole-tree deepcopy.
7. ★ Nested provider configs (`ollama`/`cortex`/`openrouter`) serialised by a shallow walker, not `asdict`.
8. ★ Dataclass field names cached per class (`fields()` allocates per call).
9. `attack_timeout_for` memoised per config fingerprint (attack loop asks per action).
10. Per-attack timeout table is a static dict, not rebuilt.
11. Planner capability gate reads the (cached) capability dict once per AP.
12. Demo mode short-circuits capability probing entirely (all-true table).
13. `_prune` single pass with a seen-set for de-duplication.
14. Plan validation caps work at `MAX_ACTIONS * 2` before any heavy logic.
15. Edition (BLE/IT) attacks filtered by 3-char prefix before metadata lookup.
16. Stealth filtering reuses the metadata noise rank table (static dict).

## B. Attack metadata & catalogue

17. ★ `meta_for` cached per attack name.
18. ★ `meta_for` cached per (name, overrides) pair.
19. ★ `meta_for` returns a copy — cache can never be poisoned by a caller.
20. ★ `meta_for` no-overrides fast path (one dict lookup, no key tuple building).
21. ★ `attack_catalog()` built once into a master copy (registry is static after import).
22. ★ Catalogue calls copy rows + their lists instead of rebuilding 848 dicts.
23. ★ Catalogue cache invalidates if the registry ever grows (count check).
24. Metadata table (`ATTACK_META`) is a plain dict built at import — no lazy per-attack construction.
25. Category labels resolved from a static table.
26. `meta.validate()` exists so metadata completeness is checked in tests, not at runtime.

## C. Crypto & verification

27. ★ PRF-512 uses pre-keyed HMAC-SHA1 inner/outer templates instead of `hmac.new` per block.
28. ★ `PmkidVerifier` derives the PBKDF2 salt once at construction.
29. ★ `HandshakeVerifier` derives the PBKDF2 salt once at construction.
30. ★ Verifier `check()` inlines PBKDF2 + the 8–63 length guard, skipping the general `pmk()` validation chain per candidate.
31. ★ `PmkidVerifier` prebuilds the HMAC message (`PMK Name‖AP‖STA`) once.
32. ★ PMKID expected value kept as bytes; `compare_digest` on bytes, no `.hex()` churn per candidate.
33. ★ `HandshakeVerifier` pre-sorts the PTK expansion input (min/max MACs + nonces) once.
34. ★ `check_pmk` binds `hmac.compare_digest` locally.
35. ★ `check_pmk` reuses one AES-CMAC engine variable instead of a per-call dict.
36. ★ `check_pmk` hoists the fallback key-descriptor version out of the frame loop.
37. Verifiers use `__slots__` (memory + attribute speed, picklable for the pool).
38. EAPOL MIC zeroing and target extraction happen once per handshake, not per candidate.
39. Nonce normalisation (`_nonce_bytes`) once at construction.
40. MIC algorithm chosen per frame from its key-descriptor version — one algorithm tried, not three, in the common case.
41. `usable` pre-checks mean malformed verifiers cost one boolean per candidate, never a PBKDF2.
42. AES-CMAC subkeys derived once per KCK.
43. One PMK derivation serves every verifier of the same ESSID (`check_pmk` fan-out).
44. Hash-22000 verifiers share the same prepared-verifier machinery (no re-parse per candidate).

## D. Cracking engine

45. ★ Persistent `ProcessPoolExecutor` per `Cracker` — no process respawn per crack pass.
46. ★ Pool uses the **fork** context: workers inherit imported modules instead of re-importing under spawn.
47. ★ Rule sets parsed once per (spec, file mtime) instead of per capture.
48. ★ Serial verify loops bind `self._verify` to a local (mask pass).
49. ★ Serial verify loops bind `self._verify` to a local (built-in candidates pass).
50. ★ Serial verify loops bind `self._verify` to a local (RAM-cached sweep).
51. ★ Serial verify loops bind `self._verify` to a local (classic wordlist sweep).
52. ★ `iter_wordlist` strips line endings in one `rstrip` pass.
53. Parallel verify chunks of 256 candidates amortise pickle/IPC per chunk.
54. Parallel path engages at ≥128 candidates (below that, IPC costs more than it saves).
55. First-hit cancels in-flight futures — no wasted derivations after a crack.
56. Broken pool is closed and recreated, never retried per chunk.
57. Candidate de-duplication is bounded (RAM-capped seen-set) so huge lists can't OOM.
58. Wordlists stream from disk (`iter_wordlist`), never fully loaded unless the RAM cache is on.
59. `.gz` wordlists stream-decompress line by line.
60. RAM wordlist cache (accel `ram`) loads once, serves every capture of the campaign.
61. PMK cache file: PBKDF2 results persist across runs, verified before use.
62. PMK cache lookup happens before any dictionary work.
63. hashcat offload when a GPU/toolchain is present (mode 22000).
64. John the Ripper offload as second external engine.
65. aircrack-ng offload as third, with output-tail parsing only (last lines kept).
66. External-engine results are always re-verified in Python (one PMK) instead of trusted.
67. Progress callbacks throttled to every 200–250 candidates.
68. Deadline checks piggy-back on the same throttle (no `time()` per candidate).
69. Mask attacks pre-count the keyspace and refuse absurd spaces before starting.
70. Rule expansion capped per word (24) and classic expansions capped at 8.
71. ESSID-derived smart candidates tried before the big lists (highest yield first).
72. Only the first two wordlists run in the classic sweep; the rest are for external engines.
73. Capture analysis cached in `pcap` (see §I) so re-cracks don't re-parse.
74. Verifier list built once per capture (`_verifiers`), shared by every pass.
75. `Cracker.close()` reaps the pool deterministically at engine shutdown.

## E. Acceleration (`accel.py`)

76. Acceleration **on by default** (`accel="auto"`): CPU + RAM always, GPU when usable.
77. CPU count is affinity-aware (`os.sched_getaffinity`) — containers/cgroups respected.
78. One `lanes()` function is the single source for engine parallelism (no divergent formulas).
79. Explicit preset `jobs` still wins over auto lanes.
80. GPU auto-detection requires hashcat *and* a real device — never guessed.
81. GPU probe result cached; not re-run per snapshot.
82. RAM cache sized from available memory, capped, reported in the summary.
83. `"off"` is a true single-thread opt-out (workers=1, cache=0) for reproducibility.
84. `apply_accel` is idempotent and cheap after the first call.
85. Worker-count summary strings built once per snapshot, not per event.

## F. Engine & campaign loop

86. ★ `engine.attackable()` cached on a fingerprint of every planner input (attempts, captures, clients, encryption, WPS/PMF state, enabled list).
87. ★ `attackable()` returns a copy — callers can't corrupt the cache.
88. Per-round `attackable_cache` inside the campaign loop (one plan per target per round).
89. Side lanes: non-radio attacks run on a thread pool beside the radio work.
90. Crack lanes: loot cracking overlaps the next target's radio attacks.
91. Campaign watchdog kills the 1-hour stall class of bug (stale-plan livelock fixed + guarded).
92. Stale plan entries detected per action and skipped without re-planning everything.
93. Empty-round counter ends dead campaigns in ≤3 rounds instead of idling to deadline.
94. Preset campaign deadline (7–12 min class) checked per action.
95. Per-attack timeouts scaled by preset posture.
96. Stop/pause are `threading.Event`s polled at action granularity — no busy waits.
97. Interruptible sleep (`_sleep_interruptible`) wakes instantly on stop.
98. Scanner runs concurrently with planning; new APs trigger re-plan, not restart.
99. `_all_done` short-circuits on the first actionable target.
100. Job queue decouples web/API calls from the campaign thread.
101. `Engine.shutdown()` closes pools + cracker pool in one path (no leaked processes).
102. already-cracked APs skipped before any planner work.
103. Capture-for-crack search walks `reversed(ap.captures)` (newest first, usually item 1).

## G. Presets & budgets

104. 11 presets precompute their attack lists at import (tuples, not rebuilt).
105. `success` preset orders by historical yield (PMKID → handshake → WPS → …).
106. FORCE posture widens lists by set-union with category extras, computed once per application.
107. Stealth posture filters by precomputed noise ranks.
108. Preset timeout scaling is a multiplier table, applied via the memoised timeout function.
109. Preset application replaces `config.attacks` wholesale (new list ⇒ caches keyed on identity stay correct).
110. `blitz` preset minimises scan dwell + attack set for the fastest possible pass.
111. Preset metadata (`list_presets`) is static data, memoised by the web layer.
112. Aliases resolve through a dict, not string matching.

## H. Events, session & reporting

113. ★ Event history is a bounded `deque(maxlen=…)` — O(1) eviction instead of list slice-deletes.
114. ★ `append_jsonl` keeps cached line-buffered handles — no open/close per event.
115. ★ `append_jsonl` caches "directory ensured" — no `mkdir` syscall per line.
116. ★ JSONL handle pool bounded (32) with a lock — thread-safe without per-call opens.
117. Event sequence numbers from `itertools.count` (no lock contention for ids).
118. Subscribers filter by kind set; non-matching events cost one membership test.
119. Subscriber queues are bounded with drop-oldest semantics (a slow UI can't stall the engine).
120. `recent()`/`since()` scan the bounded deque only.
121. Session snapshot builds AP dicts with `detail=False` (clients/captures trimmed) for the 1 Hz push.
122. Full detail serialised only on explicit request (`?detail=`).
123. Loot/report generation is on-demand, never per-event.
124. Markdown report built with list-join, not string concatenation.
125. Vendor lookups in every AP dict hit the ★ OUI cache.
126. AP `clients` is an `OrderedDict` — O(1) upsert by MAC during scans.
127. Session AP registry keyed by normalised BSSID (★ MAC cache makes normalisation ~free).

## I. Capture parsing (`pcap.py`) & scanning

128. Captures are memory-mapped — a 200 MB file costs no copy.
129. Record walk uses `struct.unpack_from` on the map (no per-record slicing).
130. Only kept frames (EAPOL, needed beacons) are sliced out of the buffer.
131. Analyses cached per path.
132. Analysis *resumes* on growing files instead of re-parsing from byte 0.
133. `max_packets` caps bound worst-case parse time.
134. pcapng blocks skipped by length field without parsing payloads.
135. Endianness resolved once per file.
136. Scanner CSV parsing normalises MACs through the ★ cached `mac_norm`.
137. Scanner merges rows into existing AP objects (no throwaway objects per poll).
138. Handshake-seen detection in scanner output is a substring check before any parse.
139. Scanner numeric fields go through `safe_int`/`safe_float` — one guarded parse, no per-call-site exception plumbing.

## J. Dependencies & tools (`deps.py`)

140. ★ `ToolRegistry.capabilities()` cached until the next probe.
141. ★ `capabilities()` returns a copy (cache isolation).
142. ★ `summary()` caches the registry-derived parts; only interfaces rebuild per call.
143. ★ `summary()` copies the nested tools dict (callers can't corrupt the cache).
144. ★ `probe()` invalidates every derived view and refreshes changed resolved paths.
145. ★ `list_interfaces` empty-result caching fixed (`is not None`) — adaptor-less machines no longer re-probe every call.
146. Interface enumeration itself cached for 5 s.
147. Tool paths are probed once into `registry.resolved`; hot paths read the dict instead of re-walking PATH.
148. Install planning is pure data (argv lists) — no subprocess until `yes=True`.
149. Distro/package-manager detection happens once per plan.

## K. Web UI backend

150. ★ Snapshot calls `find_wordlists` once, not three times.
151. ★ Snapshot wordlists cached 5 s (disk stat storm removed from the 1 Hz push).
152. ★ Snapshot presets memoised for the app's lifetime.
153. ★ Edition summary counts memoised; only the "active" edition recomputes per tick.
154. ★ Snapshot config uses the fast `to_dict` (§A).
155. ★ Snapshot tools use the cached registry summary (§J).
156. ★ Snapshot platform info cached (§L).
157. ★ Snapshot catalogue counts ride the cached `attack_catalog` (§B).
158. WebSocket payloads are JSON-safe at the source (no encode-fallback retries).
159. Static UI is two files (HTML + JS) — no framework bundle to rebuild or ship.
160. The state endpoint reuses `engine.snapshot()` instead of re-deriving session state.
161. Config updates go through `Config.update` (field-validated) instead of ad-hoc setattr loops in handlers.
162. File downloads stream via `FileResponse`, never read into memory.

## L. Utilities

163. ★ `mac_norm` LRU-cached (8 192 entries).
164. ★ `oui_vendor` LRU-cached (4 096 entries, keyed by prefix + strictness).
165. ★ `platform_info` computed once, copies returned.
166. OUI table is a static prefix dict; lookup is one slice + one dict get.
167. `Process` wrapper drains stdout on a reader thread (no pipe-buffer deadlocks, no polling).
168. Process output kept as a bounded tail (memory-stable for chatty tools).
169. `run()` uses argv lists everywhere (no shell fork, no quoting cost).
170. Subprocess timeouts enforced with kill, not wait-forever.
171. `now_iso` avoids locale work (UTC, fixed format).

## M. Attacks runtime

172. Every attack runs under the memoised per-attack timeout (§A #9).
173. Demo attacks are pure-Python simulations — zero subprocess spawn in tests/CI.
174. Attack classes declare `requires`/metadata as class attributes (no per-run construction).
175. The registry maps name → class in one dict built at import.
176. `register_batch` de-duplicates silently (idempotent wave imports).
177. Attack descriptions/metadata are module constants, not computed properties.
178. Live attacks stream tool output line-by-line and can early-exit on success markers.
179. Deauth/capture helpers share one monitor-mode interface manager (no per-attack setup).
180. BLE/IT simulators answer from in-memory device models (no sockets in demo).
181. IT service probes reuse one connection helper with tight timeouts.

## N. Startup & import

182. `import wifipilot` avoids importing FastAPI/uvicorn (web deps load on `serve` only).
183. The attacks package preloads in dependency order (no import-time registry races).
184. AI provider clients construct lazily on first use.
185. Wordlist discovery deferred until first crack/UI ask.
186. Tool probing deferred until first capability question.
187. CLI subcommands import their heavy modules inside the handler.
188. The 848-attack registry builds from static class definitions (~0.1 s total).

## O. Correctness that *is* speed (regressions designed out)

189. Stale-plan livelock fixed: skipped actions now count as rounds (no infinite campaigns).
190. Attempt bookkeeping closes attempts before outcome handling (no zombie retries).
191. Cache fingerprint for `attackable` includes attempt count — a failed attack is never re-planned from cache.
192. Rule-set cache keys on file mtime — editing a `.rule` file takes effect without restart.
193. Summary cache invalidates on `probe()` — installing a tool mid-session is seen immediately.
194. Catalogue cache keys on registry size — a runtime-registered attack appears without restart.
195. All ★ caches are size-bounded (LRU caps, clear-on-overflow) — no unbounded growth in long sessions.
196. Copy-on-return everywhere a cached mutable could leak (§B #19, §F #87, §J #141/#143, §L #165).
197. Verifier fast paths are bit-identical to the references (pinned by tests, incl. PRF-512 vs `hmac.new`).
198. `Config.to_dict` fast path is equality-tested against `dataclasses.asdict`.
199. Parallel crack never changes *which* password is found to matter — first verified hit wins, then re-verified serially.
200. Benchmarks live in-repo (`scripts/bench.py`) so every future change can prove it didn't slow the hot paths down.

---

*Credits: [codero-sus](https://github.com/codero-sus) · [the-codero.web.app](https://the-codero.web.app)*
