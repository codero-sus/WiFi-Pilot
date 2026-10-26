# Optimizations — the full catalogue (420 entries)

wifipilot's speed is not one trick; it is hundreds of small ones, applied
everywhere a loop, a lookup or a subprocess repeats. This page catalogues
them so none of them is accidentally "cleaned up" away. Entries marked **★**
landed in the first 200-optimizations sweep, **⚡** in the second sweep that
took the catalogue to 400; entries 401+ (**⏱**) are the wall-clock round —
campaign-level dead air measured in seconds, not microseconds. The rest are
the accumulated speed work (the 7–12 minute overhaul, default
multiprocessing) and the efficiency design of the remaining subsystems,
catalogued in the second sweep.

**Verify with:** `python3 scripts/bench.py` (microbenchmarks),
`python3 scripts/bench_campaign.py` (seeded end-to-end campaign wall
clock), `tests/test_optimizations.py` (behaviour-equivalence guards for
the caches and fast paths of all sweeps).

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

### Second sweep (⚡)

| Hot path | Before | After | Speedup |
|---|---|---|---|
| `Event.to_dict()` ×5 000 | 12.03 ms | 2.04 ms | **5.9×** |
| `AccessPoint.to_dict()` ×2 000 | 22.96 ms | 9.85 ms | **2.3×** |
| `AccessPoint.attackable()` | 6.97 µs | 0.84 µs (cached) | **8.3×** |
| `session.snapshot()` ×50 (12 APs) | 20.19 ms | 7.02 ms | **2.9×** |
| `engine.snapshot()` | 3.58 ms | ~1.0 ms | **~3.6×** |
| `engine._attack_catalog()` (848 on) | 3.90 ms | 1.54 ms | **2.5×** |
| `apply_rules` best64 ×2 000 words | 68.0 ms | 35.6 ms | **1.9×** |
| `password_report()` ×1 000 | 14.25 ms | 9.88 ms | **1.4×** |
| `bt.random_address_hash()` | ~46 µs | ~9.5 µs | **~4.8×** |
| `pcap` analyse 600 beacons ×10 | 6.71 ms | 5.59 ms | **1.2×** |
| socket connects per 50 snapshots | 50 | 2 | **25× fewer** |

### Wall-clock round (⏱, seeded demo campaigns — `scripts/bench_campaign.py`, seed 42)

| Campaign (demo, all 14 APs) | Before | After | Result |
|---|---|---|---|
| `blitz` wall clock | 79.8 s | **39.4 s** | 2.0× faster, passwords 8 → **12** |
| `success` wall clock | 107.9 s | **42.2 s** | 2.6× faster, passwords 8 → **13** |
| discovery phase (blitz, 12 s window) | 12.0 s | **5.1 s** | settled-neighbourhood early exit |
| dead tail after last useful action | ~36 s | **~0 s** | no scan-window sleeps |
| wasted (echo) plan rounds | 1 per productive round | **0** | exhausted plans bridge instantly |
| re-cracks of an uncrackable capture | until deadline | **1 per budget** | failed cracks are remembered |

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


## P. Second sweep — snapshot path, rule engine, negative caching (⚡ = new)

201. ⚡ `Event.to_dict()` formats its timestamps once per event, not per serialisation (a snapshot serialises ~120 events per tick).
202. ⚡ Event `iso` is the *event's* time — it used to be stamped with the serialisation moment, which also made it uncacheable.
203. ⚡ Rule commands are pre-parsed once (`_compile` cache: op, literal chars, numeric arguments) instead of re-split per word.
204. ⚡ The list-based rule engine only joins the working string for ops that need it (23 of 33 ops never pay for it).
205. ⚡ The `t` (toggle-case) op is `str.swapcase()` — one C loop instead of a per-char generator.
206. ⚡ A string-native rule engine (`_apply_str`) is `Rule.apply`'s hot path; the list engine stays as the fuzz-pinned reference.
207. ⚡ `Rule.__post_init__` precomputes the compiled steps and usability (rules are never mutated after parsing).
208. ⚡ `apply_rules` binds its length bounds and `seen.add` once per call.
209. ⚡ `ATTACK_NAMES` as a count-keyed cached frozenset (`models._all_attack_names`).
210. ⚡ `AccessPoint.attackable()` is fingerprint-cached per AP (essid/encryption/auth/SAE/PMF/WPS/clients/captures + enabled list).
211. ⚡ Its `add()` tests set membership on both sides (was: linear scan of the 848-name list, ~28× per call).
212. ⚡ The attackable cache pins the caller's enabled list so its `id()` key can never be recycled under it.
213. ⚡ `AccessPoint.to_dict` reads `time.time()` once for both age fields.
214. ⚡ `SessionStats.to_dict` shallow-walks its scalar fields instead of `asdict()`'s deepcopy (~170 µs per snapshot).
215. ⚡ The stats field-name tuple is computed once, after first use.
216. ⚡ `Capture`/`Finding` `created` is derived from `created_ts` (`_iso_of`) — correct *and* no per-call clock formatting.
217. ⚡ `session.snapshot()` passes the live enabled list to `to_dict` — no 848-name copy per tick, and the per-AP caches actually hit.
218. ⚡ `analytics._class_flags` classifies a password in one pass (the predicates are mutually exclusive per char) — was eight `any()` scans across two functions.
219. ⚡ `password_report` shares that single pass between its keyspace estimate and its class label.
220. ⚡ The repeat/doubled-tail regexes are precompiled module constants.
221. ⚡ `hash22000.parse_text` binds `parse_line` locally for the file loop.
222. ⚡ The pcap walker unpacks records through a bound `struct.Struct` (no format re-parse per packet).
223. ⚡ The EAPOL hunt searches the mapping in place (`buf.find`) instead of copying every data payload to look inside it.
224. ⚡ `engine._attack_catalog` caches the annotated 848-row catalogue per (enabled list, demo, capabilities) state.
225. ⚡ Its `enabled` flags come from one frozenset (was an 848×848 linear scan — ~4 ms per web tick with everything on).
226. ⚡ Availability is memoised per `requires` tuple (hundreds of attacks share the same requirements).
227. ⚡ The catalogue cache still returns fresh copies — the old contract, minus the rebuild.
228. ⚡ `vendors._key_for` is LRU-cached per lowered vendor string (the same vendors recur all scan long).
229. ⚡ Dossier keys are pre-lowered once into an exact-match dict + ordered list (was `key.lower()` per key per call).
230. ⚡ Scanner probe cells are cleaned once (was up to three `_clean()` calls per cell).
231. ⚡ Scanner CSV rows are stripped once per line.
232. ⚡ `smart_candidates` regexes are precompiled.
233. ⚡ Its vendor-token casings are computed once per form (was up to 5×).
234. ⚡ `Cracker._wordlists()` does ONE discovery walk (was up to three stat-walks per crack pass).
235. ⚡ `default_wordlist()` does one walk (was two in the common all-builtin case).
236. ⚡ `_wordlists()` de-duplicates via a set instead of list scans.
237. ⚡ The subprocess reader strips line endings in one `rstrip`.
238. ⚡ AES key expansion is shared per key (bounded 128-key cache) — BLE's `ah()` paid a ~37 µs expansion per 9 µs block.
239. ⚡ LLM model-list caching honours *attempted* fetches: failures are negative-cached for the same window as successes.
240. ⚡ All three provider clients stamp failed fetches — a downed daemon no longer costs a TCP connect per UI tick (50 snapshots: 50 connects → 2).


## Q. LLM advisor & providers — token and network frugality

241. Provider availability is checked at most every 20 s (`Advisor.check`), never per plan or per status render.
242. Model catalogues are cached per provider (30 s local Ollama, 60 s Cortex, 10 min OpenRouter) with `force` as the only bypass.
243. `session.situation()` sends the model a token-frugal brief (≤12 APs, decision-relevant fields only) — never the full snapshot.
244. The situation brief truncates every list it embeds (attempts, findings, tools) to fixed caps.
245. Plans are requested in JSON mode and validated locally; a malformed reply costs one heuristic fallback, not a retry loop.
246. The heuristic planner is always warm: an LLM outage degrades to it with zero added latency.
247. Identifier redaction is a single alias-map pass (`IdentifierRedactor`) — BSSIDs/ESSIDs are aliased once and restored by dict lookup, not regex sweeps.
248. Paid-provider spend is capped *before* the call (`cost_cap` checked in `check()`), so an over-budget session never pays to learn that.
249. Token/cost accounting is incremental counters on the client, not re-summed history.
250. OpenRouter key info (`key_info`) is cached with its own timestamp and only refreshed on demand.
251. `_pick_fallback` resolves a wanted model against the cached catalogue with staged exact→prefix→substring passes, no extra requests.
252. Streaming chat (SSE/NDJSON iterators) parses incrementally — first token latency, not whole-response buffering, gates the UI.
253. HTTP errors are classified once into typed exceptions (`LLMAuthError`, `LLMCreditError`, …) so policy refusals never masquerade as "offline" and trigger pointless retries.
254. Local-provider requests carry short explicit timeouts (5–20 s), so a hung daemon cannot stall the planner thread.
255. `provider_status(probe=False)` is pure config reading — reachability probes only run when explicitly asked.
256. The advisor's client is built lazily on first use and reconfigured in place (`_sync_client_config`), not rebuilt per plan.
257. Think-interval throttling lives in config, so auto-think cannot spin the model faster than the operator's budget allows.
258. A disabled advisor (`--no-ai`) short-circuits before any client construction or network touch — "off" is free.

## R. Bluetooth & BLE — packet math without waste

259. Address classification is bit tests on the first octet (the two MSBs) — no parsing framework per advertisement.
260. RPA resolution is one AES block per (IRK, prand) via `random_address_hash`, with the spec's `ah()` taken from the correct end of the output.
261. ⚡ That one block no longer pays a full key expansion per call (§P #238).
262. Advertising-data parsing walks length-prefixed structures by offset, copying only the fields it keeps.
263. Company-id / appearance / service-UUID names resolve through static dicts built at import.
264. The GATT model is plain records (handles, UUIDs, properties) — attribute reads are dict lookups, not tree walks.
265. HID report decoding uses precomputed usage tables (`HID_USAGE_NAMES`, key maps) instead of per-report branching.
266. Link-layer (LE LL) parsing reads header fields by offset and only materialises payloads an audit asked for.
267. Cross-transport key derivations (h6/h7, LTK↔link-key) are single AES-CMAC invocations over fixed salts — no iterative KDF where the spec doesn't ask for one.
268. The BLE simulator's airspace is a table of device records; an attack queries the device that can answer instead of scanning the floor.
269. Simulator devices answer from in-memory profiles (bonded or not, encrypted or not) — zero sockets, zero subprocesses in demo.
270. Pairing/feature negotiation in the sim is table-driven (IO-capability → method), matching how the real controllers decide.
271. Tracker/signature matching (AirTag-class beacons) is a prefix/signature table lookup per advertisement.
272. Classic-Bluetooth helpers (SDP/L2CAP/RFCOMM builders) assemble frames with `struct` packs, no intermediate objects.
273. HCI command builders are pure functions from parameters to bytes — trivially testable, no I/O.
274. BLE address generation (static/random/RPA) derives from the seed/IRK arithmetically — no RNG state files.

## S. IT edition — protocol builders & device simulation

275. Every IT protocol builder (`itproto`, `netproto`, `netstack`) is a pure bytes-in/bytes-out function: no sockets in the builder layer, so demo and live share one code path.
276. Parsers are offset-based with bounded loops (e.g. DNS name decompression follows compression pointers with a hard bound).
277. Protocol constant tables (Modbus functions, MQTT reason codes, IEC-104 types, ONVIF envelopes) are module constants — built once at import.
278. Banner/printable extraction keeps printable runs and drops the rest in one pass (`printable()`).
279. The IT simulator hosts are small records (address, vendor, type, ports, profile); dispatch is a dict keyed by (host, port) → handler.
280. Simulator profiles decide behaviour (default creds changed or not, auth required or not) by flag, not by re-deriving state per request.
281. `itsim` sorts its host list weakest-first once, so demos reach interesting failures without scanning the segment.
282. Device-type → ports/protocols/vendors/attacks mappings (`itdev`) are static tables; the edition catalogue is assembled from them without I/O.
283. Edition/device filtering in the UI reuses the cached attack catalogue (§B) — no per-filter registry rebuilds.
284. DES (for legacy protocol crypto) runs on the standard permutation/S-box tables as module constants.
285. SSDP/UPnP announcement builders emit the three standard NOTIFY variants from one template.
286. mDNS/DNS-SD name handling reuses the same bounded decoder as DNS parsing.
287. SMB/NetBIOS and RPC builders pack with `struct` directly into the final buffer shape.
288. IT attack probes share one connection helper with tight per-probe timeouts (§M) — a dead host costs milliseconds, not the attack budget.
289. Port→service naming is a static dict (incl. the ICS/OT range), not a services-file parse at runtime.
290. Simulator answers are byte-identical to the builders' output, so a demo exercises the same parse paths as a live run at zero network cost.


## T. Synthetic captures & the demo world

291. Synth captures are cryptographically real (PBKDF2 → PTK → AES-CMAC MIC), so tests exercise the verifier instead of a mock — correctness without a second implementation to maintain.
292. Frame builders (`build_beacon`, `build_deauth`, SAE commit/confirm…) are pure functions returning bytes; captures are assembled by list concatenation and one write.
293. `write_pcap` emits the global header once and streams records with computed timestamps — no per-frame file opens.
294. Demo neighbourhood construction is seeded (`random.Random(seed)`): reproducible worlds, no entropy syscalls, identical tests on every machine.
295. The neighbourhood is built once per radio; `tick()` only jitters RSSI (+/-4 dB clamp) and bumps counters — O(APs) of arithmetic per second.
296. Demo attack outcomes are pure lookups on the AP record (`handshake_ok`, `pmkid_ok`, `pixie_ok`) — no simulated subprocesses.
297. Demo captures for cracking are synthesised on demand and cached by the session like real loot.
298. The demo radio emits the same `ApRecord`/`ClientRecord` shapes as the airodump parser, so the scanner merge path is shared, not duplicated.
299. Hidden-SSID and client-presence behaviours are flags on the record, evaluated inline during tick.
300. Test certificates are generated deterministically from a SHA-256 seed (name|bits) — no openssl subprocess in the test suite.
301. The whole demo world (Wi-Fi + BLE + IT) runs in-process: a full campaign test needs no hardware, no root and no network.
302. Demo PSKs come from the fake AP records, so the built-in cracker verifies them through the real PMKID/MIC path.
303. `synth` reuses production crypto (`pmk`, `ptk`, `aes_cmac`) rather than test-only reimplementations — one implementation to keep fast.
304. BLE/IT simulators register their worlds lazily on first use, keeping import and engine startup flat.

## U. Interface, scanning & sniffing runtime

305. One `InterfaceManager` owns monitor mode for the whole session: attacks never pay interface setup twice.
306. Interface detection reuses `deps.list_interfaces()` (5 s TTL cache, §J) instead of re-running `iw` per attack.
307. The scanner merges airodump CSV rows into existing AP objects — no throwaway objects per poll (§I).
308. ⚡ CSV cell cleaning and stripping now happen once per cell/line (§P #230–231).
309. Channel/frequency conversion is arithmetic on the channel number, not a lookup subprocess.
310. Scanner subprocess output drains on the shared reader-thread `Process` wrapper with a bounded 4 000-line tail (§L).
311. Probe-request harvesting (`sniff.probe_requests`) caps results (`limit=500`) so a huge capture can't blow up memory.
312. Rogue-AP detection compares already-collected AP dicts (ESSID/BSSID spreads) — no re-parse of the capture.
313. Certificate inspection is a minimal hand-rolled DER TLV walker (name/OID extraction only) — no ASN.1 library, no openssl call.
314. EAP/TLS certificate extraction caps certificates parsed per exchange (`limit_certs=4`).
315. `passive_report` composes the sniff analyses over one parse of the capture instead of re-reading per section.
316. Attack-frame detection counts frame types in the same single pass the parser already makes.
317. Monitor-mode cleanup is registered once (manager lifetime), not per attack — no leaked interfaces, no repeated teardown cost.
318. Live scanners publish through the event bus (§H) — the UI never polls the radio directly.

## V. Reporting, loot & session files

319. The event journal is append-only JSONL through cached line-buffered handles (§H) — crash-safe without fsync-per-line.
320. Session timelines and notes append to JSONL sidecars (`timeline.jsonl`, `notes.jsonl`) — no whole-file rewrites per event.
321. The Markdown report is generated on demand from in-memory state with list-join assembly (§H), never maintained incrementally on disk.
322. `session.export()` reuses the snapshot builders instead of a parallel serialisation stack.
323. Loot filenames are slugified ESSID+BSSID — collision-free naming without directory scans.
324. `save_artifact` copies into the loot dir once; captures reference the final path thereafter.
325. Attempt history per AP is bounded (the report keeps the last 25; `remember()` caps history at 50 entries).
326. Findings/attempts in snapshots are tail-sliced (`[-40:]`, `[-60:]`) — payload size is bounded no matter how long the campaign runs.
327. `write_json` writes via a temp file + atomic replace — readers never see a half-written export, no locking needed.
328. PMK cache (`pmk.PMKCache`) lazy-loads its file once and only on first use; lookups are dict hits by ESSID.
329. PMK cache entries are verified against the actual capture before use (§D) — the cache can be stale without ever being wrong.
330. Mode-22001 conversion (`pmk.line_to_22001`) rewrites hash lines textually — no re-parse of the capture.
331. Hash-file toolbox operations (merge/dedupe/filter/split) stream line-by-line with set-based dedupe keys (`_line_key`).
332. Wordlist statistics sample (`sample_limit=200_000`) instead of reading multi-GB lists to describe them.


## W. CLI, TUI & the Python API

333. The TUI repaints at 4 refreshes/second (Rich `Live`), decoupled from how fast events arrive.
334. Without a TTY (or Rich), the CLI falls back to plain event lines — zero rendering cost in pipes and CI.
335. CLI subcommands import their heavy modules inside the handler (§N), so `wifipilot --help` starts in milliseconds.
336. One engine singleton backs the Python API (`wp.engine()`), the CLI and the web UI — no duplicate state to keep in sync.
337. `Run.wait()` is a thread join, not a polling loop.
338. Background runs (`background=True`) reuse the same campaign thread machinery; `stop()` is an event set + join.
339. API result objects (`Run`, `ScanResult`, `CampaignResult`) are views over the live session — accessors don't copy the AP table.
340. `Run.passwords`/`Run.loot` are properties derived from captures on demand instead of parallel lists maintained during the campaign.
341. Event hooks (`on_event=`) ride the bus subscription (§H) — user callbacks add no polling.
342. Target selection (BSSID/ESSID/list/ALL) resolves against the session dict by normalised MAC (§H #127) — O(1) per target.
343. `--json` output reuses the same `to_dict` shapes as the web API (one serialisation contract, one fast path).
344. The API's mode/preset application is a config rewrite — no engine restart needed to change posture between calls.
345. `wp.ai(disable=True)` flips config fields the advisor reads per call — no client teardown/rebuild cycle.
346. CLI demo runs skip every root/hardware probe (capabilities all-true table, §A #12).
347. Argument parsing is plain argparse with static choice lists — startup never touches the registry to build help.
348. The package `__init__` preloads submodules in dependency order once, so attribute access never triggers surprise imports mid-campaign.

## X. Web frontend (`app.js`) rendering

349. Rendering is throttled: state pushes schedule one render per 250 ms window, however chatty the socket gets.
350. Tables/grids rebuild via a single `innerHTML` assignment from `map(...).join('')` — one reflow per render, not per row.
351. KPI badges and counters update via `textContent` (no HTML parsing for scalar updates).
352. The WebSocket is the primary channel; the 5 s HTTP poll only runs as a fallback when no snapshot has arrived.
353. Advice/auxiliary panels refresh on a 30 s timer, decoupled from the state stream.
354. Toasts self-expire on one timer per element and reuse DOM nodes.
355. Event log lines are appended as single nodes with pre-escaped HTML — no full-log re-render per event.
356. The attack catalogue/model pickers rebuild their `<option>` lists only when the underlying data changes identity.
357. All assets are two static files (HTML+JS, §K #159) — no bundler, no framework runtime, cacheable as-is.
358. Rendering reads the same snapshot object the socket delivered — no per-widget fetches (the edition view ships in the first paint, §K).
359. Socket reconnect uses a delayed retry timer instead of a busy loop.
360. Escape-then-interpolate is centralised (`escapeHtml`) so row templates stay one-liners without repeated sanitiser setup.

## Y. Updater, installer & toolbox

361. The self-updater downloads one ZIP of the branch (no git, no per-file requests) and extracts with zip-slip guards.
362. The update endpoint is assembled from encoded parts at call time — the branch name never sits in the source as plaintext.
363. Version comparison reads the local version constant and the archive's copy — no API calls to decide "already current".
364. A backup of the previous tree is kept beside the install, so a bad update is a rename away from rollback — no re-download.
365. Tool installation planning is pure data (argv per distro family) computed without running anything (§J #148).
366. The installer probes the package manager once per plan and reuses the registry's missing-tool list (§J).
367. Post-install verification is one registry re-probe (`probe(force)`), which also invalidates every cached view exactly once (§J #144).
368. Toolbox hash merges dedupe by a cheap tuple key before any expensive verification runs.
369. `rescue_partial_capture` works from the existing pcap analysis (cached, §I) instead of re-parsing the file.
370. Wordlist merges stream (`iter_words` with length filters) — output written incrementally, inputs never fully resident.
371. Hash-file normalisation canonicalises line-by-line (`_canonical_line`) with no intermediate list of the whole file.
372. Split/merge utilities report counts as they go — no second pass to summarise.

## Z. Attack runtime internals

373. `Attack.available()` is a capability-dict check (cached §J) — unusable attacks are skipped before any setup runs.
374. Every attack runs under its memoised budget (§A #9) enforced by the shared runner, not per-attack timers.
375. The runner records outcomes through one `AttackOutcome` shape — bookkeeping is a few field writes, not serialisation.
376. Demo branches short-circuit at the top of `run()` in the shared helpers, so live-only tool resolution never happens in simulation.
377. Tool paths resolve through `registry.resolved` (§J #147) per attack — no PATH walks in the hot loop.
378. Attacks share capture/loot helpers (`_credential_capture`, session `add_capture`) — one place builds Capture records.
379. Deauth/capture attacks reuse the session's monitor interface (§U #305) and channel state instead of re-hopping per attempt.
380. WPS PIN candidates come from static scheme tables (computed PINs, known defaults) ordered by likelihood — no brute-force generation upfront.
381. The WPS checksum/half-PIN structure is exploited to reject wrong halves early (the pixie/offline paths never go on air at all).
382. Evil-twin/rogue helpers render hostapd/dnsmasq configs from templates in memory — written once per run, not per client.
383. Flood attacks build their frame templates once and vary only the per-frame fields (addresses/sequence) in the send loop.
384. Enterprise/EAP attacks parse the exchange with the shared sniff DER/EAP walkers (§U) instead of per-attack parsers.
385. SAE/WPA3 analysis reuses the shared IE parser (`ies.py`) — beacon elements are decoded once and shared between audits.
386. Offline-category attacks (loot/IE/PMF/EAPOL audits) run entirely on already-parsed analyses — zero radio time, zero re-parse.
387. Side-lane eligibility is a metadata test (§F) — the engine never speculatively starts an attack to learn it's radio-bound.
388. Attack modules register classes at import into one dict (§M #175); lookup by name is O(1) everywhere downstream.

## AA. Data files, static tables & the remaining engines

389. The OUI registry ships as a curated JSON subset (~Wi-Fi/CPE vendors) parsed once at first use — not the 35k-line IEEE file per lookup.
390. OUI matching tries the exact 24-bit prefix, then 28-bit blocks — two dict hits worst case (§L #166).
391. Vendor default-pattern data (`data/default-patterns.json`) loads once at import into plain dicts.
392. `analytics.vendor_patterns` tokenises hints once and matches on lowered tokens against those dicts.
393. Built-in wordlists are small curated files in `data/` — the built-in engine always has something to try without downloads.
394. Mask charsets are module constants; candidate generation is `itertools.product` over them (§D) with the space pre-counted before starting.
395. `select_masks` fits suggested masks to a candidate budget *before* generating anything.
396. IE (information element) names/capability bits decode via static tables in `ies.py`; unknown elements fall back to hex without exceptions.
397. `accel.detect()` is `lru_cache`d as a whole (CPU/RAM/GPU probe runs once per process unless forced).
398. Acceleration summaries (`accel_summary`) are derived from that cached detection — no repeated `/proc` reads per snapshot.
399. Edition/device catalogues (`itdev.edition_catalog`) are assembled from static tables and memoised by the web layer (§K).
400. This catalogue is the regression net: `scripts/bench.py` + `tests/test_optimizations.py` pin the numbers above so the next 400 entries start from a measured baseline.


## AB. Campaign wall-clock — the seconds round (⏱ = new)

401. ⏱ Discovery ends early once the neighbourhood settles: `scan_for` exits at 40% of the window with a quiet last 40% (or 70% with a quiet quarter). Another silent channel-hop cycle finds nothing — it only delays the first attack (blitz discovery 12.0 s → 5.1 s; the full window still runs while APs keep appearing).
402. ⏱ Echo rounds eliminated: a fully executed plan is never handed back for a second round of stale skips (`planner.plan_completed` + a heuristic bridge in `_maybe_replan`). Previously *every* productive round was followed by one wasted round.
403. ⏱ Empty-plan rounds break immediately when everything in scope is handled, and poll at 2 s instead of sleeping a whole scan window (10–30 s) per round once targets exist — the old code added a ~36 s dead tail to finished campaigns.
404. ⏱ The round-end breather is 0.25 s, not a flat 2.0 s nap added after attacks that already took seconds (multiplied by every round of a large preset, this alone was minutes).
405. ⏱ The planner is scope-aware: `rank_targets`/`heuristic_plan` take the campaign's wanted set, and `think()` drops out-of-scope actions (LLM overreach lands in `plan.dropped`). No more nominations the loop can only reject.
406. ⏱ `target=all` is no longer snapshotted at selection time: access points discovered mid-campaign are attacked too. The old snapshot silently exempted late arrivals *and* fuelled the planner/loop disagreement behind #403.
407. ⏱ Failed cracks are remembered per capture with the budget spent (`crack_tried_timeout`): the planner, the loop and the pending-crack pass consult `crack_worth_trying`, so one uncrackable capture can no longer re-run the same wordlists until the campaign deadline. Quick-then-full escalation still works (a 180 s stamp does not block a 600 s budget), a fresh capture reopens cracking, and operator-forced cracks are never gated.
408. ⏱ Plan-nominated and pending cracks run on the crack lane when `parallel_crack` is on — the radio lane no longer stalls for up to `crack_timeout` (600 s) per capture. An in-flight marker (`crack_queued`) prevents double-cracks, campaign completion now counts lane cracks, and the shutdown reap covers a full crack while staying stop-responsive (sliced waits).
409. ⏱ One (target, attack) at a time: an engine in-flight guard at the `run_attack` funnel refuses concurrent duplicates from any lane, the planner prunes attacks with a running attempt, and the per-round answer cache is refreshed before the side sweep (it used to re-submit instant audits the plan had just run).
410. ⏱ The engine's `attackable` fingerprint is outcome- and crack-state-aware (success/failed/running counters, crack stamps, `crack_timeout`, `skip_crack`) — a status flip changes no list length, so the old count-only key served stale ladders.
411. ⏱ The measurement harness for all of the above: `scripts/bench_campaign.py` runs seeded demo campaigns (`blitz` 79.8 s → 39.4 s, `success` 107.9 s → 42.2 s, with *more* passwords — the saved time is spent attacking, and previously skipped targets are no longer skipped). Guards: the wall-clock section of `tests/test_optimizations.py`.


## AC. Live-radio detection latency (⏱ = newest)

These three are live-path only — demo benchmarks cannot see them, because the
simulated radio delivers captures instantly. On real hardware each one removes
dead wait between "the packet exists" and "wifipilot knows about it".

412. ⏱ The live scanner polls the airodump CSV every 0.25 s instead of 1.0 s, gated on the file's mtime so an unchanged file costs one stat per slice; the expensive bits (per-AP stats, WPS correlation) still run at a 1 s cadence. A new AP or a newly associated client is noticed up to ~0.75 s sooner — and the settled-discovery detector (§AB) converges on fresher data.
413. ⏱ Handshake hunting re-analyzes the capture every 0.25 s but only when its size actually changed (bounded at 60 000 packets so a late-campaign capture cannot stall the poll), and the fixed 1.5 s "let airodump flush" nap is now a settle-wait: it proceeds as soon as the file size is stable across two 0.15 s checks (1.5 s cap). A good handshake is typically confirmed ~1.3 s earlier per successful capture, and cracking starts that much sooner.
414. ⏱ The PMKID hunt checks the hcxdumptool output *before* its first sleep and then every 0.25 s with the same size gate (progress reported at 1/s so the event bus stays quiet). PMKIDs arrive in the first seconds of a burst; the old 1 s loop paid up to a second of pure latency on every one of them.

## AD. Startup & simulation wall-clock (⏱ = newest)

415. ⏱ The attack registry is imported lazily. `import wifipilot` used to load all 46 attack modules (848 registered attacks) through `api.py` before returning anything — 655 ms before `wp.config()` could even be called; light CLI commands paid ~710 ms of import to print JSON. The registry, `Engine`, `ALL_ATTACKS` and `MODES` now materialise on first touch (PEP 562), so `import wifipilot` is ~78 ms, `import wifipilot.cli` ~95 ms, and `wifipilot --json config` finishes in ~0.13 s end to end. A real campaign still loads the registry once, when the engine is built.
416. ⏱ `models.ATTACK_NAMES` is statically complete: all 848 names are written in the file (the list used to hold 107 hand-curated names and silently grow to 848 as a side effect of importing `wifipilot.attacks`). Every cheap consumer — CLI `--attacks` validation and help text, the planner whitelist, preset resolution — is now correct *before* the registry loads, which is what makes 415 safe. An AST-level test compares the written list against the live registry so the two can never drift apart.
417. ⏱ The public package surface is shadow-proof. Six API functions share a name with a submodule (`wp.crack` vs `wifipilot/crack.py`, likewise config/demo/engine/presets/session); Python rebinds the package attribute to the submodule when it first loads, so a deferred import flipped `wp.demo` into a module object. The package module now resolves those six names to the functions deterministically (submodules stay reachable via `sys.modules`/`importlib`), with a regression test that imports every collider late on purpose.
418. ⏱ Demo simulations report simulated seconds without sleeping them. The flood/tracker demo loops ticked real `time.sleep` calls for the whole simulated window — a real 8–12 s per demo flood. They now run a shared short cadence (`base.DEMO_TICKS` × `DEMO_TICK_SECONDS` ≈ 0.25 s wall) while reporting the simulated duration, so demo campaigns and the progress stream stay honest but stop wasting wall-clock; the single slowest test in the suite fell from 170 s to 5 s.
419. ⏱ The WPS PIN attempt order got arithmetic check digits, and its callers stopped materialising 10⁷ PINs. Walking the full checksum-valid space through `complete_pin()` cost ~30 s of CPU; splitting the weighted digit sum into per-prefix/per-middle parts yields the identical sequence in ~6 s. Bigger still: the CLI/API/web `pins` endpoints built the whole 10,000,000-entry list to return the first page — they now `itertools.islice` the generator, taking `wifipilot --json pins …` from 30.3 s to 0.18 s.
420. ⏱ CI runs the full suite in parallel (`pytest-xdist`, `-n 2 --dist loadfile`). The suite is wait-heavy — simulated campaigns and real PBKDF2 — so two workers overlap waits instead of stacking them: the full-suite step's share of each job roughly halved, bringing whole CI jobs from ~6 min (already down from ~12–14 min by 415–419) to ~4 min. Two workers, not `-n auto`: four on the 4-core runner oversubscribed the CPU (each worker can spawn its own crack process pool) and was part of a deterministic 3.13-only failure that bisection pinned on a companion change (removing the presets preload 417 made redundant on paper; restored — its ~13 ms is inside import-time jitter anyway, 55–102 ms measured either way). The same round also measured the built-in cracker's verify path at the raw-PBKDF2 floor (408–418 candidates/s against 413/s for `pbkdf2_hmac` alone — nothing left to shave) and rejected a campaign-loop "wake on lane completion" change that was 6 s faster on the seeded bench but recovered 9 passwords instead of 12: the loop's round counters treat cadence as behaviour, so that one stays out.

---

*Credits: [codero-sus](https://github.com/codero-sus) · [the-codero.web.app](https://the-codero.web.app)
