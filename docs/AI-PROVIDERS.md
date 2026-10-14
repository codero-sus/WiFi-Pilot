# AI providers: Ollama and Cortex LLMHoster (local), OpenRouter (cloud)

**Why "AI-piloted" and "optional" are not a contradiction.** The pilot is the advisor: it
proposes which attack to run against which target, and wifipilot validates the proposal
against the attack registry and the live session before anything reaches the radio. A pilot
that is switched off is simply a plane flown by its deterministic autopilot — the name
describes what the tool *can* do, not a requirement to run a model.

wifipilot's "auto think" needs a model. It does not need to have one: the deterministic
planner runs every engagement on its own, and the advisor is an additive extra. This page is
about the ways to give it a model.

**Turning it off is one switch with several spellings** (all identical):

```bash
wifipilot --no-ai attack -d 45m   # --disable-ai and --offline are aliases
wifipilot ai off [--save]         # switch it off; --save persists ai_provider="none"
wifipilot ai on [ollama]          # ...and back on
WIFIPILOT_NO_AI=1 wifipilot web   # this shell only (also true/yes/on)
```
```python
import wifipilot as wp
wp.ai(disable=True)               # wp.ai(disable=False) restores the previous provider
```

While it is off nothing is probed, no daemon is asked for a model list, and `status`,
`models`, `pull`, `use` and `ask` all answer "off" instead of trying. The dashboard shows
`AI: off · deterministic`, the web header shows `ai: off · deterministic planner`, and the
advisor tab is greyed out with a single button to bring it back.

Choose a provider per run, per config file, or from the web UI:

| | **Ollama** (default) | **Cortex LLMHoster** | **OpenRouter** |
|---|---|---|---|
| Where the model runs | your machine (`127.0.0.1:11434`) | your machine (`127.0.0.1:8624`) | a third-party cloud service |
| Cost | free (your CPU/GPU) | free (your CPU/GPU) | pay per token, some models free |
| Data leaving the box | nothing | nothing | SSIDs, BSSIDs, client MACs, and *unless you turn redaction off* nothing else |
| Best models for planning | 7–14B instruct (qwen2.5, llama3.1) | the GGUF you point it at | anything; small fast models are plenty |
| Setup | `ollama serve` + `ollama pull` | `cortex-llmhoster --config cortex.toml` (it starts `llama.cpp` itself) | an API key from <https://openrouter.ai/keys> |
| Works offline | yes | yes | no |
| API | Ollama's own | OpenAI-compatible (`/v1/chat/completions`) | OpenAI-compatible |

Select with the command line (`--provider`), the config file (`ai_provider`), or the
**Model provider** card in the web UI. `auto` (the default) prefers a local model
(Ollama, then Cortex LLMHoster) and only falls back to OpenRouter if it is explicitly
enabled *and* has a key.

```bash
wifipilot ai providers                       # what is configured, what is missing
wifipilot --provider ollama attack -d 45m    # local model plans the engagement
wifipilot --provider openrouter --model openai/gpt-4o-mini attack -d 45m
wifipilot ai use openai/gpt-4o-mini --provider openrouter --save   # persist the choice
```

If no model is reachable — or you switched it off — nothing breaks: the deterministic
planner in `wifipilot/planner.py` does the job, and every plan is labelled `heuristic`
(or `planner`, in the dashboard, when the advisor was disabled on purpose).

---

## Cortex LLMHoster (local, OpenAI-compatible)

`Cortex LLMHoster <https://github.com/codero-sus/Cortex_LLMHoster>`_ is a local model host:
you give it GGUF paths (or a command that starts your own OpenAI-compatible engine) in
`cortex.toml` and it starts, supervises and serves them behind the OpenAI API, with a
dashboard for the details. It is the middle ground between Ollama (easy, but its own API and
its own model store) and running `llama-server` by hand (every flag is yours to forget).

wifipilot treats it as what it is — a **local service on the loopback interface**:

* nothing is probed until `cortex.enabled` is true (or you pass `--provider cortex`);
* the host must be loopback (`127.0.0.1`, `localhost`, `::1`) unless
  `cortex.allow_remote_host=true` says otherwise, because the API has no transport security
  of its own;
* the key is optional: Cortex runs keyless on a trusted listener
  (`CORTEX_API_AUTH_ENABLED=false`), and when a key *is* configured it is read from
  `CORTEX_API_KEY` and sent as a bearer token, never logged and never returned over the API;
* nothing leaves the machine, so no consent flag and no identifier redaction is involved.

```bash
cortex-llmhoster --config cortex.toml          # start the hoster (default 127.0.0.1:8624)
wifipilot --provider cortex ai status          # wifipilot talks to it
wifipilot --provider cortex --cortex-model qwen-local attack -d 45m
wifipilot ai providers                         # the three providers, side by side
```

```json
{
  "cortex": {
    "enabled": true,
    "host": "http://127.0.0.1:8624",
    "model": "qwen-local"
  }
}
```

`--cortex-host` overrides the URL for one run (`--provider cortex --cortex-host
http://127.0.0.1:9000`), and the web UI's **Model provider** card has a `use cortex` button
and the host field next to it. A model that is slow to load is expected: this provider's
default timeout is 300 s, not 120.

## Ollama (local, private — the default)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve                      # or: systemctl enable --now ollama
ollama pull qwen2.5:7b            # ~4.7 GB; llama3.1:8b, gemma2:9b also work well
wifipilot ai status
```

* Only **loopback** hosts are allowed. Pointing it at another machine is refused
  unless you set `ollama.allow_remote_host = true` — at which point the engagement
  data leaves your box, exactly like a cloud provider.
* `wifipilot ai models` lists what is installed; `wifipilot ai pull <model>` installs
  one (the web UI can do both).
* Prompts are small: the situation report is a few hundred tokens, so a 7B model on a
  laptop answers in seconds and a 3B model is still usable.
* Model choice: `llama3.1:8b`, `qwen2.5:7b`, `mistral:7b`, `gemma2:9b`, `phi3:mini`.
  Avoid coder/vision/embedding models — they are penalised by the auto-picker because
  they follow the JSON schema poorly.

## OpenRouter (cloud, explicit consent)

```bash
export OPENROUTER_API_KEY=sk-or-v1-...        # create one at openrouter.ai/keys
wifipilot ai providers --probe                # verifies the key and shows your quota
wifipilot --provider openrouter ai status
```

Prefer the environment variable or a key file over the command line (a key typed on
the command line lands in your shell history):

```jsonc
"openrouter": {
  "enabled": true,
  "api_key_env": "OPENROUTER_API_KEY",     // recommended
  "key_file": "~/.config/wifipilot/openrouter.key",   // or a 0600 file
  "api_key": "",                           // last resort: the config file itself
  "model": "openai/gpt-4o-mini"
}
```

`wifipilot.json` is written with mode `600` because it may hold a key, and the key is
**never** returned by `GET /api/config`, `GET /api/state` or the web UI — the API only
reports `has_api_key`, the source (`environment`, `key file`, `config file`) and the
key length. `wifipilot ai providers` and `ai status` print the same non-revealing
fingerprint, so a screenshot or a pasted log cannot leak it.

### Privacy: identifier redaction (on by default)

The situation report is the only thing sent, and before it leaves the machine every
engagement identifier is replaced by a stable pseudonym:

```
real                                  sent to OpenRouter
dc:c2:5e:80:33:bb   (BSSID)     →     bssid-1
HOME-2F4A           (SSID)      →     ssid-1
sunshine2015        (PSK)       →     psk-1
02:00:00:00:00:09   (client)    →     mac-1
```

The substitution is textual and total — it also rewrites identifiers that appear in
free-text fields such as findings, failure details or a working directory. The model
still gets everything it needs to reason ("`ssid-2` is WPA2 with WPS unlocked, one
client, a PSK is already recovered"), and wifipilot maps the aliases back to real
BSSIDs *before* the plan is validated, so the attack still targets the right access
point even though the model never learned its name.

Turn it off only when you deliberately want the model to see the real names:

```bash
wifipilot --provider openrouter --no-ai-redact attack -d 30m
```

Reality check: with redaction on, the provider still learns your **client's
fingerprint** (how many APs, their security posture, which attacks you run) and, from
your key, who you are. If the engagement contract forbids third-party processing, use
Ollama. The tool never sends captures, hashes, handshakes or wordlists — only the
tactical summary.

### Cost control

```bash
wifipilot --provider openrouter --ai-budget 0.50 attack -d 45m
```

* `ai-budget` (config: `openrouter.max_cost_usd`) is a hard stop: once the spend for
  the session reaches it, the advisor stops planning and the deterministic planner
  takes over. `0` means unlimited.
* Every response's usage (including OpenRouter's own `usage.cost`) is accumulated and
  shown in `wifipilot ai status`, in the web UI, in the report and in
  `session.stats.llm_cost`.
* A rough guide: a plan costs ~1–3k tokens; with a cheap model (for example
  `openai/gpt-4o-mini` or `google/gemini-2.5-flash`) a 45-minute engagement with
  re-planning every 45 s stays well under a cent. Free models cost nothing but are
  rate limited and often weaker at JSON.
* Provider routing preferences pass straight through (`"provider_routing": {"sort":
  "throughput"}`), so you can require providers that permit your traffic or prefer
  cheap/fast ones.

### Failing safely

Everything a provider can do wrong has a defined behaviour, and none of it stops the
engagement:

| Situation | What happens |
|---|---|
| no API key / provider disabled / `http://` base URL | refused **before** anything is sent, with instructions; heuristics plan instead |
| wrong or revoked key (401/403) | one clear "authentication failed" error, then heuristics; the campaign continues |
| out of credits (402) | warns once with the top-up link, switches to heuristics |
| rate limited (429) | logged, that call is skipped, next cycle retries |
| no egress / proxy needed | transport error explains it and suggests `--provider ollama` |
| model returns prose instead of JSON | rejected, deterministic planner fills in the plan |
| model proposes something unsafe | `planner.validate_plan()` drops it and reports it in the UI |
| spend over budget | planning stops, heuristics take over, reason shown in the UI |

Requests are attributed to the project (OpenRouter's `HTTP-Referer`/`X-Title`
headers), so spend can be traced per app in their dashboard.

## What the model is allowed to decide

Only the *order and choice* of actions, and only from this closed vocabulary:
`pmkid`, `handshake`, `wps_pixie`, `wps_pin`, `wep_ivs`, `passive`, `crack`, `stop`.
Whatever the model says is re-validated against the live session: unknown BSSIDs,
disabled attacks, WPA3 handshake attempts, WPS attacks on non-WPS access points,
stealth-mode violations and cracking without captures are all dropped and surfaced to
the operator. The engine additionally refuses to transmit at all without explicit
authorisation, no matter what any planner asks for.
