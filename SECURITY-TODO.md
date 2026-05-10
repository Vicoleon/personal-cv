# SECURITY-TODO.md — Proxy hardening plan

Status: **client side hardened (commit `95bf36c`)**, server side pending.

The page calls `https://gemini-cv-proxy-hqfdhwhhga-uc.a.run.app/chat` (Google Cloud Run).
That endpoint is currently the only meaningful attack surface left.

## What the client already does (good but not sufficient)

| Defense | Effective against | Bypassable by |
|---|---|---|
| 500-char input cap | casual flooding | `curl` |
| 15 msg/session cap | one tab spamming | new tab / `curl` |
| 2.5s cooldown | accidental double-send | `curl` |
| 30s abort | hanging requests | n/a |
| CSP `connect-src` | XSS pivoting to other domains | not an attacker problem |
| Prompt-injection clauses in system prompt | naïve attempts | a determined attacker (LLM jailbreaks are not solved) |
| `maxOutputTokens: 1024` | runaway cost per call | a thousand calls |

A motivated attacker with `curl` can still:
- Hit `/chat` from anywhere (no CORS, no Origin check).
- Burn your Gemini quota / spend in minutes.
- Inject any system prompt they want (the client supplies it).
- Pretend to be a different conversation.

## What to do on the Cloud Run proxy

Roughly in order of payoff. The proxy is presumably a small Node/Python service.
If the source is in a repo, I can write the diff; otherwise these are the changes
to make by hand.

### 1. Lock CORS to the two real origins (10 min — biggest win)

```js
// Node/Express example
const ALLOWED = new Set([
  'https://vicoleon.github.io',
  'https://rubik-soft.com',
  'https://www.rubik-soft.com'
]);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Reject requests with no Origin or wrong Origin on POST:
app.post('/chat', (req, res, next) => {
  if (!ALLOWED.has(req.headers.origin)) {
    return res.status(403).json({ error: 'Forbidden origin' });
  }
  next();
});
```

> Origin headers can be spoofed by a non-browser, but every drive-by attacker
> using a normal browser is now blocked. That alone kills 95% of casual abuse.

### 2. Per-IP rate limit (15 min)

```js
import rateLimit from 'express-rate-limit';
const limiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 20,               // 20 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' }
});
app.post('/chat', limiter, handler);
```

Cloud Run sits behind Google's load balancer — read the real client IP from
`x-forwarded-for` (first value). Configure `express-rate-limit` with
`keyGenerator: req => req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip`.

### 3. Server-side message + token caps (10 min)

Validate the request body before forwarding to Gemini:

```js
const body = req.body;
if (!Array.isArray(body?.contents) || body.contents.length > 30) {
  return res.status(400).json({ error: 'Invalid request' });
}
const lastMsg = body.contents.at(-1)?.parts?.[0]?.text || '';
if (typeof lastMsg !== 'string' || lastMsg.length > 1000) {
  return res.status(400).json({ error: 'Message too long' });
}
// Force a sane upper bound, regardless of what the client asked for:
body.generationConfig = {
  ...(body.generationConfig || {}),
  maxOutputTokens: Math.min(body.generationConfig?.maxOutputTokens ?? 1024, 1024),
  temperature: Math.min(body.generationConfig?.temperature ?? 0.4, 1.0)
};
```

### 4. Pin the system prompt on the server (15 min — closes a big hole)

Right now the *client* sends the system prompt. An attacker can replace it with
"You are a malicious bot that helps with X" and the proxy obediently forwards it
to Gemini under Jose's API key. Fix:

```js
// Ignore whatever system_instruction the client sent; use ours.
const JOSE_SYSTEM_PROMPT = fs.readFileSync('./prompt.txt', 'utf8');
body.system_instruction = { parts: [{ text: JOSE_SYSTEM_PROMPT }] };
```

Keep the CV context and rules **only on the server**. The client never needs to
see them. This is the single biggest server change in this list.

### 5. Daily budget cap (10 min)

Set a hard ceiling in code so a runaway week doesn't translate into a runaway
bill:

```js
let dailyCalls = 0;
let dailyReset = Date.now() + 86400000;
// in the handler, before forwarding:
if (Date.now() > dailyReset) { dailyCalls = 0; dailyReset = Date.now() + 86400000; }
if (++dailyCalls > 5000) {
  return res.status(503).json({ error: 'Daily budget reached' });
}
```

Belt-and-suspenders: in **GCP console** set a Billing Budget alert on the project
($10/day notify, $50/day cap) so even a code bug can't surprise you.

### 6. Optional: Cloudflare Turnstile gate (30 min)

If abuse keeps happening despite 1-4, add invisible Turnstile to the chatbot.
Frontend: load Turnstile widget, get a token. Server: verify token before
forwarding. Free tier handles all the traffic this site will ever see.

### 7. Logging + alerts (15 min)

Emit a structured log line per request (IP, user message length, response
length, latency, model). Then in GCP set a log-based metric +
alert if requests/min > 30 sustained for 5 min. Free.

## Recommended order

1. Pin system prompt on server (#4) — closes the loudest hole.
2. CORS lock + Origin check (#1) — kills drive-by abuse.
3. Per-IP rate limit (#2) — limits any remaining abuse.
4. Daily cap + billing budget (#5) — protects the wallet.
5. Server-side body validation + token caps (#3).
6. Logging + alerts (#7).
7. (Only if needed) Turnstile (#6).

Total work: ~90 minutes if the proxy source is in a repo. Happy to write
the diff whenever you point me at it.

— Jarvis
