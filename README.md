# FAE False-Positive Benchmark

A deliberately mixed Express monolith for comparing:

- a deterministic/rules-based SAST pass that may over-report source-to-sink flows
- a context-aware FAE/AI analysis pass that may suppress findings when validation, encoding, allowlisting, authorization, or safe API usage makes the path non-exploitable

## Fixture composition

- **19 safe bait paths**
- **10 planted true positives**
- One `app.js` monolith
- Express JSON API with a few HTML/file/redirect endpoints
- No database or external service dependency required for scanning
- Node.js 20+

The safe cases intentionally place untrusted request data near recognizable sinks while neutralizing it through:

- HTML encoding
- parameter binding
- closed enum/allowlist mapping
- strict URL validation
- internal-only redirects
- path containment checks
- `execFile()` with separate arguments
- object ownership checks
- authorization middleware
- allowlisted object copying
- cryptographically secure randomness

The vulnerable twins omit those controls.

## Run

```bash
npm install
npm start
```

Health check:

```bash
curl http://localhost:3000/health
```

## Suggested Checkmarx comparison

Scan the exact same commit twice:

1. FAE enabled
2. FAE disabled

Use the same:

- tenant
- preset
- branch
- source package
- scan configuration
- severity filters

Then grade every result against `answer-key.json`.

## Metrics

Track:

- True positives caught out of 10
- False positives raised against the 19 safe bait routes
- Precision
- Recall
- Findings unique to each engine
- Whether the reported data flow includes a sanitizer/validator that the engine ignored

## Important caveat

This fixture is designed to create opportunities for false positives, but it cannot guarantee that a particular Checkmarx query pack or engine version will produce 10+ false positives. Query coverage and engine behavior vary by release and configuration. Add or duplicate safe bait patterns that actually trigger in your tenant after the first baseline run.
