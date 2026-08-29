# BreakTrace

> **Find vulnerabilities. Turn them into tests. Keep them from coming back.**

BreakTrace is an AI-assisted security regression testing platform built for rapidly developed web applications. It inspects an application inside an isolated security twin, runtime-verifies security failures, and converts verified vulnerabilities into persistent regression tests.

Traditional security scanners tell developers what is broken **now**. BreakTrace goes further: it remembers verified security failures and automatically checks whether previously fixed vulnerabilities return in future versions.

---

## Project Overview

Vibe coding makes it possible to ship applications incredibly quickly, but security validation often struggles to keep pace with that speed.

BreakTrace provides a continuous security feedback loop:

**Discover → Verify → Remember → Replay → Detect Regression**

Instead of producing a disposable vulnerability report, BreakTrace converts verified failures into **Security Memory** — executable security regression tests that can be replayed as the application evolves.

The result is a security system designed around a simple principle:

> **Every verified break should become a test.**

---

# Why BreakTrace?

Modern AI-assisted development dramatically reduces the time required to build software.

That creates a new problem.

A developer can:

1. generate a feature,
2. introduce a vulnerability,
3. fix the vulnerability,
4. continue prompting and modifying the application,
5. accidentally reintroduce the same security failure later.

Traditional point-in-time scanning does not solve this lifecycle problem particularly well.

BreakTrace treats a verified vulnerability as something worth **remembering**.

```text
Vulnerability discovered
        ↓
Runtime verified
        ↓
Converted into regression test
        ↓
Stored in Security Memory
        ↓
Application changes
        ↓
Same security invariant replayed
        ↓
PASS                     REGRESSION
Fix still works          Vulnerability returned
```

This changes security testing from:

> "What vulnerabilities exist right now?"

into:

> "What security properties has this application previously violated, and do they still hold today?"

---

# Key Features

## 🔎 Application-Aware Security Discovery

BreakTrace builds an application context before AI exploration.

Depending on the target, discovery can identify information such as:

- runtime routes
- frameworks
- dependencies
- API references
- identity inputs
- resource relationships
- ownership semantics
- data resources
- storage resources
- external services
- authentication signals
- environment-variable references
- seeded entities for bounded testing

This gives the security analysis layer application-specific context instead of asking an AI model to blindly guess endpoints.

---

## 🧠 AI-Assisted Security Exploration

BreakTrace uses an AI-assisted reasoning layer to generate security hypotheses from discovered application semantics.

For example, given:

```text
Identity:
X-Demo-User → user_id

Resource:
reports

Ownership:
report.owner_id → user_id

Known principals:
1, 2

Known reports:
1, 2
```

BreakTrace can reason about a concrete cross-user authorization experiment:

```http
GET /api/reports/2
X-Demo-User: 1
```

with the security expectation:

```text
403 Forbidden
```

AI output is treated as a **hypothesis**, not proof of a vulnerability.

---

## 🧪 Runtime Verification

BreakTrace does not trust an AI-generated vulnerability claim by itself.

The pipeline is:

```text
AI proposes
    ↓
BreakTrace validates
    ↓
Security Twin executes
    ↓
Runtime evidence collected
    ↓
BreakTrace verifies
```

Only runtime-evidenced security failures become verified findings.

This reduces the risk of turning hallucinated AI output into security claims.

---

## 🧱 Isolated Security Twins

Target applications can be prepared and executed inside disposable isolated environments.

This separates security experimentation from the user's production application and gives BreakTrace a controlled environment for:

- application discovery
- deterministic checks
- AI-generated experiments
- runtime verification
- Security Memory replay

---

## 🧠 Security Memory

Security Memory is the core BreakTrace capability.

A verified security failure becomes a reusable executable test.

Example:

```text
BT-001

Category:
Broken Access Control

Invariant:
A user must not access another user's report.

Principal:
User 1

Request:
GET /api/reports/2

Identity:
X-Demo-User: 1

Expected:
403 Forbidden
```

BreakTrace stores enough context to replay the security condition later.

Security Memory entries use stable fingerprints and application-scoped identifiers to prevent duplicate tests from accumulating across repeated assessments.

---

## 🔁 Automatic Regression Replay

When a stored BreakTrace exists, the same request can be replayed against a later application version.

### Fix verified

```text
BT-001

Expected: 403
Observed: 403

PASS
```

The security invariant still holds.

### Regression detected

```text
BT-001

Expected: 403
Observed: 200

REGRESSION
```

A previously fixed security condition has returned.

---

## 🛡️ Deterministic Security Analysis

BreakTrace complements AI exploration with deterministic checks.

Current analysis includes checks around areas such as:

- Content-Security-Policy
- X-Content-Type-Options
- Referrer-Policy
- frame protection
- cookie security
- CORS configuration
- accidental sensitive-file exposure
- hardcoded client secrets
- authentication-related client storage

This hybrid approach means BreakTrace does not depend entirely on AI reasoning.

---

## 👤 Identity and Ownership-Aware Testing

BreakTrace can model security semantics such as:

```text
Principal A
    ↓
requests
    ↓
Resource owned by Principal B
```

This enables higher-quality authorization experiments rather than confusing:

```text
anonymous → protected resource
```

with:

```text
authenticated user A → user B's resource
```

That distinction matters when verifying vulnerabilities such as IDOR / broken object-level authorization.

---

## 🔐 Safe Experiment Validation

AI-generated experiments pass through BreakTrace validation before execution.

Validation includes controls around:

- discovered routes
- concrete resource identifiers
- known seed entities
- allowed request headers
- identity semantics
- request-header sanitization
- executable HTTP experiments

The AI layer proposes experiments; it does not receive unrestricted control of the execution environment.

---

## 💾 Duplicate-Resistant Security Memory

Repeated assessments should not create endless copies of the same security test.

BreakTrace fingerprints tests using stable properties such as:

- principal
- HTTP method
- normalized path
- expected status
- category
- invariant
- relevant request headers

This allows repeated discoveries of the same security condition to resolve to the same remembered test.

---

## 🖥️ One-URL Inspection Experience

The user-facing workflow is intentionally simple:

```text
┌──────────────────────────────────────────────┐
│ https://your-application.example             │
└──────────────────────────────────────────────┘

             Inspect Application
```

Behind that single action, BreakTrace can coordinate:

```text
Resolve Application
        ↓
Create Security Twin
        ↓
Discover Application
        ↓
Run Deterministic Checks
        ↓
AI Security Exploration
        ↓
Validate Experiments
        ↓
Runtime Verification
        ↓
Save Verified BreakTraces
        ↓
Replay Security Memory
        ↓
Detect Regressions
```

The complexity stays inside BreakTrace rather than being exposed to the developer.

---

# Demo: A Vulnerability That Comes Back

The included regression demo demonstrates the complete BreakTrace lifecycle using cross-user access control.

## Stage 1 — Discover

The vulnerable application contains reports owned by different users.

BreakTrace tests:

```http
GET /api/reports/2
X-Demo-User: 1
```

Report 2 belongs to User 2.

Secure behavior:

```text
403 Forbidden
```

Observed vulnerable behavior:

```text
200 OK
```

BreakTrace verifies the cross-user access failure.

---

## Stage 2 — Remember

The verified failures become Security Memory tests:

```text
BT-001
User 1 → Report 2

BT-002
User 2 → Report 1
```

These are no longer merely findings in a report.

They are executable security regression tests.

---

## Stage 3 — Verify

BreakTrace replays the same tests against the fixed application.

```text
BT-001
Expected 403
Observed 403
PASS

BT-002
Expected 403
Observed 403
PASS
```

Result:

```text
2 replayed
2 passed
0 regressions
```

The fix is verified.

---

## Stage 4 — Detect

The application changes again and the authorization flaw returns.

BreakTrace replays the **same Security Memory**:

```text
BT-001
Expected 403
Observed 200
REGRESSION

BT-002
Expected 403
Observed 200
REGRESSION
```

Result:

```text
2 replayed
0 passed
2 regressions
```

BreakTrace detects that previously fixed security behavior has been broken again.

---

# Architecture

```text
                         ┌─────────────────────┐
                         │      Developer      │
                         └──────────┬──────────┘
                                    │
                              Application URL
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ BreakTrace Frontend │
                         │ Next.js + TypeScript│
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │  FastAPI Backend    │
                         │ Orchestration Layer │
                         └──────────┬──────────┘
                                    │
                  ┌─────────────────┼─────────────────┐
                  │                 │                 │
                  ▼                 ▼                 ▼
          ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
          │ Application  │  │Deterministic │  │ AI Security  │
          │  Discovery   │  │    Checks    │  │ Exploration  │
          └──────┬───────┘  └──────────────┘  └──────┬───────┘
                 │                                     │
                 └─────────────────┬───────────────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │ Proposal Validation  │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │   Daytona Security   │
                        │        Twin          │
                        └──────────┬───────────┘
                                   │
                            Runtime Evidence
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │ Verified BreakTrace  │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │   Security Memory    │
                        └──────────┬───────────┘
                                   │
                             Future Versions
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │ Regression Replay    │
                        └──────────┬───────────┘
                                   │
                          ┌────────┴────────┐
                          ▼                 ▼
                    Fix Verified      Regression
                                        Detected
```

---

# Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | Next.js + TypeScript | One-URL inspection workflow and security dashboard |
| Backend | FastAPI + Python | Security orchestration, validation and APIs |
| Security Twin | Daytona | Disposable isolated application execution |
| AI Inference | Nosana | Application-aware security hypothesis generation |
| Discovery | BreakTrace | Routes, identities, resources and ownership semantics |
| Deterministic Analysis | BreakTrace checks | Repeatable non-AI security checks |
| Runtime Verification | BreakTrace + Daytona | Evidence-based validation of proposed security failures |
| Security Memory | BreakTrace Library | Persistent executable regression tests |
| Regression Engine | BreakTrace | Replays historical security invariants against later versions |
---

# Daytona & Nosana Integration

BreakTrace separates **AI reasoning** from **security execution**.

This is an intentional architectural decision:

```text
                    BreakTrace
                        │
          ┌─────────────┴─────────────┐
          │                           │
          ▼                           ▼
      Nosana                      Daytona
   AI Reasoning              Security Execution
          │                           │
          │   proposes experiments    │
          └─────────────┬─────────────┘
                        ▼
               BreakTrace Validation
                        │
                        ▼
                  Runtime Evidence
                        │
                        ▼
                  Security Memory
```

In simple terms:

> **Nosana helps BreakTrace reason about what to test.  
> Daytona gives BreakTrace an isolated environment in which to verify it.  
> BreakTrace turns verified failures into Security Memory.**

---

## 🧱 How Daytona Is Used

BreakTrace uses **Daytona as the isolated execution environment for its Security Twins**.

Security testing should not blindly execute AI-generated experiments against a developer's production application. BreakTrace instead prepares a disposable environment containing the target application and performs verification there.

The lifecycle is:

```text
Application
     ↓
Create Daytona Sandbox
     ↓
Prepare Target Repository
     ↓
Start Application
     ↓
Discover Runtime Surface
     ↓
Execute Security Experiments
     ↓
Collect Runtime Evidence
     ↓
Replay Security Memory
     ↓
Destroy / Expire Sandbox
```

### Why Daytona matters to BreakTrace

Daytona gives BreakTrace an execution boundary between:

```text
AI-generated security hypothesis
```

and:

```text
real security finding
```

The AI does not decide that an application is vulnerable.

Instead:

1. BreakTrace creates/prepares the application inside the Daytona environment.
2. BreakTrace discovers the application's runtime behavior.
3. A security experiment is proposed.
4. BreakTrace validates the experiment.
5. The experiment is executed against the application running in the Security Twin.
6. The observed HTTP behavior is compared with the expected secure behavior.
7. Only runtime-supported failures become verified findings.

For example:

```text
Hypothesis:
User 1 should not be able to access User 2's report.

Experiment:
GET /api/reports/2
X-Demo-User: 1

Expected:
403 Forbidden
```

The experiment is then executed against the isolated application.

If the Security Twin returns:

```text
200 OK
```

BreakTrace now has runtime evidence of the authorization failure.

That verified failure can become a Security Memory test.

### Daytona's role in regression testing

Daytona is also important after initial discovery.

Security Memory can be replayed against another version of the application:

```text
Security Memory
      │
      ▼
New Application Version
      │
      ▼
Daytona Security Twin
      │
      ▼
Replay BT-001
      │
      ├── 403 → Fix still works
      │
      └── 200 → Security regression
```

This makes Daytona more than a sandbox used for a single scan.

It becomes the isolated execution layer supporting BreakTrace's:

- discovery
- verification
- fix validation
- regression replay

---

## 🧠 How Nosana Is Used

BreakTrace integrates **Nosana as an AI inference layer for application-aware security exploration**.

Rather than sending the AI an unconstrained prompt asking it to "hack this application," BreakTrace first builds structured application context.

That context can include:

```text
Routes
Identity inputs
Resource relationships
Ownership semantics
Seed entities
Frameworks
Dependencies
Storage resources
External services
Authentication signals
```

For example, BreakTrace may discover:

```text
Route:
GET /api/reports/:id

Identity input:
X-Demo-User → user_id

Resource:
reports

Ownership:
report.owner_id → user_id

Known principals:
User 1
User 2

Known resources:
Report 1
Report 2
```

This structured context is supplied to the AI reasoning layer.

Nosana can then help generate a security hypothesis such as:

```text
A user may be able to access a report owned by another user.
```

and propose a concrete experiment:

```http
GET /api/reports/2
X-Demo-User: 1
```

with:

```text
Expected secure status:
403
```

### Nosana does not verify vulnerabilities

This distinction is fundamental to BreakTrace.

```text
Nosana
   │
   │ proposes
   ▼
Security Hypothesis
   │
   ▼
BreakTrace Validation
   │
   ▼
Daytona Security Twin
   │
   │ executes
   ▼
Runtime Evidence
   │
   ▼
BreakTrace Verification
```

Nosana's output is treated as an **untrusted proposal**.

It must still pass BreakTrace's experiment-validation layer.

Validation constrains experiments using discovered application evidence, including:

- valid routes
- bounded resource identifiers
- known identity inputs
- allowed request headers
- ownership relationships
- safe request construction

Only after validation can the experiment be executed.

This architecture combines the flexibility of AI reasoning with deterministic runtime verification.

---

# Why Use Both?

Daytona and Nosana solve different parts of the problem.

| Component | Role in BreakTrace |
|---|---|
| **Nosana** | AI reasoning and security hypothesis generation |
| **BreakTrace Discovery** | Builds application-specific security context |
| **BreakTrace Validator** | Constrains AI proposals to evidence-backed experiments |
| **Daytona** | Runs isolated Security Twins and executes experiments |
| **BreakTrace Verification** | Compares expected vs observed runtime behavior |
| **Security Memory** | Stores verified failures as regression tests |
| **Regression Engine** | Replays those tests against future versions |

Neither component replaces the other.

Nosana answers:

> **"Given what we discovered about this application, what security condition should we investigate?"**

Daytona enables BreakTrace to answer:

> **"When we actually execute that experiment against the application, what happens?"**

BreakTrace then answers the long-term question:

> **"If we fix this today, will we know if it comes back tomorrow?"**

---

# End-to-End Sponsor Integration

The complete BreakTrace pipeline is:

```text
Developer
    │
    │ application URL
    ▼
BreakTrace
    │
    ▼
Application Resolution
    │
    ▼
Daytona Security Twin
    │
    ├── prepare application
    ├── start application
    └── expose isolated runtime
    │
    ▼
BreakTrace Discovery
    │
    ├── routes
    ├── identities
    ├── resources
    └── ownership semantics
    │
    ▼
Nosana AI
    │
    └── propose security hypotheses
    │
    ▼
BreakTrace Validator
    │
    └── reject unsupported/unsafe experiments
    │
    ▼
Daytona Security Twin
    │
    └── execute validated experiment
    │
    ▼
Runtime Evidence
    │
    ▼
BreakTrace Verification
    │
    ├── secure behavior → PASS
    │
    └── security failure → VERIFIED
    │
    ▼
Security Memory
    │
    └── convert verified break into BT-XXX
    │
    ▼
Future Application Version
    │
    ▼
Daytona Security Twin
    │
    └── replay BT-XXX
    │
    ├── expected == observed → FIX VERIFIED
    │
    └── secure expectation violated → REGRESSION DETECTED
```

This is the central BreakTrace idea:

> **AI helps discover what might break.  
> Isolated execution proves what actually breaks.  
> Security Memory makes sure the same break does not silently return.**


# Project Structure

```text
breaktrace/
│
├── backend/
│   ├── main.py
│   │   API endpoints and orchestration
│   │
│   ├── security_twin.py
│   │   Security Twin assessment pipeline
│   │
│   ├── discovery.py
│   │   Application and security-semantic discovery
│   │
│   ├── target_runner.py
│   │   Target execution and Security Memory replay
│   │
│   ├── library.py
│   │   Security Memory persistence, fingerprints,
│   │   deduplication and BreakTrace IDs
│   │
│   ├── models.py
│   │   Shared application/security data models
│   │
│   ├── ai_provider.py
│   │   AI provider abstraction
│   │
│   ├── ai_shared.py
│   │   AI proposal generation and validation helpers
│   │
│   ├── nosana_client.py
│   │   Nosana integration layer
│   │
│   ├── groq_client.py
│   │   Alternate AI provider client
│   │
│   ├── daytona_runner.py
│   │   Daytona sandbox lifecycle
│   │
│   ├── applications.py
│   │   Application identity and persistence
│   │
│   ├── targets.py
│   │   Supported target definitions
│   │
│   ├── checks/
│   │   ├── headers.py
│   │   ├── cookies.py
│   │   ├── cors.py
│   │   ├── exposure.py
│   │   ├── source.py
│   │   └── registry.py
│   │
│   ├── data/
│   │   └── applications.json
│   │
│   ├── test_security_twin.py
│   ├── test_regression_demo.py
│   ├── test_security_analysis.py
│   ├── test_discovery_quality.py
│   └── ...
│
├── frontend/
│   ├── app/
│   │   ├── page.tsx
│   │   ├── globals.css
│   │   └── layout.tsx
│   │
│   ├── public/
│   ├── package.json
│   └── tsconfig.json
│
├── .gitignore
└── README.md
```

---

# Usage

## Prerequisites

You will need:

- Python
- Node.js / npm
- required API/service credentials
- access to the configured sandbox/inference services

---

## 1. Configure the Backend

Create:

```text
backend/.env
```

Use:

```text
backend/.env.example
```

as the configuration template.

Never commit real credentials.

---

## 2. Start the Backend

On Windows:

```bat
cd backend
venv\Scripts\activate
python -m uvicorn main:app --port 8000
```

BreakTrace API:

```text
http://localhost:8000
```

---

## 3. Start the Frontend

In another terminal:

```bat
cd frontend
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

---

# Running the Regression Demo

Enter this application identity into BreakTrace:

```text
https://breaktrace-regression-demo.example
```

Then click:

**Inspect Application**

The demo automatically executes the complete lifecycle internally.

```text
DISCOVER
2 cross-user authorization failures

        ↓

REMEMBER
2 verified tests stored
BT-001 + BT-002

        ↓

VERIFY
2 replayed
2 passed
0 regressions

        ↓

DETECT
2 replayed
0 passed
2 regressions
```

The user does not need to manually select application versions.

---

# Why BreakTrace Is Different

Many security tools focus on one of these jobs:

```text
Scan code
```

or:

```text
Find vulnerabilities
```

or:

```text
Run security tests
```

BreakTrace connects the entire lifecycle:

```text
UNDERSTAND
application semantics

        ↓

DISCOVER
security hypothesis

        ↓

VERIFY
against a running application

        ↓

REMEMBER
the verified failure

        ↓

REPLAY
the same security invariant later

        ↓

DETECT
when a fixed vulnerability returns
```

The key output is therefore not only a vulnerability report.

It is **executable security memory**.

---

# Why This Matters for Vibe Coding

Vibe coding changes the economics of software development.

Developers can now generate and modify large amounts of application code through natural-language prompts in minutes.

But increased development velocity can also mean increased security drift.

A prompt such as:

> "Add an admin dashboard."

or:

> "Refactor the reports API."

or:

> "Make this endpoint easier to use."

can change security-sensitive behavior far beyond the lines a developer intentionally touched.

For vibe coders, manually reasoning about every authorization boundary after every generated change does not scale.

BreakTrace is designed around that reality.

## BreakTrace gives vibe coders a security memory layer

Once BreakTrace verifies:

```text
User A must not access User B's report
```

the developer should not have to rediscover that requirement after every AI-generated refactor.

BreakTrace remembers it as an executable test.

That creates a feedback loop:

```text
Vibe Code
    ↓
Inspect
    ↓
Find Security Failure
    ↓
Fix
    ↓
BreakTrace Remembers
    ↓
Keep Vibe Coding
    ↓
Automatic Replay
    ↓
Catch Regression
```

---

# Benefits for Vibe Coders

### Faster security feedback

Developers can inspect the application without manually constructing every security test.

### Application-specific testing

BreakTrace reasons about discovered routes, identities, resources, and ownership relationships instead of relying entirely on generic security prompts.

### Reduced repeated mistakes

Once a failure becomes Security Memory, future versions can be checked against the same security invariant.

### AI with verification

AI helps generate hypotheses, while runtime execution determines whether a vulnerability actually exists.

### Low-friction workflow

The primary user interaction is intentionally:

```text
Paste URL → Inspect Application
```

rather than requiring developers to become penetration-testing experts.

### Security that evolves with the application

Security tests accumulate from real verified failures, allowing the security suite to become increasingly application-specific over time.

---

# Design Principles

BreakTrace is built around several principles.

## 1. AI proposes. Runtime evidence decides.

AI-generated text alone is not a verified vulnerability.

## 2. Every verified break should become a test.

A vulnerability report has temporary value.

A regression test has lasting value.

## 3. Security context matters.

Understanding identities, ownership and application resources enables better experiments than blind endpoint guessing.

## 4. Security should keep pace with development.

Fast development should not require abandoning security regression testing.

## 5. Previously fixed vulnerabilities deserve special attention.

A known security failure returning is different from a newly discovered low-confidence hypothesis.

BreakTrace treats regressions as first-class security events.

---

# Example Security Invariant

Consider:

```text
Alice owns Report 1
Bob owns Report 2
```

BreakTrace learns:

```text
Identity field:
user_id

Resource owner:
report.owner_id
```

It can then test:

```http
GET /api/reports/2
X-Demo-User: 1
```

If the application returns:

```text
200 OK
```

instead of:

```text
403 Forbidden
```

BreakTrace has runtime evidence of a cross-user authorization failure.

That evidence becomes:

```text
BT-001
```

and can survive beyond the original assessment.

---

# Testing & Quality

The project includes automated coverage for areas including:

- application resolution
- context serialization
- target discovery
- discovery quality
- security analysis
- Security Twin execution
- regression-demo behavior
- Security Memory lifecycle
- duplicate prevention
- application-scoped IDs
- cross-user authorization
- secure-denial semantics
- AI failure handling
- replay behavior
- target configuration

Frontend quality checks include:

```bash
npx tsc --noEmit
npx eslint .
npm run build
```

---

# Current Capabilities

- [x] URL-based application inspection
- [x] isolated Security Twin execution
- [x] runtime application discovery
- [x] deterministic security checks
- [x] AI-assisted security exploration
- [x] proposal validation
- [x] runtime vulnerability verification
- [x] identity-aware security testing
- [x] ownership-aware security testing
- [x] cross-user access-control testing
- [x] persistent Security Memory
- [x] stable BreakTrace test identities
- [x] duplicate-resistant test storage
- [x] automatic regression replay
- [x] fix verification
- [x] regression detection
- [x] graceful AI-layer failure
- [x] one-click regression demonstration
- [x] desktop-first security dashboard

---

# Future Direction

BreakTrace's Security Memory model can be extended toward:

- CI/CD security regression gates
- pull-request security checks
- richer authentication flows
- broader API mutation testing
- multi-step attack sequences
- automatic invariant extraction
- repository-change-aware test prioritization
- historical security timelines
- team-level Security Memory
- application security posture tracking

The long-term idea is simple:

> As an application evolves, its security tests should evolve from the vulnerabilities it has actually experienced.

---

# Responsible Use

BreakTrace is an educational security-testing project.

Only use BreakTrace against applications, environments, repositories, and systems that you own or have explicit authorization to test.

---

# BreakTrace

### Find it once. Fix it once. Remember it forever.

**Discover → Remember → Verify → Detect**
