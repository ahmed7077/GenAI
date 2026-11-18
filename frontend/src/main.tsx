import { FormEvent, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api/v1";
type Evt = {
  id: string;
  event_type: string;
  occurred_at: string;
  source_ip?: string;
  host?: string;
  actor?: string;
  outcome?: string;
};
type Cand = {
  source_ip: string;
  failed_logins: number;
  privilege_escalation: boolean;
  sensitive_access: boolean;
};
type ReviewSignal = {
  event_id: string;
  event_type: string;
  label: string;
  occurred_at: string;
  actor?: string;
};
type Eval = {
  evaluated_events: number;
  incident_candidates: Cand[];
  review_signals: ReviewSignal[];
};
type Model = {
  available: boolean;
  metrics?: {
    records: number;
    features: number;
    random_forest: { f1: number; roc_auc: number };
  };
  purpose: string;
  limitation: string;
};
type Tab = "dashboard" | "events" | "detections" | "models" | "assistant";
type Message = { role: "user" | "assistant"; text: string; time: string };
const navigation: Array<[Tab, string, string]> = [
  ["dashboard", "Overview", "◈"],
  ["events", "Evidence vault", "◌"],
  ["detections", "Detection center", "⌁"],
  ["models", "Model intelligence", "◒"],
  ["assistant", "Investigation assistant", "✦"],
];
const stamp = () =>
  new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
function App() {
  const [token, setToken] = useState(
    localStorage.getItem("threatlens_token") ?? "",
  );
  const [tab, setTab] = useState<Tab>("dashboard");
  const [events, setEvents] = useState<Evt[]>([]);
  const [evaluation, setEvaluation] = useState<Eval | null>(null);
  const [model, setModel] = useState<Model | null>(null);
  const [error, setError] = useState("");
  const [uploading, setUploading] = useState(false);
  const headers = { Authorization: `Bearer ${token}` };
  const fail = async (r: Response) => {
    const x = await r.json().catch(() => ({}));
    return typeof x.detail === "string" ? x.detail : "Request failed.";
  };
  async function refresh() {
    if (!token) return;
    try {
      const [a, b, c] = await Promise.all([
        fetch(`${API}/events`, { headers }),
        fetch(`${API}/detection/evaluate`, { headers }),
        fetch(`${API}/models/status`, { headers }),
      ]);
      if (!a.ok || !b.ok || !c.ok)
        throw Error("Unable to load the live workspace.");
      setEvents(await a.json());
      setEvaluation(await b.json());
      setModel(await c.json());
      setError("");
    } catch (x) {
      setError(x instanceof Error ? x.message : "Unable to load data.");
    }
  }
  useEffect(() => {
    void refresh();
  }, [token]);
  async function upload(file: File) {
    setUploading(true);
    const form = new FormData();
    form.append("file", file);
    try {
      const r = await fetch(`${API}/events/upload`, {
        method: "POST",
        headers,
        body: form,
      });
      if (!r.ok) throw Error(await fail(r));
      await refresh();
      setTab("events");
    } catch (x) {
      setError(x instanceof Error ? x.message : "Upload failed.");
    } finally {
      setUploading(false);
    }
  }
  if (!token)
    return (
      <Login
        onToken={(v) => {
          localStorage.setItem("threatlens_token", v);
          setToken(v);
        }}
      />
    );
  const candidates = evaluation?.incident_candidates ?? [];
  const signals = evaluation?.review_signals ?? [];
  const title = navigation.find(([k]) => k === tab)?.[1] ?? "ThreatLens";
  return (
    <div className="app">
      <aside className="rail">
        <div className="brand">
          <span>◇</span>
          <b>THREAT</b>
          <em>LENS</em>
        </div>
        <div className="rail-caption">Security workspace</div>
        <nav>
          {navigation.map(([k, label, icon]) => (
            <button
              className={tab === k ? "active" : ""}
              key={k}
              onClick={() => setTab(k)}
            >
              <i>{icon}</i>
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="rail-bottom">
          <button
            className="signout"
            onClick={() => {
              localStorage.removeItem("threatlens_token");
              setToken("");
            }}
          >
            <i>↗</i>
            <span>Sign out</span>
          </button>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <small>THREATLENS / SECURITY OPERATIONS</small>
            <h1>{title}</h1>
          </div>
        </header>
        {error && <p className="error">{error}</p>}
        {tab === "dashboard" && (
          <Dashboard
            events={events}
            candidates={candidates}
            evaluation={evaluation}
            uploading={uploading}
            upload={upload}
          />
        )}{" "}
        {tab === "events" && (
          <Events events={events} uploading={uploading} upload={upload} />
        )}{" "}
        {tab === "detections" && (
          <Detections
            candidates={candidates}
            evaluated={evaluation?.evaluated_events ?? 0}
            signals={signals}
          />
        )}{" "}
        {tab === "models" && (
          <Models model={model} headers={headers} fail={fail} />
        )}{" "}
        {tab === "assistant" && <Assistant headers={headers} fail={fail} />}
      </main>
    </div>
  );
}
function Card({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail?: string;
}) {
  return (
    <article className="metric">
      <small>{label}</small>
      <b>{value}</b>
      <span>{detail ?? "Live API state"}</span>
    </article>
  );
}
function Upload({
  uploading,
  upload,
}: {
  uploading: boolean;
  upload: (f: File) => Promise<void>;
}) {
  return (
    <label className="button gold">
      {uploading ? "Importing…" : "Import evidence"}
      <input
        hidden
        type="file"
        accept=".json,.csv,.log,.txt,text/plain,application/octet-stream"
        disabled={uploading}
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) void upload(f);
        }}
      />
    </label>
  );
}
function Candidate({ c }: { c: Cand }) {
  return (
    <div className="candidate">
      <i>!</i>
      <div>
        <b>{c.source_ip}</b>
        <span>{c.failed_logins} failed logins before success</span>
      </div>
      <small>Review</small>
    </div>
  );
}
function Chart({ events }: { events: Evt[] }) {
  const data = useMemo(
    () =>
      Object.entries(
        events.reduce<Record<string, number>>((a, e) => {
          const key = e.event_type.split(".").slice(0, 2).join(".") || "other";
          a[key] = (a[key] ?? 0) + 1;
          return a;
        }, {}),
      )
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5),
    [events],
  );
  const max = Math.max(...data.map(([, v]) => v), 1);
  const leader = data[0];
  const share =
    leader && events.length ? Math.round((leader[1] / events.length) * 100) : 0;
  return (
    <article className="chart">
      <div className="section-title">
        <div>
          <small>EVIDENCE DISTRIBUTION</small>
          <h2>Observed activity</h2>
        </div>
        <span>Top event families</span>
      </div>
      {data.length ? (
        <>
          <div className="donut">
            <svg
              viewBox="0 0 42 42"
              aria-label={`${leader[0]} represents ${share}% of retained events`}
            >
              <circle className="donut-base" cx="21" cy="21" r="15.9" />
              <circle
                className="donut-value"
                cx="21"
                cy="21"
                r="15.9"
                strokeDasharray={`${share} ${100 - share}`}
                transform="rotate(-90 21 21)"
              />
            </svg>
            <div>
              <b>{share}%</b>
              <small>{leader[0]} of all events</small>
            </div>
          </div>
          <div className="bars">
            {data.map(([name, value], i) => (
              <div className="bar-row" key={name}>
                <span title={name}>{name}</span>
                <div>
                  <i
                    style={{
                      width: `${(value / max) * 100}%`,
                      animationDelay: `${i * 90}ms`,
                    }}
                  />
                </div>
                <b>{value}</b>
              </div>
            ))}
          </div>
        </>
      ) : (
        <p>Import evidence to generate an observed-activity chart.</p>
      )}
    </article>
  );
}
function Dashboard({
  events,
  candidates,
  evaluation,
  uploading,
  upload,
}: {
  events: Evt[];
  candidates: Cand[];
  evaluation: Eval | null;
  uploading: boolean;
  upload: (f: File) => Promise<void>;
}) {
  return (
    <>
      <section className="hero">
        <div>
          <small>REAL EVIDENCE / NO SYNTHETIC SIGNALS</small>
          <h2>
            See what the evidence says—
            <br />
            <em>and what it does not.</em>
          </h2>
          <p>
            Preserve source events, correlate explicit patterns, and keep
            analyst judgement in the loop.
          </p>
        </div>
        <Upload uploading={uploading} upload={upload} />
      </section>
      <section className="metrics">
        <Card
          label="Events ingested"
          value={String(events.length).padStart(2, "0")}
        />
        <Card
          label="Incident candidates"
          value={String(candidates.length).padStart(2, "0")}
        />
        <Card
          label="Rule evaluation"
          value={evaluation ? "Current" : "Waiting"}
        />
        <Card label="Evidence policy" value="Traceable" />
      </section>
      <section className="two">
        <Chart events={events} />
        <article className="signal">
          <small>DETECTION SIGNAL</small>
          <h2>
            {candidates.length
              ? "Analyst review required"
              : "No correlated incident"}
          </h2>
          <p>
            {candidates.length
              ? "Authentication evidence meets the correlation threshold. Review the event trail before taking action."
              : "No stored evidence currently meets the authentication correlation threshold."}
          </p>
          {candidates.slice(0, 2).map((c) => (
            <Candidate c={c} key={c.source_ip} />
          ))}
        </article>
      </section>
    </>
  );
}
function Events({
  events,
  uploading,
  upload,
}: {
  events: Evt[];
  uploading: boolean;
  upload: (f: File) => Promise<void>;
}) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const [page, setPage] = useState(1);
  const categories = useMemo(
    () =>
      [
        ...new Set(events.map((e) => e.event_type.split(".")[0] || "other")),
      ].sort(),
    [events],
  );
  const filtered = events.filter(
    (e) =>
      (category === "all" || e.event_type.startsWith(category + ".")) &&
      `${e.event_type} ${e.actor ?? ""} ${e.source_ip ?? ""} ${e.host ?? ""} ${e.outcome ?? ""}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const pages = Math.max(1, Math.ceil(filtered.length / 50));
  const safePage = Math.min(page, pages);
  const visible = filtered.slice((safePage - 1) * 50, safePage * 50);
  const firstPage = Math.min(Math.max(1, safePage - 3), Math.max(1, pages - 6));
  const change = () => setPage(1);
  return (
    <>
      <section className="hero compact">
        <div>
          <small>EVIDENCE VAULT</small>
          <h2>Every record has a trail.</h2>
          <p>Search, filter, and page through the retained evidence.</p>
        </div>
        <Upload uploading={uploading} upload={upload} />
      </section>
      <article className="table-panel">
        <div className="section-title">
          <div>
            <small>EVENT EXPLORER</small>
            <h2>Persisted evidence</h2>
          </div>
          <span>
            Page {safePage} of {pages} · {filtered.length} matching
          </span>
        </div>
        {events.length && (
          <div className="event-controls">
            <input
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                change();
              }}
              placeholder="Search event type, actor, host, outcome…"
            />
            <select
              value={category}
              onChange={(e) => {
                setCategory(e.target.value);
                change();
              }}
            >
              <option value="all">All categories</option>
              {categories.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
        )}
        {events.length ? (
          <table>
            <thead>
              <tr>
                <th>TIME</th>
                <th>EVENT</th>
                <th>ACTOR / SOURCE</th>
                <th>HOST</th>
                <th>OUTCOME</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((e) => (
                <tr key={e.id}>
                  <td>{new Date(e.occurred_at).toLocaleString()}</td>
                  <td>
                    <b>{e.event_type}</b>
                  </td>
                  <td>{e.actor ?? e.source_ip ?? "Not provided"}</td>
                  <td>{e.host ?? "Not provided"}</td>
                  <td>{e.outcome ?? "Not provided"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty text="No evidence has been imported." />
        )}
        {pages > 1 && (
          <nav className="pagination">
            <button
              disabled={safePage === 1}
              onClick={() => setPage(safePage - 1)}
            >
              Previous
            </button>
            {Array.from({ length: Math.min(pages, 7) }, (_, i) => {
              const value = firstPage + i;
              return (
                <button
                  className={value === safePage ? "current" : ""}
                  key={value}
                  onClick={() => setPage(value)}
                >
                  {value}
                </button>
              );
            })}
            <button
              disabled={safePage === pages}
              onClick={() => setPage(safePage + 1)}
            >
              Next
            </button>
          </nav>
        )}
      </article>
    </>
  );
}
function Detections({
  candidates,
  evaluated,
  signals,
}: {
  candidates: Cand[];
  evaluated: number;
  signals: ReviewSignal[];
}) {
  return (
    <>
      <section className="metrics">
        <Card
          label="Events evaluated"
          value={String(evaluated)}
          detail="Current evidence"
        />
        <Card
          label="Auth candidates"
          value={String(candidates.length)}
          detail="Confirmed rule matches"
        />
        <Card
          label="Review signals"
          value={String(signals.length)}
          detail="Configuration / OAuth changes"
        />
        <Card
          label="Disposition"
          value={signals.length ? "Review" : "No signal"}
          detail="Not an incident verdict"
        />
      </section>
      <section className="two">
        <article className="signal">
          <small>REVIEW QUEUE</small>
          <h2>
            {signals.length ? "Changes needing context" : "No review signals"}
          </h2>
          <p>
            These records changed repository controls or OAuth access. They are
            not alerts or confirmed incidents; review the actor, repository,
            approval and change-ticket context.
          </p>
          {signals.length ? (
            <div className="review-list">
              {signals.slice(0, 6).map((s) => (
                <div className="candidate" key={s.event_id}>
                  <i>•</i>
                  <div>
                    <b>{s.label}</b>
                    <span>
                      {s.actor ?? "Actor not provided"} ·{" "}
                      {new Date(s.occurred_at).toLocaleString()}
                    </span>
                  </div>
                  <small>Review</small>
                </div>
              ))}
            </div>
          ) : (
            <Empty text="No workflow, merge-setting, or OAuth review signals are present in this evidence set." />
          )}
        </article>
        <article className="orbit">
          <small>AUTHENTICATION CORRELATION</small>
          <h2>Failure, then success</h2>
          <div className="path">
            <span>3 failed logins</span>
            <i>→</i>
            <span>Same source</span>
            <i>→</i>
            <span>Success</span>
          </div>
          <p>
            This separate detector applies only to host-authentication logs.{" "}
            {candidates.length
              ? "Matching evidence is listed in the review queue."
              : "Your GitHub audit export does not contain login failures or source IPs, so no auth correlation can be made."}
          </p>
        </article>
      </section>
    </>
  );
}
function Models({
  model,
  headers,
  fail,
}: {
  model: Model | null;
  headers: Record<string, string>;
  fail: (r: Response) => Promise<string>;
}) {
  const [payload, setPayload] = useState("");
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [loadingSample, setLoadingSample] = useState(false);
  const [sampleName, setSampleName] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [batchBusy, setBatchBusy] = useState(false);
  const [batchResult, setBatchResult] = useState<{
    flows_scored: number;
    attack_count: number;
    attack_rate: number;
    anomaly_count: number;
    anomaly_rate: number;
    mean_attack_probability: number;
    highest_risk_flows: Array<{ row: number; attack_probability: number; isolation_forest_anomaly: boolean; source_label?: string }>;
  } | null>(null);
  async function loadSample(file: File) {
    setLoadingSample(true);
    setError("");
    const form = new FormData();
    form.append("file", file);
    try {
      const r = await fetch(`${API}/models/flow-sample`, {
        method: "POST",
        headers,
        body: form,
      });
      if (!r.ok) throw Error(await fail(r));
      const data = await r.json();
      setSelectedFile(file);
      setPayload(JSON.stringify(data.features, null, 2));
      setSampleName(
        `${data.filename} · row ${data.source_row} · ${data.feature_count} features loaded${data.source_label ? ` · dataset label: ${data.source_label}` : ""}`,
      );
      setResult("");
    } catch (x) {
      setError(x instanceof Error ? x.message : "Could not load flow sample.");
    } finally {
      setLoadingSample(false);
    }
  }
  async function scoreBatch() {
    if (!selectedFile) return;
    setBatchBusy(true);
    setError("");
    setBatchResult(null);
    const form = new FormData();
    form.append("file", selectedFile);
    try {
      const r = await fetch(`${API}/models/score-csv`, { method: "POST", headers, body: form });
      if (!r.ok) throw Error(await fail(r));
      setBatchResult(await r.json());
    } catch (x) {
      setError(x instanceof Error ? x.message : "Batch scoring failed.");
    } finally {
      setBatchBusy(false);
    }
  }
  async function predict(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const r = await fetch(`${API}/models/predict`, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ features: JSON.parse(payload) }),
      });
      if (!r.ok) throw Error(await fail(r));
      setResult(JSON.stringify(await r.json(), null, 2));
    } catch (x) {
      setError(x instanceof Error ? x.message : "Prediction failed.");
    }
  }
  const m = model?.metrics?.random_forest;
  return (
    <>
      <section className="hero compact">
        <div>
          <small>
            {model?.available ? "TRAINED ARTIFACTS READY" : "MODEL UNAVAILABLE"}
          </small>
          <h2>Network-flow intelligence.</h2>
          <p>{model?.limitation}</p>
        </div>
      </section>
      {m && (
        <section className="metrics">
          <Card
            label="Training records"
            value={model!.metrics!.records.toLocaleString()}
          />
          <Card
            label="Flow features"
            value={String(model!.metrics!.features)}
          />
          <Card label="Random Forest F1" value={m.f1.toFixed(4)} />
          <Card label="ROC-AUC" value={m.roc_auc.toFixed(4)} />
        </section>
      )}
      <section className="two">
        <article className="signal">
          <small>MODEL APPLICABILITY</small>
          <h2>CICIDS2017 flows only</h2>
          <p>
            The Random Forest and Isolation Forest load from local artifacts and
            require the complete numerical CICIDS2017 flow schema. Audit and
            authentication records are evaluated by their dedicated rules.
          </p>
        </article>
        <article className="model-form">
          <small>LIVE FLOW INFERENCE</small>
          <h2>Score a flow</h2>
          <p className="model-help">
            Select a CICIDS2017 MachineLearningCVE CSV. ThreatLens loads its first row and checks all 78 model features.
          </p>
          <label className="button sample-picker">
            {loadingSample ? "Reading CSV…" : "Select CICIDS CSV row"}
            <input
              hidden
              type="file"
              accept=".csv,text/csv"
              disabled={loadingSample || !model?.available}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) {
                  void loadSample(file);
                  // Allow selecting the same file again after changing its row/content.
                  e.currentTarget.value = "";
                }
              }}
            />
          </label>
          {sampleName && <small className="sample-name">{sampleName}</small>}
          <button className="button batch-score" type="button" disabled={!selectedFile || batchBusy} onClick={scoreBatch}>
            {batchBusy ? "Scoring full CSV…" : "Score entire selected CSV"}
          </button>
          <p className="model-help">Batch scoring analyzes every compatible flow in the selected file and surfaces aggregate rates plus the ten highest-risk rows.</p>
          <form onSubmit={predict}>
            <textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              placeholder={
                '{" Destination Port":80," Flow Duration":12345,...}'
              }
            />
            <button className="button gold" disabled={!model?.available}>
              Run model
            </button>
          </form>
          {error && <p className="error">{error}</p>}
          {result && <pre>{result}</pre>}
          {batchResult && (
            <section className="batch-result">
              <small>BATCH FLOW ANALYSIS</small>
              <div className="batch-metrics"><b>{batchResult.flows_scored.toLocaleString()}<span>flows scored</span></b><b>{(batchResult.attack_rate * 100).toFixed(1)}%<span>attack-model rate</span></b><b>{(batchResult.anomaly_rate * 100).toFixed(1)}%<span>anomaly rate</span></b></div>
              <p>{batchResult.attack_count.toLocaleString()} flows scored as attack; {batchResult.anomaly_count.toLocaleString()} flagged as anomalous. Mean attack probability: {batchResult.mean_attack_probability.toFixed(4)}.</p>
              <small>HIGHEST-RISK SOURCE ROWS</small>
              <ol>{batchResult.highest_risk_flows.slice(0,5).map(flow => <li key={flow.row}>Row {flow.row}: {(flow.attack_probability * 100).toFixed(2)}% model probability{flow.isolation_forest_anomaly ? " · anomaly" : ""}{flow.source_label ? ` · dataset label: ${flow.source_label}` : ""}</li>)}</ol>
            </section>
          )}
        </article>
      </section>
    </>
  );
}
function LinkedText({ text }: { text: string }) {
  const parts = text.split(
    /(\[[^\]]+\]\(https?:\/\/[^\s)]+\)|https?:\/\/[^\s]+)/g,
  );
  return (
    <>
      {parts.map((part, i) => {
        const markdown = part.match(/^\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)$/);
        const url = markdown?.[2] ?? (part.startsWith("http") ? part : null);
        return url ? (
          <a key={i} href={url} target="_blank" rel="noreferrer">
            {markdown?.[1] ?? url}
          </a>
        ) : (
          part
        );
      })}
    </>
  );
}
function Assistant({
  headers,
  fail,
}: {
  headers: Record<string, string>;
  fail: (r: Response) => Promise<string>;
}) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [q, setQ] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function ask(e: FormEvent) {
    e.preventDefault();
    const question = q.trim();
    if (!question || busy) return;
    setMessages((x) => [...x, { role: "user", text: question, time: stamp() }]);
    setQ("");
    setBusy(true);
    setError("");
    try {
      const r = await fetch(`${API}/chat`, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      });
      if (!r.ok) throw Error(await fail(r));
      const data = await r.json();
      setMessages((x) => [
        ...x,
        { role: "assistant", text: data.answer, time: stamp() },
      ]);
    } catch (x) {
      setError(x instanceof Error ? x.message : "Assistant unavailable.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="chat">
      <div className="chat-top">
        <div>
          <small>EVIDENCE-BOUNDED INVESTIGATION</small>
          <h2>Your investigation thread</h2>
        </div>
        <span>
          <i /> Evidence aware
        </span>
      </div>
      <div className="messages">
        {!messages.length && (
          <div className="chat-empty">
            <b>Start with the evidence.</b>
            <p>
              Ask about a pattern, an event type, or where to focus review.
              Answers are bounded to stored summaries.
            </p>
            <button onClick={() => setQ("What should I review first?")}>
              Try a suggested question →
            </button>
          </div>
        )}
        {messages.map((m, i) => (
          <div className={`message ${m.role}`} key={`${m.time}-${i}`}>
            <div className="avatar">{m.role === "user" ? "You" : "TL"}</div>
            <div>
              <div className="bubble">
                <LinkedText text={m.text} />
              </div>
              <small>
                {m.role === "user" ? "ANALYST" : "THREATLENS ASSISTANT"} ·{" "}
                {m.time}
              </small>
            </div>
          </div>
        ))}
        {busy && (
          <div className="message assistant">
            <div className="avatar">TL</div>
            <div className="bubble thinking">
              <i />
              <i />
              <i />
            </div>
          </div>
        )}
      </div>
      {error && <p className="error">{error}</p>}
      <form className="composer" onSubmit={ask}>
        <textarea
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Ask about the evidence…"
          required
        />
        <button className="button gold" disabled={busy}>
          Send <span>↗</span>
        </button>
      </form>
      <small className="chat-note">
        Responses cite stored evidence and distinguish facts from uncertainty.
      </small>
    </section>
  );
}
function Empty({ text }: { text: string }) {
  return <p className="empty">{text}</p>;
}
function Login({ onToken }: { onToken: (v: string) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [register, setRegister] = useState(true);
  const [error, setError] = useState("");
  async function submit(e: FormEvent) {
    e.preventDefault();
    const r = await fetch(`${API}/auth/${register ? "register" : "login"}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const d = await r.json();
    if (!r.ok) {
      setError(d.detail ?? "Authentication failed.");
      return;
    }
    onToken(d.access_token);
  }
  return (
    <div className="login">
      <form onSubmit={submit}>
        <div className="brand">
          <span>◇</span>
          <b>THREAT</b>
          <em>LENS</em>
        </div>
        <small>SECURE ANALYST ACCESS</small>
        <h1>{register ? "Build your command post." : "Welcome back."}</h1>
        <input
          type="email"
          placeholder="Analyst email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password (12+ characters)"
          minLength={12}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <button className="button gold">
          {register ? "Create account" : "Sign in"}
        </button>
        {error && <p className="error">{error}</p>}
        <button
          type="button"
          className="switch"
          onClick={() => setRegister(!register)}
        >
          {register
            ? "Already have an account? Sign in"
            : "Need an account? Register"}
        </button>
      </form>
    </div>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
