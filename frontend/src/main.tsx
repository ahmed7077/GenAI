import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api/v1";
const DEMO = import.meta.env.VITE_DEMO_MODE === "true";
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
  failure_event_ids: string[];
  success_event_id: string;
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
type Tab = "dashboard" | "events" | "detections" | "models" | "assistant" | "cases";
type TimelineEvent = Pick<Evt, "id" | "event_type" | "occurred_at" | "source_ip">;
type Message = { role: "user" | "assistant"; text: string; time: string; workflow?: string[]; timeline?: TimelineEvent[] };
const linkedEvidence = new URLSearchParams(location.search).get("event");
const navigation: Array<[Tab, string, string]> = [
  ["dashboard", "Overview", "◈"],
  ["events", "Evidence vault", "◌"],
  ["cases", "Analyst cases", ""],
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
  const [tab, setTab] = useState<Tab>(linkedEvidence ? "events" : "dashboard");
  const [events, setEvents] = useState<Evt[]>([]);
  const [eventTotal, setEventTotal] = useState(0);
  const [evaluation, setEvaluation] = useState<Eval | null>(null);
  const [model, setModel] = useState<Model | null>(null);
  const [error, setError] = useState("");
  const [sessionNotice, setSessionNotice] = useState("");
  const [uploading, setUploading] = useState(false);
  const [evidenceRevision, setEvidenceRevision] = useState(0);
  const headers: Record<string, string> = DEMO ? {} : { Authorization: `Bearer ${token}` };
  const fail = async (r: Response) => {
    const x = await r.json().catch(() => ({}));
    return typeof x.detail === "string" ? x.detail : "Request failed.";
  };
  async function refresh() {
    if (!token && !DEMO) return;
    try {
      const [a, b, c, d] = await Promise.all([
        fetch(`${API}/events?limit=10000`, { headers }),
        fetch(`${API}/detection/evaluate`, { headers }),
        fetch(`${API}/models/status`, { headers }),
        fetch(`${API}/events/summary`, { headers }),
      ]);
      if (!DEMO && [a, b, c, d].some((response) => response.status === 401)) {
        if (localStorage.getItem("threatlens_token") !== token) return;
        localStorage.removeItem("threatlens_token");
        setEvents([]);
        setEventTotal(0);
        setEvaluation(null);
        setModel(null);
        setSessionNotice("Your session is no longer valid. Sign in again to open your workspace.");
        setToken("");
        return;
      }
      if (!DEMO && localStorage.getItem("threatlens_token") !== token) return;
      if (!a.ok || !b.ok || !c.ok || !d.ok)
        throw Error("Unable to load the live workspace.");
      setEvents(await a.json());
      setEvaluation(await b.json());
      setModel(await c.json());
      setEventTotal((await d.json()).events);
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
      setEvidenceRevision((revision) => revision + 1);
      await refresh();
      setTab("events");
    } catch (x) {
      setError(x instanceof Error ? x.message : "Upload failed.");
    } finally {
      setUploading(false);
    }
  }
  if (!token && !DEMO)
    return (
      <>
        {sessionNotice && <p className="error" role="status">{sessionNotice}</p>}
        <Login
          onToken={(v) => {
            setSessionNotice("");
            setError("");
            localStorage.setItem("threatlens_token", v);
            setToken(v);
          }}
        />
      </>
    );
  const candidates = evaluation?.incident_candidates ?? [];
  const signals = evaluation?.review_signals ?? [];
  const title = navigation.find(([k]) => k === tab)?.[1] ?? "ThreatLens";
  return (
    <div className="app">
      <aside className="rail">
        <div className="brand">
          <img src="/favicon.svg" alt="" width={28} height={28} />
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
              <i aria-hidden="true">{k === "cases" ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                  strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="7" width="18" height="14" rx="2" />
                  <path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M3 13h18m-9 0v2" />
                </svg>
              ) : icon}</i>
              <span>{label}</span>
            </button>
          ))}
        </nav>
        {!DEMO && <div className="rail-bottom">
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
        </div>}
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
            eventTotal={eventTotal}
            candidates={candidates}
            evaluation={evaluation}
            uploading={uploading}
            upload={upload}
          />
        )}{" "}
        {tab === "events" && (
          <Events token={token} revision={evidenceRevision} eventTotal={eventTotal} uploading={uploading} upload={upload} />
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
        {tab === "cases" && <Cases authorization={headers.Authorization} />}
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
        {c.success_event_id && <details>
          <summary>Evidence IDs</summary>
          <p>Failures: {c.failure_event_ids.join(", ")}</p>
          <p>Success: {c.success_event_id}</p>
        </details>}
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
  const other = events.length - data.reduce((sum, [, count]) => sum + count, 0);
  const palette = ["#75b9a2", "#80abc9", "#d59073", "#b6c18d", "#ba98bd", "#919d98"];
  let offset = 0;
  const segments = [...data, ...(other ? [["Other", other] as const] : [])].map(([name, count], index) => {
    const share = count / events.length * 100;
    const start = offset;
    offset += share;
    return { name, count, share, start, color: palette[index] };
  });
  return (
    <article className="chart">
      <div className="section-title">
        <div>
          <small>EVIDENCE DISTRIBUTION</small>
          <h2>Observed activity</h2>
        </div>
        <span>Top 5 event types + other</span>
      </div>
      {data.length ? (
        <div className="activity-distribution">
          <div className="activity-ring">
            <svg viewBox="0 0 160 160" aria-hidden="true">
              {segments.map(({ name, share, start, color }) => (
                <circle key={name} cx="80" cy="80" r="65" fill="none" stroke={color}
                  strokeWidth="22" pathLength="100" strokeDasharray={`${share} ${100 - share}`}
                  strokeDashoffset={-start} transform="rotate(-90 80 80)" />
              ))}
            </svg>
            <div className="activity-ring-total">
              <b>{events.length.toLocaleString()}</b>
              <span>Events charted</span>
            </div>
          </div>
          <ul className="activity-legend" aria-label="Event distribution">
            {segments.map(({ name, count, share, color }) => (
              <li key={name}>
                <i aria-hidden="true" style={{ background: color }} />
                <span>{name}</span>
                <b>{count.toLocaleString()}</b>
                <span>{share < 0.05 ? "<0.1" : share.toFixed(1)}%</span>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p>Import evidence to generate an observed-activity chart.</p>
      )}
    </article>
  );
}
function Dashboard({
  events,
  eventTotal,
  candidates,
  evaluation,
  uploading,
  upload,
}: {
  events: Evt[];
  eventTotal: number;
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
          value={String(eventTotal).padStart(2, "0")}
          detail="Stored evidence total"
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
  token,
  revision,
  eventTotal,
  uploading,
  upload,
}: {
  token: string;
  revision: number;
  eventTotal: number;
  uploading: boolean;
  upload: (f: File) => Promise<void>;
}) {
  const [query, setQuery] = useState(linkedEvidence ?? "");
  const [category, setCategory] = useState("all");
  const [page, setPage] = useState(1);
  const [result, setResult] = useState<{ items: Evt[]; total: number; page: number; categories: string[] }>();
  const [pageError, setPageError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setPageError("");
    const timer = window.setTimeout(async () => {
      const params = new URLSearchParams({ page: String(page), query, category: category === "all" ? "" : category });
      try {
        const response = await fetch(`${API}/events/page?${params}`, {
          signal: controller.signal,
          headers: DEMO ? {} : { Authorization: `Bearer ${token}` },
        });
        if (!response.ok) throw Error(`Evidence request failed (HTTP ${response.status}).`);
        const data = await response.json();
        if (!controller.signal.aborted) setResult(data);
      } catch (error) {
        if (!controller.signal.aborted) setPageError(error instanceof Error ? error.message : "Unable to load evidence.");
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 200);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [page, query, category, token, revision]);
  const categories = result?.categories ?? [];
  const pages = Math.max(1, Math.ceil((result?.total ?? 0) / 50));
  const safePage = result?.page ?? 1;
  const visible = result?.items ?? [];
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
            Page {safePage} of {pages} · {result?.total ?? 0} matching · {eventTotal.toLocaleString()} stored
          </span>
        </div>
        {eventTotal > 0 && (
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
        {pageError ? <p role="alert">{pageError}</p> : loading ? <p role="status">Loading evidence…</p> : eventTotal > 0 ? (
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
  const csvPicker = useRef<HTMLInputElement>(null);
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [loadingSample, setLoadingSample] = useState(false);
  const [sampleName, setSampleName] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [sampleRow, setSampleRow] = useState("");
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
  async function loadSample(file: File, requestedRow?: string) {
    setLoadingSample(true);
    setError("");
    const form = new FormData();
    form.append("file", file);
    try {
      const query = requestedRow && Number(requestedRow) > 0 ? `?row_number=${encodeURIComponent(requestedRow)}` : "";
      const r = await fetch(`${API}/models/flow-sample${query}`, {
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
      <section className="model-workspace">
        <article className="model-form">
          <small>LIVE FLOW INFERENCE</small>
          <h2>Score a flow</h2>
          <p className="model-help">
            Choose a CICIDS2017 MachineLearningCVE CSV to load a sample, select a row, or score the entire file.
          </p>
          <div className="workspace-actions">
            <button className="button sample-picker" type="button"
              disabled={loadingSample || batchBusy || !model?.available}
              onClick={() => csvPicker.current?.click()}>
              {loadingSample ? "Reading CSV…" : selectedFile ? "Change CICIDS CSV" : "Choose CICIDS CSV"}
            </button>
            <button className="button batch-score" type="button" disabled={!selectedFile || loadingSample || batchBusy} onClick={scoreBatch}>
              {batchBusy ? "Scoring full CSV…" : "Score entire CSV"}
            </button>
          </div>
            <input
              ref={csvPicker}
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
          {sampleName && <small className="sample-name">{sampleName}</small>}
          {selectedFile && <div className="row-picker"><input type="number" min="1" value={sampleRow} onChange={e => setSampleRow(e.target.value)} placeholder="Row number"/><button className="button" type="button" disabled={!sampleRow || loadingSample} onClick={() => void loadSample(selectedFile, sampleRow)}>Load row</button></div>}
          <p className="model-help">Batch scoring analyzes every compatible flow in the selected file and surfaces aggregate rates plus the ten highest-risk rows.</p>
          <form onSubmit={predict}>
            <textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              placeholder={
                '{" Destination Port":80," Flow Duration":12345,...}'
              }
            />
            <button className="button gold" disabled={!model?.available || loadingSample || !payload.trim()}>
              Score this row
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
        <aside className="signal model-applicability">
          <small>MODEL APPLICABILITY</small>
          <h3>CICIDS2017 flows only</h3>
          <p>Random Forest and Isolation Forest require the CICIDS2017 numeric flow schema. Use Evidence Vault for audit and authentication logs.</p>
        </aside>
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
type CaseStatus = "open" | "under_review" | "resolved";
type AnalystCase = { id: string; title: string; severity: string; status: CaseStatus; evidence: Record<string, unknown> };
type CaseEntry = { id: string; action: string; detail: string; created_at: string };

function Cases({ authorization }: { authorization?: string }) {
  const [cases, setCases] = useState<AnalystCase[]>([]);
  const [selected, setSelected] = useState("");
  const [timeline, setTimeline] = useState<CaseEntry[]>([]);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("low");
  const severityLevels = ["low", "medium", "high", "critical"];
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const active = cases.find((item) => item.id === selected);
  async function request<T>(path = "", method = "GET", body?: object): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (authorization) headers.Authorization = authorization;
    const response = await fetch(`${API}/incidents${path}`, { method, headers, body: body && JSON.stringify(body) });
    if (!response.ok) {
      const result = await response.json().catch(() => null);
      throw Error(typeof result?.detail === "string" ? result.detail : `Case request failed (HTTP ${response.status}).`);
    }
    return response.json();
  }
  useEffect(() => {
    let current = true;
    request<AnalystCase[]>().then((items) => { if (current) setCases(items); })
      .catch((failure: Error) => { if (current) setError(failure.message); });
    return () => { current = false; };
  }, [authorization]);
  useEffect(() => {
    if (!selected) return;
    let current = true;
    setTimeline([]);
    request<CaseEntry[]>(`/${selected}/timeline`).then((entries) => { if (current) setTimeline(entries); })
      .catch((failure: Error) => { if (current) setError(failure.message); });
    return () => { current = false; };
  }, [selected, authorization]);
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try { await action(); }
    catch (failure) { setError(failure instanceof Error ? failure.message : "Case request failed."); }
    finally { setBusy(false); }
  }
  return (
    <section className="table-panel case-panel">
      <h2>Case workspace</h2>
      {error && <p className="error" role="alert">{error}</p>}
      <form className="event-controls" onSubmit={(event) => {
        event.preventDefault();
        void perform(async () => {
          const item = await request<AnalystCase>("", "POST", { title: title.trim(), severity, confidence: 0, evidence: {} });
          setCases((items) => [item, ...items]);
          setSelected(item.id);
          setTitle("");
        });
      }}>
        <input aria-label="Case title" placeholder="New case title" value={title} onChange={(event) => setTitle(event.target.value)} maxLength={255} />
        <label>Severity <select value={severity} disabled={busy} onChange={(event) => setSeverity(event.target.value)}>
          {severityLevels.map((level) => <option key={level} value={level}>{level[0].toUpperCase() + level.slice(1)}</option>)}
        </select></label>
        <button className="button gold" disabled={busy || title.trim().length < 3}>Create case</button>
      </form>
      <label>Case <select value={selected} disabled={busy} onChange={(event) => { setSelected(event.target.value); setNote(""); }}>
        <option value="">Select a case</option>
        {cases.map((item) => <option key={item.id} value={item.id}>{item.title} · {item.severity}</option>)}
      </select></label>
      {active && <>
        <h3>{active.title}</h3>
        <p>Analyst-assigned severity: <strong className={`case-severity case-severity--${active.severity}`}>{active.severity}</strong></p>
        <div className="workspace-actions">
        <button className="button case-export" disabled={busy} onClick={() => void perform(async () => {
          setTimeline(await request<CaseEntry[]>(`/${active.id}/timeline`));
          requestAnimationFrame(() => requestAnimationFrame(() => window.print()));
        })}>Print / Save as PDF</button>
        <label>Status <select value={active.status} disabled={busy} onChange={(event) => {
          const status = event.target.value;
          void perform(async () => {
            const updated = await request<AnalystCase>(`/${active.id}/status?status_value=${status}`, "PATCH");
            setCases((items) => items.map((item) => item.id === updated.id ? updated : item));
            setTimeline(await request<CaseEntry[]>(`/${active.id}/timeline`));
          });
        }}>
          <option value="open">Open</option><option value="under_review">Under review</option><option value="resolved">Resolved</option>
        </select></label>
        </div>
        <form className="event-controls" onSubmit={(event) => {
          event.preventDefault();
          void perform(async () => {
            await request(`/${active.id}/notes`, "POST", { text: note });
            setNote("");
            setTimeline(await request<CaseEntry[]>(`/${active.id}/timeline`));
          });
        }}>
          <input aria-label="Review note" placeholder="Add a review note" value={note} maxLength={4000} onChange={(event) => setNote(event.target.value)} />
          <button className="button gold" disabled={busy || !note.trim()}>Add note</button>
        </form>
        <h3>Audit timeline</h3>
        <ul>{timeline.map((entry) => <li key={entry.id}>{new Date(entry.created_at).toLocaleString()} · {entry.action}{entry.detail && ` · ${entry.detail}`}</li>)}</ul>
        <article className="case-print-report">
          <p>ThreatLens · Analyst case report</p>
          <h1>{active.title}</h1>
          <dl>
            <dt>Case ID</dt><dd>{active.id}</dd>
            <dt>Status</dt><dd>{active.status.replaceAll("_", " ")}</dd>
            <dt>Severity</dt><dd>{active.severity}</dd>
          </dl>
          <h2>Attached evidence</h2>
          {Object.keys(active.evidence).length > 0
            ? <pre>{JSON.stringify(active.evidence, null, 2)}</pre>
            : <p>No evidence attached to this case.</p>}
          <h2>Audit timeline</h2>
          {timeline.length ? <ol>{timeline.map((entry) => (
            <li key={entry.id}>
              {new Date(entry.created_at).toLocaleString()} · {entry.action}
              {entry.detail && <p>{entry.detail}</p>}
            </li>
          ))}</ol> : <p>No audit entries are available.</p>}
        </article>
      </>}
    </section>
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
  const [mode, setMode] = useState<"chat" | "brief" | "checklist" | "timeline">("chat");
  async function ask(e: FormEvent) {
    e.preventDefault();
    const question = q.trim() || (mode === "chat" ? "" : mode === "timeline" ? "Show recent login.failed and login.success events" : "What should I review first?");
    if (!question || busy) return;
    setMessages((x) => [...x, { role: "user", text: question, time: stamp() }]);
    setQ("");
    setBusy(true);
    setError("");
    try {
      const r = await fetch(`${API}/chat`, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({
          question,
          mode,
          history: messages.slice(-6).map(({ role, text }) => ({ role, text: text.slice(0, 1500) })),
        }),
      });
      if (!r.ok) throw Error(await fail(r));
      const data = await r.json();
      setMessages((x) => [
        ...x,
        { role: "assistant", text: data.answer, time: stamp(), workflow: data.workflow, timeline: data.timeline },
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
                {m.timeline?.length ? <ol className="investigation-timeline" aria-label="Investigation timeline">
                  {m.timeline.map((event) => (
                    <li key={event.id} data-event-type={event.event_type}>
                      <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString()}</time>
                      <strong>{event.event_type}</strong>
                      {event.source_ip && <span>{event.source_ip}</span>}
                      <a href={`?event=${encodeURIComponent(event.id)}`} target="_blank" rel="noreferrer">Open evidence {event.id.slice(0, 8)}</a>
                    </li>
                  ))}
                </ol> : null}
                {m.workflow?.length ? <details>
                  <summary>Investigation workflow</summary>
                  <ol>{m.workflow.map((stage) => <li key={stage}>{stage}</li>)}</ol>
                </details> : null}
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
        <select aria-label="Investigation output" value={mode} onChange={(e) => {
          const value = e.target.value;
          if (value === "chat" || value === "brief" || value === "checklist" || value === "timeline") setMode(value);
        }} disabled={busy}>
          <option value="chat">Ask a question</option>
          <option value="brief">Draft incident brief</option>
          <option value="checklist">Build review checklist</option>
          <option value="timeline">Generate investigation timeline</option>
        </select>
        <textarea
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Ask about the evidence…"
          required={mode === "chat"}
        />
        <button className="button gold" disabled={busy}>
          {mode === "chat" ? "Send" : "Generate"} <span>↗</span>
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
          <img src="/favicon.svg" alt="" width={28} height={28} />
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
