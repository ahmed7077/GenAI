import { ShieldCheck } from "lucide-react";
import { createRoot } from "react-dom/client";
import "./styles.css";

function App() {
  return <main><ShieldCheck aria-hidden="true" size={44} /><h1>ThreatLens</h1><p>Security intelligence, built on traceable evidence.</p></main>;
}

createRoot(document.getElementById("root")!).render(<App />);

