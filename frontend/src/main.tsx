import { createRoot } from "react-dom/client";
import "./styles.css";

function App() {
  return <main><span aria-hidden="true" className="shield">◇</span><h1>ThreatLens</h1><p>Security intelligence, built on traceable evidence.</p></main>;
}

createRoot(document.getElementById("root")!).render(<App />);

