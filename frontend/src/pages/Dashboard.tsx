import { useState, useEffect } from "react";
import { useThreatStore } from "../store/useThreatStore";
import { Send, Loader2, ShieldAlert, CheckCircle2, XCircle, ShieldCheck, Activity, Sliders } from "lucide-react";
import ThreatGraph from "../components/ThreatGraph";
import ArtifactViewer from "../components/ArtifactViewer";
import Coverage from "../components/Coverage";
import ThreatAssessment from "../components/ThreatAssessment"; 
import AttackSimulationView from "../components/AttackSimulationView"; // <-- Impor komponen simulasi
import { useLocation } from "react-router-dom";

export default function Dashboard() {
  const {
    scenarioInput,
    setScenarioInput,
    processScenario,
    isProcessing,
    cirData,
    cirSpec,
    scenarioId,
    error,
    artifacts,
    fetchArtifacts,
    validation,
  } = useThreatStore();

  // Tambahkan "simulation" ke dalam tipe union activeTab
  const [activeTab, setActiveTab] = useState<
    "graph" | "artifacts" | "validation" | "coverage" | "assessment" | "simulation"
  >("graph");

  const [selectedArtifact, setSelectedArtifact] = useState<
    "sigma" | "kql" | "spl"
  >("sigma");

  const location = useLocation();

  useEffect(() => {
    if (location.state && location.state.loadedScenario) {
      const scenario = location.state.loadedScenario;
      setScenarioInput(scenario.original_input);
      window.history.replaceState({}, document.title);
    }
  }, [location, setScenarioInput]);

  const handleTabChange = (
    tab: "graph" | "artifacts" | "validation" | "coverage" | "assessment" | "simulation"
  ) => {
    setActiveTab(tab);

    if (tab === "artifacts" && scenarioId) {
      fetchArtifacts(scenarioId, selectedArtifact);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <header>
        <h2 className="text-2xl font-bold text-white mb-2">
          Threat Narrative Processor
        </h2>
        <p className="text-gray-400">
          Transform natural language attack scenarios into deterministic CIR graphs.
        </p>
      </header>

      {/* ================= INPUT ================= */}
      <div className="bg-surface border border-gray-800 rounded-xl p-6 shadow-xl">
        <textarea
          rows={6}
          className="w-full bg-background border border-gray-700 rounded-lg p-4 text-gray-100 outline-none focus:ring-2 focus:ring-primary"
          placeholder="Example: Attacker sends phishing email..."
          value={scenarioInput}
          onChange={(e) => setScenarioInput(e.target.value)}
        />

        <button
          onClick={processScenario}
          disabled={isProcessing}
          className="mt-4 flex items-center px-6 py-2.5 bg-primary text-white rounded-lg hover:bg-blue-600 disabled:opacity-50"
        >
          {isProcessing ? (
            <Loader2 className="animate-spin mr-2" />
          ) : (
            <Send className="mr-2" />
          )}
          Generate Artifacts
        </button>

        {error && !cirData && (
          <p className="mt-3 text-red-400 flex items-center">
            <ShieldAlert size={16} className="mr-2" />
            {error}
          </p>
        )}
      </div>

      {/* ================= RESULT ================= */}
      {(cirData || validation) && (
        <div className="bg-surface border border-gray-800 rounded-xl p-6 shadow-xl">

          {/* TAB NAVIGATION */}
          <div className="flex gap-6 border-b border-gray-700 mb-6 overflow-x-auto">
            <button
              onClick={() => handleTabChange("graph")}
              className={`pb-2 whitespace-nowrap ${
                activeTab === "graph"
                  ? "border-b-2 border-primary text-primary"
                  : "text-gray-400"
              }`}
            >
              Attack Graph
            </button>

            <button
              onClick={() => handleTabChange("artifacts")}
              className={`pb-2 whitespace-nowrap ${
                activeTab === "artifacts"
                  ? "border-b-2 border-primary text-primary"
                  : "text-gray-400"
              }`}
            >
              Detection Artifacts
            </button>

            <button
              onClick={() => handleTabChange("validation")}
              className={`pb-2 flex items-center gap-2 whitespace-nowrap ${
                activeTab === "validation"
                  ? "border-b-2 border-primary text-primary"
                  : "text-gray-400"
              }`}
            >
              Validation
              {validation &&
                (validation.valid ? (
                  <CheckCircle2 size={16} className="text-green-500" />
                ) : (
                  <XCircle size={16} className="text-red-500" />
                ))}
            </button>

            <button
              onClick={() => handleTabChange("coverage")}
              className={`pb-2 flex items-center gap-2 whitespace-nowrap ${
                activeTab === "coverage"
                  ? "border-b-2 border-primary text-primary"
                  : "text-gray-400"
              }`}
            >
              <ShieldCheck size={16} />
              Coverage
            </button>

            <button
              onClick={() => handleTabChange("assessment")}
              className={`pb-2 flex items-center gap-2 whitespace-nowrap ${
                activeTab === "assessment"
                  ? "border-b-2 border-primary text-primary"
                  : "text-gray-400"
              }`}
            >
              <Activity size={16} />
              Threat Assessment
            </button>

            {/* TAB BARU: ATTACK SIMULATION */}
            <button
              onClick={() => handleTabChange("simulation")}
              className={`pb-2 flex items-center gap-2 whitespace-nowrap ${
                activeTab === "simulation"
                  ? "border-b-2 border-primary text-primary"
                  : "text-gray-400"
              }`}
            >
              <Sliders size={16} />
              Simulation
            </button>
          </div>

          {/* ================= GRAPH ================= */}
          {activeTab === "graph" && (
            <div className="min-h-[700px]">
              {cirData ? (
                <ThreatGraph 
                  data={(cirData as any).cir || cirData}
                  specification={cirSpec ?? undefined}
                  scenarioId={scenarioId ?? undefined} 
                />
              ) : (
                <div className="flex items-center justify-center h-full text-gray-500">
                  No graph data available. Please generate artifacts first.
                </div>
              )}
            </div>
          )}

          {/* ================= ARTIFACT ================= */}
          {activeTab === "artifacts" && cirData && (
            <div className="space-y-4">
              <div className="flex gap-2">
                {(["sigma", "kql", "spl"] as const).map((type) => (
                  <button
                    key={type}
                    onClick={() => {
                      setSelectedArtifact(type);
                      if (scenarioId) {
                        fetchArtifacts(scenarioId, type);
                      }
                    }}
                    className={`px-4 py-2 rounded ${
                      selectedArtifact === type
                        ? "bg-primary text-white"
                        : "bg-gray-800 text-gray-400"
                    }`}
                  >
                    {type.toUpperCase()}
                  </button>
                ))}
              </div>

              <ArtifactViewer
                code={artifacts[selectedArtifact] || ""}
                language={selectedArtifact.toUpperCase()}
              />
            </div>
          )}

          {/* ================= VALIDATION ================= */}
          {activeTab === "validation" && validation && (
            <div
              className={`rounded-lg p-6 ${
                validation.valid
                  ? "bg-green-950 border border-green-700"
                  : "bg-red-950 border border-red-700"
              }`}
            >
              <div className="flex items-center gap-3 mb-5">
                {validation.valid ? (
                  <>
                    <CheckCircle2 className="text-green-400" />
                    <h3 className="text-green-400 font-bold text-lg">
                      CIR STRUCTURE VALID
                    </h3>
                  </>
                ) : (
                  <>
                    <XCircle className="text-red-400" />
                    <h3 className="text-red-400 font-bold text-lg">
                      CIR VALIDATION FAILED
                    </h3>
                  </>
                )}
              </div>

              {validation.errors && validation.errors.length > 0 && (
                <>
                  <h4 className="text-red-300 font-semibold mb-2">Detected Issues</h4>
                  <ul className="list-disc ml-6 space-y-2">
                    {validation.errors.map((err, index) => (
                      <li key={index}>{err}</li>
                    ))}
                  </ul>
                </>
              )}

              {validation.warnings && validation.warnings.length > 0 && (
                <>
                  <h4 className="text-yellow-300 font-semibold mt-5 mb-2">Warnings</h4>
                  <ul className="list-disc ml-6 space-y-2">
                    {validation.warnings.map((warn, index) => (
                      <li key={index}>{warn}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}

          {/* ================= COVERAGE ================= */}
          {activeTab === "coverage" && scenarioId && (
            <Coverage scenarioId={scenarioId} />
          )}

          {/* ================= THREAT ASSESSMENT ================= */}
          {activeTab === "assessment" && scenarioId && (
            <div className="h-full">
              <ThreatAssessment scenarioId={scenarioId} />
            </div>
          )}

          {/* ================= ATTACK SIMULATION (TAB BARU) ================= */}
          {activeTab === "simulation" && scenarioId && (
            <div className="h-full">
              <AttackSimulationView scenarioId={scenarioId} />
            </div>
          )}

        </div>
      )}
    </div>
  );
}
