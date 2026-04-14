import React, { useState } from "react";
import { motion } from "framer-motion";
import AnimatedCard from "./AnimatedCard";
import AnimatedError from "./AnimatedError";
import CheckpointModal from "./CheckpointModal";
import AnimatedSpinner from "./AnimatedSpinner";

export default function IncidentReport() {
  const [session, setSession] = useState("");
  const [payload, setPayload] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [modal, setModal] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    setResult(null);
    try {
      const res = await fetch("/api/incident/submit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Ops-Session": session,
        },
        body: JSON.stringify({ payload }),
      });
      const data = await res.json();
      if (data.token) {
        setResult(data);
        setModal(true);
      } else if (data.error) {
        setError(data.error);
      } else {
        setError("Unexpected error: No response from backend.");
      }
    } catch {
      setError("Network error: Could not reach agency backend.");
    }
    setSubmitting(false);
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <AnimatedCard>
        <h2 className="text-2xl font-bold text-green-300 mb-2">Incident Report (Protocol-v1)</h2>
        <div className="mb-4 text-green-200 font-mono text-base">
          <strong>INSTRUCTIONS:</strong>  
          <br />• Use a <span className="text-green-400">valid Ops-Session header</span> (see session audit/notes).
          <br />• Payload must be <span className="text-green-400">double-base64 encoded</span> with nonstandard serialization (per docs).
          <br />• Submission is accepted <span className="text-green-400">only during a sync window</span>.
          <br />• All successful reports receive a secure checkpoint transmission.
        </div>
        <form className="space-y-4" onSubmit={handleSubmit}>
          <div>
            <label className="block font-mono text-green-400 mb-1">Ops-Session Header</label>
            <input
              className="w-full bg-[#19282b] border border-green-800 rounded-lg px-3 py-2 font-mono text-green-200 focus:outline-none"
              type="text"
              value={session}
              onChange={(e) => setSession(e.target.value)}
              placeholder="Paste your session secret here"
              autoComplete="off"
              required
            />
          </div>
          <div>
            <label className="block font-mono text-green-400 mb-1">Incident Payload</label>
            <textarea
              className="w-full h-28 bg-[#19282b] border border-green-800 rounded-lg px-3 py-2 font-mono text-green-200 focus:outline-none"
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              placeholder="Paste double-base64, protocol-v1 encoded payload here"
              required
            />
          </div>
          <button
            className="bg-green-700 text-white font-mono px-6 py-2 rounded-lg hover:bg-green-800 active:bg-green-900 shadow transition disabled:opacity-70"
            type="submit"
            disabled={submitting}
          >
            {submitting ? <AnimatedSpinner /> : "Submit Report"}
          </button>
        </form>
        {error && <AnimatedError>{error}</AnimatedError>}
      </AnimatedCard>
      <CheckpointModal
        open={modal}
        onClose={() => setModal(false)}
        message={result ? result.message : ""}
        token={result ? result.token : ""}
      />
    </motion.div>
  );
}
