import React, { useState } from "react";
import { motion } from "framer-motion";
import AnimatedCard from "../components/AnimatedCard";
import AnimatedError from "../components/AnimatedError";

export default function Feedback() {
  const [feedback, setFeedback] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setResult(null);
    setError("");
    try {
      const res = await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ feedback }),
      });
      const data = await res.json();
      if (data.log || data.message) setResult(data);
      else if (data.error) setError(data.error);
    } catch {
      setError("Network error: Could not reach agency backend.");
    }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <AnimatedCard>
        <h2 className="text-2xl font-bold text-green-300 mb-2">Submit Field Feedback</h2>
        <form className="space-y-4" onSubmit={handleSubmit}>
          <textarea
            className="w-full h-20 bg-[#19282b] border border-green-800 rounded-lg px-3 py-2 font-mono text-green-200 focus:outline-none"
            value={feedback}
            onChange={(e) => setFeedback(e.target.value)}
            placeholder="Send field intelligence or command input"
            required
          />
          <button
            className="bg-green-700 text-white font-mono px-6 py-2 rounded-lg hover:bg-green-800 active:bg-green-900 shadow transition"
            type="submit"
          >
            Submit Feedback
          </button>
        </form>
        {error && <AnimatedError>{error}</AnimatedError>}
        {result && (
          <div className="mt-4 space-y-2">
            {result.log && (
              <div>
                <div className="font-mono text-green-400 mb-2">Feedback Log:</div>
                <div className="flex gap-2 flex-wrap">
                  {result.log.map((l, i) => (
                    <div key={i} className="px-2 py-1 bg-green-800 rounded-lg font-mono text-green-100 shadow">
                      {l}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {result.message && <div className="text-green-200 font-mono">{result.message}</div>}
          </div>
        )}
      </AnimatedCard>
    </motion.div>
  );
}
