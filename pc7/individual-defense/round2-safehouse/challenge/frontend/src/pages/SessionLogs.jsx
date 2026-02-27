import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import AnimatedCard from "../components/AnimatedCard";
import AnimatedSpinner from "../components/AnimatedSpinner";

export default function SessionLogs() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("/api/session-audit")
      .then((res) => res.json())
      .then(setData);
  }, []);

  if (!data)
    return (
      <div className="flex flex-col items-center mt-10">
        <AnimatedSpinner />
        <span className="text-green-400 animate-pulse font-mono">Loading session logs…</span>
      </div>
    );

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <AnimatedCard>
        <h2 className="text-xl font-bold text-green-300 mb-2">Session Audit Logs</h2>
        <div className="space-y-2">
          <div>
            <span className="font-mono text-green-400">Session State: </span>
            <span className="text-green-200">{data.current}</span>
          </div>
          <div>
            <span className="font-mono text-green-400">Salt Hint: </span>
            <span className="text-green-200">{data.salt_hint}</span>
          </div>
          <div>
            <span className="font-mono text-green-400">Submission Window: </span>
            <span className={`text-green-200 ${data.window === "active" ? "animate-pulse" : ""}`}>
              {data.window === "active" ? "OPEN" : "CLOSED"}
            </span>
          </div>
        </div>
      </AnimatedCard>
    </motion.div>
  );
}
