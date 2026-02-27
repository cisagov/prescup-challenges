import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import AnimatedCard from "../components/AnimatedCard";

export default function Notes() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("/api/incident-notes")
      .then((res) => res.json())
      .then(setData);
  }, []);

  if (!data)
    return <div className="text-green-400 animate-pulse font-mono">Loading notes…</div>;

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <AnimatedCard>
        <h2 className="text-xl font-bold text-green-300 mb-2">Incident Notes</h2>
        <div className="font-mono text-green-200 mb-2">{data.message}</div>
        <div className="flex flex-wrap gap-2">
          {data.fragments.map((frag, i) => (
            <div key={i} className="px-2 py-1 bg-green-800 rounded-lg font-mono text-green-100 shadow">
              {frag}
            </div>
          ))}
        </div>
      </AnimatedCard>
    </motion.div>
  );
}
