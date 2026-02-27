import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import AnimatedCard from "../components/AnimatedCard";
import AnimatedSpinner from "../components/AnimatedSpinner";

export default function Dashboard() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("/api/dashboard")
      .then((res) => res.json())
      .then(setData);
  }, []);

  if (!data)
    return (
      <div className="flex flex-col items-center mt-10">
        <AnimatedSpinner />
        <span className="text-green-400 animate-pulse font-mono text-lg mt-2">Loading dashboard…</span>
      </div>
    );

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <div className="mb-6">
        <AnimatedCard>
          <h2 className="text-2xl font-bold text-green-300 mb-2">Mission Briefing</h2>
          <div className="whitespace-pre-line font-mono text-green-200">{data.briefing}</div>
        </AnimatedCard>
      </div>
      <div className="space-y-4">
        {data.notices.map((notice, i) => (
          <AnimatedCard key={i}>
            <div className="flex gap-2 items-center">
              <span className="inline-block w-3 h-3 rounded-full bg-green-400 animate-pulse"></span>
              <span className="font-mono text-green-300">{notice}</span>
            </div>
          </AnimatedCard>
        ))}
      </div>
    </motion.div>
  );
}
