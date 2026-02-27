import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import AnimatedCard from "../components/AnimatedCard";
import AnimatedSpinner from "../components/AnimatedSpinner";

export default function Docs() {
  const [doc, setDoc] = useState(null);

  useEffect(() => {
    fetch("/api/docs/submission-protocols")
      .then((res) => res.json())
      .then(setDoc);
  }, []);

  if (!doc)
    return (
      <div className="flex flex-col items-center mt-10">
        <AnimatedSpinner />
        <span className="text-green-400 animate-pulse font-mono">Loading documentation…</span>
      </div>
    );

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <AnimatedCard>
        <h2 className="text-xl font-bold text-green-300 mb-2">{doc.title}</h2>
        <div className="whitespace-pre-line font-mono text-green-200">{doc.content}</div>
      </AnimatedCard>
    </motion.div>
  );
}
