import { motion } from "framer-motion";

export default function MissionHeader() {
  return (
    <motion.header
      className="mb-6"
      initial={{ opacity: 0, y: -24 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.8, delay: 0.3 }}
    >
      <h1 className="text-3xl font-mono text-green-400 tracking-wide drop-shadow-lg">
        <span className="mr-2">MISSION:</span>
        <motion.span
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{
            repeat: Infinity,
            repeatType: "reverse",
            duration: 2,
            delay: 1,
          }}
          className="text-green-500/80"
        >
          Safehouse Breach
        </motion.span>
      </h1>
      <div className="text-green-200 font-mono mt-1">
        "All activity monitored. Unauthorized access is forbidden."
      </div>
    </motion.header>
  );
}
