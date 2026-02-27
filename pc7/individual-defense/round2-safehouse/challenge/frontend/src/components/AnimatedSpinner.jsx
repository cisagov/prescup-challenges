import { motion } from "framer-motion";

export default function AnimatedSpinner() {
  return (
    <motion.div
      className="mx-auto mt-8 w-12 h-12 flex items-center justify-center"
      animate={{ rotate: 360 }}
      transition={{ repeat: Infinity, duration: 1.2, ease: "linear" }}
    >
      <svg viewBox="0 0 50 50" className="w-10 h-10">
        <circle
          cx="25"
          cy="25"
          r="20"
          fill="none"
          stroke="#59ff59"
          strokeWidth="4"
          strokeDasharray="100"
          strokeDashoffset="70"
          strokeLinecap="round"
        />
      </svg>
    </motion.div>
  );
}
