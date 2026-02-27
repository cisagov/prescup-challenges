import { motion } from "framer-motion";

export default function AnimatedError({ children }) {
  return (
    <motion.div
      className="mt-4 px-4 py-2 rounded-lg bg-red-900/80 border border-red-500 text-red-200 font-mono shadow"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
    >
      {children}
    </motion.div>
  );
}
