import { motion, AnimatePresence } from "framer-motion";
import { useEffect } from "react";

export default function CheckpointModal({ open, onClose, message, token }) {
  useEffect(() => {
    if (open) {
      const audio = new window.Audio("/radio-static.mp3");
      audio.volume = 0.3;
      audio.play();
    }
  }, [open]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 flex items-center justify-center z-50 bg-black/70 backdrop-blur"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          <motion.div
            className="bg-[#192e1e] rounded-2xl border-2 border-green-600 shadow-2xl px-10 py-8 text-center max-w-md"
            initial={{ scale: 0.88, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.8, opacity: 0 }}
            transition={{ type: "spring", duration: 0.7 }}
          >
            <div className="text-green-400 text-xl font-mono mb-2 animate-pulse">
              <span role="img" aria-label="radio">📻</span> Secure Agency Transmission
            </div>
            <div className="text-green-100 font-mono whitespace-pre-line mb-3">
              {message}
            </div>
            {token && (
              <div className="my-3 font-bold font-mono text-green-300">
                <span className="text-green-400">Token:</span> {token}
              </div>
            )}
            <button
              onClick={onClose}
              className="mt-3 px-6 py-2 rounded-lg bg-green-800 text-white font-mono hover:bg-green-900 shadow"
            >
              Close
            </button>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
