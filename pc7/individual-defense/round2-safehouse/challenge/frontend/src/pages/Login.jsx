import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import AnimatedError from "../components/AnimatedError";

export default function Login({ setSession }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (data.success && data.session) {
        setSession(data.session);
        localStorage.setItem("session", data.session);
        navigate("/");
      } else {
        setError(data.error || "Access denied.");
      }
    } catch {
      setError("Network error. Try again.");
    }
  }

  return (
    <motion.div
      className="flex items-center justify-center h-screen bg-[#091218] font-mono"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <motion.div
        className="w-full max-w-md bg-[#131d16]/90 rounded-2xl border-2 border-green-800 shadow-2xl p-10"
        initial={{ y: 48, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.7, type: "spring" }}
      >
        <div className="flex flex-col items-center mb-6">
          <img src="/agency-logo.svg" className="w-16 mb-2" alt="Agency" />
          <div className="text-green-400 text-2xl mb-2 font-bold tracking-wider">AGENCY LOGIN</div>
          <div className="text-green-200 text-sm">Authorized agents only. All activity logged.</div>
        </div>
        <form className="space-y-5" onSubmit={handleSubmit}>
          <div>
            <label className="block mb-1 text-green-300">Codename</label>
            <input
              className="w-full px-4 py-2 rounded-lg bg-[#19282b] border border-green-800 text-green-100 focus:outline-none"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
              autoComplete="username"
              placeholder="e.g. employee"
            />
          </div>
          <div>
            <label className="block mb-1 text-green-300">Passphrase</label>
            <input
              className="w-full px-4 py-2 rounded-lg bg-[#19282b] border border-green-800 text-green-100 focus:outline-none"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              type="password"
              autoComplete="current-password"
              placeholder="*******"
            />
          </div>
          <button
            className="w-full mt-2 px-6 py-2 rounded-lg bg-green-700 text-white font-bold hover:bg-green-900 transition"
            type="submit"
          >
            Login
          </button>
        </form>
        {error && <AnimatedError>{error}</AnimatedError>}
      </motion.div>
    </motion.div>
  );
}
