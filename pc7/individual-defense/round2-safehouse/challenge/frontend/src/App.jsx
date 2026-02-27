import React, { useState } from "react";
import { motion } from "framer-motion";
import { Shield, Database, Lock, Info, KeyRound, ChevronRight } from "lucide-react";

function Field({ label, type = "text", name, placeholder, autoComplete }) {
  return (
    <label className="block">
      <span className="text-sm text-neutral-300">{label}</span>
      <input
        type={type}
        name={name}
        placeholder={placeholder}
        autoComplete={autoComplete}
        className="mt-1 w-full rounded-xl bg-neutral-900/80 border border-neutral-800 px-3 py-2 text-neutral-100 placeholder-neutral-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
      />
    </label>
  );
}

export default function App() {
  const [submitting, setSubmitting] = useState(false);
  const [msg, setMsg] = useState("");

  const onFakeSubmit = async (e) => {
    e.preventDefault();
    setMsg("");
    setSubmitting(true);
    await new Promise((r) => setTimeout(r, 700));
    setSubmitting(false);
    setMsg("SSO redirect blocked in this environment. Use /portal/admin-entry endpoint.");
  };

  return (
    <div className="min-h-screen text-neutral-100">
      <header className="border-b border-neutral-900/80 bg-neutral-950/70 backdrop-blur">
        <div className="mx-auto max-w-6xl px-4 py-4 flex items-center gap-3">
          <img src="/agency-logo.svg" alt="" aria-hidden="true" className="h-8 w-8" />
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-blue-400" />
              <h1 className="text-lg font-semibold tracking-wide">SAFEHOUSE RECORDS PORTAL</h1>
            </div>
            <p className="text-xs text-neutral-400">Directorate of Field Logistics · Records Division</p>
          </div>
          <div className="ml-auto flex items-center gap-2 text-xs">
            <span className="rounded-full bg-emerald-500/20 text-emerald-300 px-2 py-0.5">STATUS: OPERATIONAL</span>
            <span className="rounded-full bg-amber-500/20 text-amber-300 px-2 py-0.5">SYNC WINDOW: CLOSED</span>
          </div>
        </div>
      </header>

      <div className="border-b border-neutral-900/80 bg-neutral-900/60">
        <div className="mx-auto max-w-6xl px-4 py-2 text-sm flex items-center gap-2">
          <Info className="h-4 w-4 text-blue-300" />
          <span className="text-neutral-300">AUTHORIZED USE ONLY — Monitoring and auditing in effect.</span>
        </div>
      </div>

      <main className="mx-auto max-w-6xl px-4 py-10">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <motion.section
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.35 }}
            className="rounded-2xl border border-neutral-900 bg-neutral-950/60 shadow-xl"
          >
            <div className="p-6">
              <div className="flex items-center gap-3 mb-2">
                <Database className="h-5 w-5 text-blue-400" />
                <h2 className="text-xl font-semibold tracking-wide">About the Safehouse Records Database (SRD)</h2>
              </div>
              <p className="text-neutral-300 leading-relaxed">
                The SRD is an internal repository for field Safehouse logistics, access audits, and encrypted incident
                submissions. Data is compartmentalized and access is governed by role-based policy and session posture.
              </p>
              <ul className="mt-5 space-y-3 text-neutral-300">
                <li className="flex items-start gap-2">
                  <ChevronRight className="mt-1 h-4 w-4 text-neutral-500" />
                  <span><span className="text-neutral-200">Briefings:</span> Current operational notices and maintenance windows.</span>
                </li>
                <li className="flex items-start gap-2">
                  <ChevronRight className="mt-1 h-4 w-4 text-neutral-500" />
                  <span><span className="text-neutral-200">Audit Trails:</span> Session tokens, access attempts, and integrity events.</span>
                </li>
                <li className="flex items-start gap-2">
                  <ChevronRight className="mt-1 h-4 w-4 text-neutral-500" />
                  <span><span className="text-neutral-200">Incident Intake:</span> Encrypted upload path for legacy protocol-v1 reports.</span>
                </li>
              </ul>
              <div className="mt-6 rounded-xl border border-neutral-800 bg-neutral-900/50 p-4">
                <p className="text-sm text-neutral-400">
                  <span className="font-semibold text-neutral-200">NOTICE:</span> This system holds official agent records. Do not add any additional information to this datastore without express authorization of the SRD custodians.
                </p>
              </div>
            </div>
          </motion.section>

          <motion.section
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05, duration: 0.35 }}
            className="rounded-2xl border border-neutral-900 bg-neutral-950/60 shadow-xl"
          >
            <div className="p-6">
              <div className="flex items-center gap-3 mb-4">
                <Lock className="h-5 w-5 text-blue-400" />
                <h2 className="text-xl font-semibold tracking-wide">Agency Sign-In</h2>
              </div>
              <form onSubmit={onFakeSubmit} className="space-y-4">
                <Field label="Username" name="username" placeholder="e.g. jdoe" autoComplete="username" />
                <Field label="Password" type="password" name="password" placeholder="••••••••" autoComplete="current-password" />
                <div className="flex items-center justify-between">
                  <label className="inline-flex items-center gap-2 text-sm text-neutral-400">
                    <input type="checkbox" className="h-4 w-4 rounded border-neutral-700 bg-neutral-900" />
                    Remember this device
                  </label>
                  <a className="text-sm text-blue-300 hover:text-blue-200" href="#" onClick={(e)=>e.preventDefault()}>
                    Forgot password?
                  </a>
                </div>
                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full rounded-xl bg-blue-600 hover:bg-blue-500 transition text-white font-medium py-2.5 disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {submitting ? "Contacting SSO…" : "Sign in"}
                </button>
              </form>
              {msg && (
                <div className="mt-4 rounded-xl border border-neutral-800 bg-neutral-900/60 p-3 text-sm text-neutral-300">
                  {msg}
                </div>
              )}
              <div className="mt-6 text-xs text-neutral-500 leading-relaxed">
                WARNING: This is an agency information system. By attempting to access, you consent to monitoring,
                interception, recording, and disclosure for official purposes. Unauthorized use is prohibited and may
                result in penalties.
              </div>
              <div className="mt-4 text-xs text-neutral-500">
                <KeyRound className="inline h-3.5 w-3.5 mr-1" />
                For real backend wiring later, POST to <code className="text-neutral-400">/api/login</code> and store the session.
              </div>
            </div>
          </motion.section>
        </div>
      </main>

      <footer className="border-t border-neutral-900/80 bg-neutral-950/70">
        <div className="mx-auto max-w-6xl px-4 py-4 text-xs text-neutral-500">
          © {new Date().getFullYear()} Directorate of Field Logistics · SRD v1.0 · Property of the Agency
        </div>
      </footer>
    </div>
  );
}

