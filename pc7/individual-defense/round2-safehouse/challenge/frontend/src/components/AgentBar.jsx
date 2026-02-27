import React from "react";
import { User } from "lucide-react";

export default function AgentBar() {
  const session = localStorage.getItem("session") || "unknown";
  const codename = session.split("-")[0] || "unknown";
  return (
    <div className="fixed top-4 right-10 flex items-center gap-3 z-40">
      <div className="flex items-center gap-2 bg-[#163921] px-4 py-2 rounded-xl shadow border border-green-800">
        <User className="text-green-400 w-5 h-5" />
        <span className="text-green-300 font-mono text-sm">Agent: {codename}</span>
      </div>
    </div>
  );
}
