import { Home, FileText, BookOpen, Terminal, MessageCircle, List } from "lucide-react";
import { motion } from "framer-motion";
import { Link, useLocation } from "react-router-dom";

const navItems = [
  { name: "Dashboard", icon: <Home />, path: "/" },
  { name: "Incident Reports", icon: <FileText />, path: "/incident" },
  { name: "Internal Docs", icon: <BookOpen />, path: "/docs" },
  { name: "Session Logs", icon: <Terminal />, path: "/session" },
  { name: "Incident Notes", icon: <List />, path: "/notes" },
  { name: "Feedback", icon: <MessageCircle />, path: "/feedback" },
];

export default function Sidebar() {
  const location = useLocation();
  return (
    <aside className="w-56 bg-[#111b23] border-r border-green-900 min-h-screen flex flex-col items-center py-8 shadow-lg">
      <img src="/agency-logo.svg" alt="Agency Logo" className="w-12 mb-8" />
      <span className="text-green-400 font-bold tracking-widest mb-8 text-xl animate-pulse">SAFEHOUSE</span>
      <nav className="flex flex-col gap-4 w-full">
        {navItems.map((item) => (
          <Link key={item.path} to={item.path} className="w-full group">
            <motion.div
              className={`flex items-center gap-4 px-5 py-3 rounded-2xl font-mono text-green-300 hover:bg-green-800/20 transition 
              ${location.pathname === item.path ? "bg-green-800/30 border-l-4 border-green-400" : ""}`}
              whileHover={{ scale: 1.04, x: 4 }}
              whileTap={{ scale: 0.97 }}
            >
              <span>{item.icon}</span>
              <span>{item.name}</span>
            </motion.div>
          </Link>
        ))}
      </nav>
    </aside>
  );
}
