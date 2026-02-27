// src/PortalNotFound.jsx
import { Link } from "react-router-dom";
import PortalLayout from "./PortalLayout";

export default function PortalNotFound() {
  return (
    <PortalLayout>
      <div className="text-center py-24">
        <h2 className="text-4xl font-bold mb-4">404</h2>
        <p className="text-neutral-400 mb-6">
          This safehouse location does not exist.
        </p>

        <Link
          to="/portal"
          className="inline-block rounded-xl bg-green-800/30 px-6 py-2 hover:bg-green-800/50 transition"
        >
          Return to Portal
        </Link>
      </div>
    </PortalLayout>
  );
}

