// src/PortalLayout.jsx
export default function PortalLayout({ children }) {
  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100">
      {/* Header / chrome */}
      <header className="border-b border-neutral-900/80 bg-neutral-950/70 backdrop-blur">
        <div className="mx-auto max-w-6xl px-4 py-4 flex items-center gap-3">
          <img src="/agency-logo.svg" className="h-8 w-8" />
          <h1 className="text-lg font-semibold tracking-wide">
            SAFEHOUSE RECORDS PORTAL
          </h1>
        </div>
      </header>

      {/* Main content */}
      <main className="mx-auto max-w-6xl px-4 py-10">
        {children}
      </main>
    </div>
  );
}

