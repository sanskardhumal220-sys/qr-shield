import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen bg-black text-white selection:bg-indigo-500/30 overflow-hidden relative">
      {/* Ambient background glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[500px] h-[500px] bg-indigo-600/20 rounded-full blur-[120px] mix-blend-screen pointer-events-none animate-[blob_7s_infinite]"></div>
      <div className="absolute top-[20%] right-[-10%] w-[400px] h-[400px] bg-emerald-500/10 rounded-full blur-[100px] mix-blend-screen pointer-events-none animate-[blob_7s_infinite_2s]"></div>
      <div className="absolute bottom-[-20%] left-[20%] w-[600px] h-[600px] bg-purple-600/15 rounded-full blur-[150px] mix-blend-screen pointer-events-none animate-[blob_7s_infinite_4s]"></div>

      {/* Header */}
      <header className="relative z-10 glass-panel border-b border-white/5 border-t-0 border-x-0">
        <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center p-2 shadow-[0_0_20px_rgba(99,102,241,0.4)]">
              <img src="/app/shield_icon.png" alt="Logo" className="w-full h-full object-contain filter brightness-0 invert" />
            </div>
            <span className="font-bold text-xl tracking-wide">QR SHIELD</span>
          </div>
          <nav className="hidden md:flex gap-8 text-sm font-medium text-white/70">
            <Link href="#features" className="hover:text-white transition-colors">Features</Link>
            <Link href="#how-it-works" className="hover:text-white transition-colors">How it works</Link>
            <Link href="#security" className="hover:text-white transition-colors">Security</Link>
          </nav>
          <Link href="/app" className="btn-primary px-6 py-2.5 rounded-full text-sm font-semibold tracking-wide flex items-center gap-2">
            Open Dashboard 
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14"></path><path d="m12 5 7 7-7 7"></path></svg>
          </Link>
        </div>
      </header>

      {/* Hero Section */}
      <main className="relative z-10 max-w-7xl mx-auto px-6 pt-32 pb-24 lg:pt-48 lg:pb-32">
        <div className="flex flex-col items-center text-center max-w-4xl mx-auto">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass-panel text-sm font-medium text-indigo-300 mb-8 [animation:fadeInUp_0.8s_ease-out_forwards]">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-500"></span>
            </span>
            v2.5 AI Engine Now Live
          </div>
          
          <h1 className="text-5xl md:text-7xl font-bold tracking-tight mb-8 leading-[1.1] [animation:fadeInUp_0.8s_ease-out_0.1s_forwards] opacity-0">
            Next-Generation <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 via-purple-400 to-emerald-400">
              Quishing Detection
            </span>
          </h1>
          
          <p className="text-lg md:text-xl text-white/60 mb-12 max-w-2xl leading-relaxed [animation:fadeInUp_0.8s_ease-out_0.2s_forwards] opacity-0">
            Defend against malicious QR codes and advanced phishing threats with our hybrid AI engine. XGBoost Machine Learning meets enterprise-grade rule sets in a beautiful, serverless dashboard.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 w-full sm:w-auto [animation:fadeInUp_0.8s_ease-out_0.3s_forwards] opacity-0">
            <Link href="/app" className="btn-primary px-8 py-4 rounded-full text-base font-semibold flex items-center justify-center gap-2 group">
              Scan a QR Code
              <svg className="group-hover:translate-x-1 transition-transform" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><rect x="7" y="7" width="10" height="10" rx="1"></rect></svg>
            </Link>
            <a href="#features" className="btn-secondary px-8 py-4 rounded-full text-base font-semibold flex items-center justify-center">
              Explore Features
            </a>
          </div>
        </div>

        {/* Feature grid */}
        <div id="features" className="mt-40 grid md:grid-cols-3 gap-6 [animation:fadeInUp_0.8s_ease-out_0.5s_forwards] opacity-0">
          <div className="glass-panel p-8 rounded-2xl hover:bg-white/[0.02] transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-xl flex items-center justify-center mb-6 text-indigo-400 group-hover:scale-110 transition-transform">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
            </div>
            <h3 className="text-xl font-bold mb-3 text-white">XGBoost ML Models</h3>
            <p className="text-white/60 leading-relaxed text-sm">
              Trained on 10,000+ malicious samples, our advanced machine learning algorithm spots minute anomalies that static scanners miss.
            </p>
          </div>
          
          <div className="glass-panel p-8 rounded-2xl hover:bg-white/[0.02] transition-colors group">
            <div className="w-12 h-12 bg-emerald-500/10 rounded-xl flex items-center justify-center mb-6 text-emerald-400 group-hover:scale-110 transition-transform">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            </div>
            <h3 className="text-xl font-bold mb-3 text-white">Hybrid Decision Engine</h3>
            <p className="text-white/60 leading-relaxed text-sm">
              Combines deterministic rules, URL shortener tracing, and heuristic AI to provide an infallible risk score for every scan.
            </p>
          </div>
          
          <div className="glass-panel p-8 rounded-2xl hover:bg-white/[0.02] transition-colors group">
            <div className="w-12 h-12 bg-purple-500/10 rounded-xl flex items-center justify-center mb-6 text-purple-400 group-hover:scale-110 transition-transform">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
            </div>
            <h3 className="text-xl font-bold mb-3 text-white">AI Sandbox Analysis</h3>
            <p className="text-white/60 leading-relaxed text-sm">
              Safely detonate payloads within isolated browser iframes and let our ChatGPT-style agent synthesize the risk narrative.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/5 relative z-10 mt-20">
        <div className="max-w-7xl mx-auto px-6 py-12 flex flex-col md:flex-row justify-between items-center gap-6">
          <div className="flex items-center gap-2 opacity-50">
            <img src="/app/favicon.png" alt="Favicon" className="w-6 h-6 grayscale" />
            <span className="font-semibold text-sm tracking-widest">QR SHIELD INC</span>
          </div>
          <p className="text-sm text-white/40">© {new Date().getFullYear()} QR Shield. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}
