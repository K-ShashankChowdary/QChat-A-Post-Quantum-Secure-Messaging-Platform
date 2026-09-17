import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useScroll, useSpring } from 'framer-motion';
import LatticeField from './visuals/LatticeField';
import ScrambleText from './visuals/ScrambleText';
import Logo from './visuals/Logo';
import {
  ShieldCheck, ArrowRight, Lock, KeyRound, Cpu, MessageSquare,
  Video, Paperclip, Fingerprint, UserPlus, Check, X, Server, Zap, ChevronDown
} from 'lucide-react';

/* Card that tracks the cursor for a spotlight highlight. */
const SpotCard = ({ children, className = '' }) => {
  const onMove = (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty('--mx', `${e.clientX - r.left}px`);
    e.currentTarget.style.setProperty('--my', `${e.clientY - r.top}px`);
  };
  return (
    <div onMouseMove={onMove} className={`glass spotlight lift ${className}`}>
      {children}
    </div>
  );
};

/* Reveal-on-scroll wrapper. */
const Reveal = ({ children, delay = 0, className = '' }) => (
  <motion.div
    className={className}
    initial={{ opacity: 0, y: 24 }}
    whileInView={{ opacity: 1, y: 0 }}
    viewport={{ once: true, margin: '-80px' }}
    transition={{ duration: 0.55, delay, ease: [0.22, 1, 0.36, 1] }}
  >
    {children}
  </motion.div>
);

const PIPELINE = [
  {
    icon: KeyRound,
    step: '01',
    title: 'Keys are born on your device',
    body: 'Registering generates an ML-KEM-768 keypair in your browser. The 1184-byte public half goes to the server; the 2400-byte secret half stays in this device’s local storage and is never sent anywhere.',
  },
  {
    icon: Cpu,
    step: '02',
    title: 'A lattice problem wraps the key',
    body: 'Each message gets a fresh 32-byte content key. Only that key is encapsulated — once per participant — using ML-KEM-768, whose hardness rests on finding short vectors in a module lattice. Shor’s algorithm does not apply.',
  },
  {
    icon: Lock,
    step: '03',
    title: 'AES-256-GCM seals the message',
    body: 'The body is encrypted once under that content key, with a 12-byte nonce and a 16-byte authentication tag — so a single flipped bit fails to decrypt rather than quietly producing garbage.',
  },
];

const FEATURES = [
  { icon: MessageSquare, title: 'Real-time messaging', body: 'Delivery and read receipts, typing indicators, replies, reactions and delete-for-everyone — all of it encrypted end to end.' },
  { icon: Paperclip,     title: 'Files and voice notes', body: 'Images, documents and recorded audio travel through the same pipeline as text. Filenames are encrypted too.' },
  { icon: Video,         title: 'Peer-to-peer video calls', body: 'Media flows directly between devices over WebRTC. Every SDP offer, answer and ICE candidate is post-quantum encrypted before touching the relay; the media itself rides on DTLS-SRTP.' },
  { icon: UserPlus,      title: 'Private by default',  body: 'No public directory. You are found only by a shareable QChat ID such as QC-8L99-2TVY, matched exactly — so the user base cannot be enumerated or probed for a username.' },
  { icon: Fingerprint,   title: 'Tamper-evident history', body: 'Every message folds into a rolling SHA-256 chain — previous hash, text, timestamp and direction — so a conversation carries a fingerprint that shifts if any earlier message is altered.' },
  { icon: ShieldCheck,   title: 'Hardened by default', body: 'Both the REST API and the socket layer authenticate independently, with rate limiting and strict input validation.' },
];

const SPEC = [
  ['Key encapsulation', 'ML-KEM-768 (NIST FIPS 203)'],
  ['Public key', '1184 bytes'],
  ['Secret key', '2400 bytes · never leaves the device'],
  ['KEM ciphertext', '1088 bytes'],
  ['Shared secret', '32 bytes'],
  ['Key derivation', 'HKDF-SHA256 · random salt + context string'],
  ['Content cipher', 'AES-256-GCM · 12-byte nonce · 16-byte tag'],
  ['Integrity', 'SHA-256 rolling hash chain'],
  ['Messaging transport', 'Socket.io · JWT-authenticated handshake'],
  ['Call media', 'WebRTC · DTLS-SRTP, signalling post-quantum encrypted'],
];

const SERVER_BLIND = ['Message text', 'Photos, files and voice notes', 'Attachment filenames', 'Emoji reactions', 'Call signalling', 'Your private key'];
const SERVER_SEES  = ['Who messages whom', 'When messages are sent', 'Whether a message is text or media', 'Delivery and read state', 'Online and last-seen status'];

const NAV_LINKS = [
  { id: 'how-it-works', label: 'How it works' },
  { id: 'spec',         label: 'Specification' },
  { id: 'server',       label: 'What the server sees' },
];

const jumpTo = (id) =>
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });

export default function Landing() {
  const navigate = useNavigate();
  // Held in state, not read inline, so signing out re-renders immediately.
  // Read once at mount. The landing page never mutates the session — signing
  // out belongs inside the app, next to the identity it actually signs out.
  const signedIn = useState(() => !!localStorage.getItem('qchat_token'))[0];
  const { scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 120, damping: 28, restDelta: 0.001 });

  const primaryCta = signedIn
    ? { label: 'Open QChat', action: () => navigate('/chat') }
    : { label: 'Create identity', action: () => navigate('/register') };

  // Account switching lives in the nav (Sign out), so the hero's secondary
  // button is free to do the landing page's real job: explain the thing.
  // Signed out, a route to sign-in is always offered here — hiding it whenever
  // a token existed stranded anyone whose stored session had gone stale.
  const secondaryCta = signedIn
    ? {
        label: 'How it works',
        icon: <ChevronDown size={15} />,
        action: () => jumpTo('how-it-works'),
      }
    : { label: 'Sign in', icon: <Lock size={15} />, action: () => navigate('/login') };

  return (
    <div className="relative min-h-[100dvh] bg-navy-950 overflow-x-hidden">
      <motion.div className="scroll-rail" style={{ scaleX: progress }} />

      {/* The lattice is the whole point of ML-KEM, so it is the backdrop. */}
      <LatticeField className="fixed inset-0 w-full h-full z-0 pointer-events-none opacity-70" />

      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        <div className="orb w-[560px] h-[560px] bg-blue-900/25 -top-48 -left-32" />
        <div className="orb w-[460px] h-[460px] bg-violet-900/20 top-[45%] -right-28" style={{ animationDelay: '-7s' }} />
        <div className="orb w-[380px] h-[380px] bg-cyan-900/15 bottom-0 left-1/3" style={{ animationDelay: '-13s' }} />
      </div>

      {/* ── Nav ── */}
      <header className="sticky top-0 z-40 backdrop-blur-xl bg-navy-950/70 border-b border-white/[0.06]">
        <nav className="relative max-w-6xl mx-auto px-5 sm:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Logo size={32} />
            <span className="font-extrabold text-sm tracking-tight">QChat</span>
          </div>
          {/* Section links carry the page; the nav is not an account menu. */}
          <div className="hidden md:flex items-center gap-1 absolute left-1/2 -translate-x-1/2">
            {NAV_LINKS.map(({ id, label }) => (
              <button
                key={id}
                onClick={() => jumpTo(id)}
                className="px-3 py-2 text-[13px] font-medium text-slate-400 hover:text-white rounded-lg hover:bg-white/[0.06] transition-colors"
              >
                {label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            {!signedIn && (
              <button onClick={() => navigate('/login')} className="btn-ghost !px-4">Sign in</button>
            )}
            <button onClick={primaryCta.action} className="btn-primary !px-4">
              {primaryCta.label}
            </button>
          </div>
        </nav>
      </header>

      <main className="relative z-10">
        {/* ── Hero ── */}
        <section className="max-w-6xl mx-auto px-5 sm:px-8 pt-20 sm:pt-28 pb-20 text-center">
          <Reveal>
            <span className="badge-pq !tracking-[0.2em] !text-[10px] mb-7 inline-flex items-center gap-2">
              <Zap size={10} />
              <ScrambleText text="NIST FIPS 203 · ML-KEM-768" speed={26} />
            </span>
          </Reveal>

          <Reveal delay={0.05}>
            <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight leading-[1.05] mb-6">
              Encrypted for a threat<br className="hidden sm:block" />{' '}
              <span className="text-gradient">that hasn&apos;t arrived yet.</span>
            </h1>
          </Reveal>

          <Reveal delay={0.1}>
            <p className="text-base sm:text-lg text-sub leading-relaxed max-w-2xl mx-auto mb-9">
              An attacker can record your encrypted traffic today and wait for a quantum
              computer to open it later. QChat closes that window by encrypting every
              message with lattice-based cryptography that stays hard either way.
            </p>
          </Reveal>

          <Reveal delay={0.15}>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-center gap-3">
              <button onClick={primaryCta.action} className="btn-primary h-12 px-7 text-base group">
                {primaryCta.label}
                <ArrowRight size={17} className="transition-transform group-hover:translate-x-0.5" />
              </button>
              <button onClick={secondaryCta.action} className="btn-ghost h-12 px-7 !text-base justify-center">
                {secondaryCta.icon} {secondaryCta.label}
              </button>
            </div>
          </Reveal>

          <Reveal delay={0.2}>
            <p className="mt-7 text-[11px] text-slate-600">
              Your private key is generated on this device and never leaves it.
            </p>
          </Reveal>
        </section>

        {/* ── The problem ── */}
        <section className="max-w-4xl mx-auto px-5 sm:px-8 py-16">
          <Reveal>
            <SpotCard className="p-8 sm:p-10">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-cyan-400 mb-4">
                Harvest now, decrypt later
              </p>
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-5 leading-snug">
                The encryption protecting most messages today has a shelf life.
              </h2>
              <p className="text-sub leading-relaxed mb-4">
                RSA and elliptic-curve cryptography rest on problems — factoring large
                numbers, discrete logarithms — that a sufficiently capable quantum
                computer solves efficiently. Anything recorded now can be decrypted the
                day such a machine exists.
              </p>
              <p className="text-sub leading-relaxed">
                For a conversation that must stay private for a decade, the relevant
                question isn&apos;t whether that machine exists today. It&apos;s whether
                your traffic is being stored until it does.
              </p>
            </SpotCard>
          </Reveal>
        </section>

        {/* ── Pipeline ── */}
        <section id="how-it-works" className="max-w-6xl mx-auto px-5 sm:px-8 py-16 scroll-mt-24">
          <Reveal className="text-center mb-12">
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">How a message is sealed</h2>
            <p className="text-sub max-w-xl mx-auto leading-relaxed">
              A hybrid construction: lattice cryptography moves the key, and a fast
              symmetric cipher moves the data.
            </p>
          </Reveal>

          <div className="grid gap-5 md:grid-cols-3">
            {PIPELINE.map(({ icon: Icon, step, title, body }, i) => (
              <Reveal key={step} delay={i * 0.08}>
                <SpotCard className="p-6 h-full">
                  <div className="flex items-center justify-between mb-5">
                    <div className="w-10 h-10 rounded-xl bg-cyan-400/10 border border-cyan-400/20 flex items-center justify-center float-soft" style={{ animationDelay: `${i * 0.6}s` }}>
                      <Icon size={18} className="text-cyan-400" />
                    </div>
                    <span className="font-mono text-xs text-slate-600">{step}</span>
                  </div>
                  <h3 className="font-bold mb-2.5 leading-snug">{title}</h3>
                  <p className="text-sm text-sub leading-relaxed">{body}</p>
                </SpotCard>
              </Reveal>
            ))}
          </div>
        </section>

        {/* ── Specification ── */}
        <section id="spec" className="max-w-4xl mx-auto px-5 sm:px-8 py-16 scroll-mt-24">
          <Reveal className="text-center mb-10">
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">Specification</h2>
            <p className="text-sub max-w-xl mx-auto leading-relaxed">
              No hand-waving — these are the exact primitives and parameters in use.
            </p>
          </Reveal>

          <Reveal>
            <SpotCard className="p-2 sm:p-3">
              <dl className="divide-y divide-white/[0.05]">
                {SPEC.map(([label, value]) => (
                  <div key={label} className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4 px-4 sm:px-5 py-3.5">
                    <dt className="text-[10px] uppercase tracking-widest text-slate-500 sm:w-52 flex-shrink-0">{label}</dt>
                    <dd className="font-mono text-[13px] text-slate-200">{value}</dd>
                  </div>
                ))}
              </dl>
            </SpotCard>
          </Reveal>

          <Reveal delay={0.08}>
            <p className="text-center text-xs text-slate-600 mt-6 leading-relaxed max-w-2xl mx-auto">
              Encrypting the body once and wrapping only the content key — rather than
              encrypting the whole message separately for each participant — cuts stored
              ciphertext by roughly half on a typical attachment.
            </p>
          </Reveal>
        </section>

        {/* ── Features ── */}
        <section className="max-w-6xl mx-auto px-5 sm:px-8 py-16">
          <Reveal className="text-center mb-12">
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">A full messenger, not a demo</h2>
            <p className="text-sub max-w-xl mx-auto leading-relaxed">
              Everything you expect from a modern chat app, with the cryptography
              carried all the way through.
            </p>
          </Reveal>

          <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map(({ icon: Icon, title, body }, i) => (
              <Reveal key={title} delay={(i % 3) * 0.07}>
                <SpotCard className="p-6 h-full">
                  <Icon size={19} className="text-cyan-400 mb-4" />
                  <h3 className="font-semibold text-[15px] mb-2">{title}</h3>
                  <p className="text-sm text-sub leading-relaxed">{body}</p>
                </SpotCard>
              </Reveal>
            ))}
          </div>
        </section>

        {/* ── What the server can and cannot see ── */}
        <section id="server" className="max-w-5xl mx-auto px-5 sm:px-8 py-16 scroll-mt-24">
          <Reveal className="text-center mb-12">
            <div className="inline-flex items-center justify-center w-11 h-11 rounded-xl bg-white/5 mb-5">
              <Server size={19} className="text-slate-400" />
            </div>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">What the server actually knows</h2>
            <p className="text-sub max-w-xl mx-auto leading-relaxed">
              End-to-end encryption protects content, not the fact that you spoke.
              Here is the honest split.
            </p>
          </Reveal>

          <div className="grid gap-5 md:grid-cols-2">
            <Reveal>
              <SpotCard className="p-7 h-full !border-emerald-500/20">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-emerald-400 mb-5">
                  Never leaves your device readable
                </p>
                <ul className="space-y-3">
                  {SERVER_BLIND.map(item => (
                    <li key={item} className="flex items-start gap-2.5 text-sm text-slate-300">
                      <Check size={15} className="text-emerald-400 mt-0.5 flex-shrink-0" />
                      {item}
                    </li>
                  ))}
                </ul>
              </SpotCard>
            </Reveal>

            <Reveal delay={0.08}>
              <SpotCard className="p-7 h-full !border-amber-500/20">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-amber-400 mb-5">
                  Visible as metadata
                </p>
                <ul className="space-y-3">
                  {SERVER_SEES.map(item => (
                    <li key={item} className="flex items-start gap-2.5 text-sm text-slate-300">
                      <X size={15} className="text-amber-400 mt-0.5 flex-shrink-0" />
                      {item}
                    </li>
                  ))}
                </ul>
              </SpotCard>
            </Reveal>
          </div>
        </section>

        {/* ── Closing CTA ── */}
        <section className="max-w-4xl mx-auto px-5 sm:px-8 py-20">
          <Reveal>
            <SpotCard className="p-10 sm:p-14 text-center">
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-4">
                Start a <span className="text-gradient">conversation worth protecting.</span>
              </h2>
              <p className="text-sub leading-relaxed mb-8 max-w-md mx-auto">
                Creating an identity takes a few seconds and generates your keypair
                locally. No email, no phone number.
              </p>
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-center gap-3">
                <button onClick={primaryCta.action} className="btn-primary h-12 px-8 text-base">
                  {primaryCta.label} <ArrowRight size={17} />
                </button>
                <button onClick={secondaryCta.action} className="btn-ghost h-12 px-7 !text-base justify-center">
                  {secondaryCta.icon} {secondaryCta.label}
                </button>
              </div>
            </SpotCard>
          </Reveal>
        </section>
      </main>

      <footer className="relative z-10 border-t border-white/[0.06]">
        <div className="max-w-6xl mx-auto px-5 sm:px-8 py-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-slate-600">
            <Logo size={18} withGlow={false} />
            <span className="text-xs">QChat · ML-KEM-768 + AES-256-GCM</span>
          </div>
          <p className="text-[11px] text-slate-600">
            Built as a final-year engineering project.
          </p>
        </div>
      </footer>
    </div>
  );
}
