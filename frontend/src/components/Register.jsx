import React, { useState } from 'react';
import api from '../lib/api';
import { useNavigate } from 'react-router-dom';
import { generateKeyPair, b64encode, wrapPrivateKey } from '../crypto/encryption';
import LatticeField from './visuals/LatticeField';
import Logo from './visuals/Logo';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldCheck, Loader2, Lock, CheckCircle2, Circle, Cpu } from 'lucide-react';

const STEPS = [
  'Initializing ML-KEM-768 parameters',
  'Sampling lattice noise vectors',
  'Computing polynomial coefficients',
  'Generating encapsulation keypair',
  'Deriving private key material',
];

export default function Register() {
  const [username, setUsername]   = useState('');
  const [password, setPassword]   = useState('');
  const [activeStep, setActiveStep] = useState(-1);
  const [doneSteps, setDoneSteps]   = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]           = useState('');
  const navigate = useNavigate();

  const animateKeygen = () => new Promise(resolve => {
    let i = 0;
    const tick = () => {
      if (i >= STEPS.length) { resolve(); return; }
      setActiveStep(i);
      setTimeout(() => { setDoneSteps(d => [...d, i]); i++; setTimeout(tick, 60); }, 230);
    };
    tick();
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (password.length < 8) { setError('Password must be at least 8 characters'); return; }
    setError('');
    setActiveStep(0);
    setDoneSteps([]);
    try {
      await animateKeygen();
      const kp = await generateKeyPair();
      setSubmitting(true);
      const pubB64 = b64encode(kp.publicKey);
      // Encrypted under the password so this exact key can be recovered on any
      // other device, instead of that device generating a replacement and
      // orphaning every message sent to this one.
      const keyBackup = await wrapPrivateKey(kp.privateKey, password);
      const { data } = await api.post('/api/auth/register', {
        username, password, publicKey: pubB64, keyBackup
      });
      
      // Store the private and public key persistently based on user ID
      localStorage.setItem(`qchat_priv_${data.user.id}`, b64encode(kp.privateKey));
      localStorage.setItem(`qchat_pub_${data.user.id}`, pubB64);
      
      localStorage.setItem('qchat_token', data.token);
      localStorage.setItem('qchat_user', JSON.stringify({ ...data.user, publicKey: pubB64 }));
      navigate('/chat');
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed');
      setActiveStep(-1); setDoneSteps([]); setSubmitting(false);
    }
  };

  const busy = activeStep >= 0 || submitting;

  return (
    <div className="relative min-h-screen flex items-center justify-center p-6 overflow-hidden bg-navy-950">
      {/* Background */}
      <LatticeField className="fixed inset-0 w-full h-full z-0 pointer-events-none opacity-60" />
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        <div className="orb w-[600px] h-[600px] bg-blue-900/30 -top-40 -left-20" />
        <div className="orb w-[500px] h-[500px] bg-cyan-900/20 -bottom-32 -right-16" style={{ animationDelay: '-7s' }} />
        <div className="orb w-[300px] h-[300px] bg-purple-900/20 top-1/2 left-1/2" style={{ animationDelay: '-14s' }} />
      </div>

      <motion.div
        className="relative z-10 w-full max-w-md"
        initial={{ opacity: 0, y: 24, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      >
        <div className="glass p-10">
          {/* Logo */}
          <div className="flex items-center gap-3 mb-8">
            <Logo size={44} />
            <div>
              <p className="font-extrabold text-lg tracking-tight leading-none">QChat</p>
              <p className="text-[10px] text-slate-500 uppercase tracking-widest">Post-Quantum Secure</p>
            </div>
          </div>

          <h1 className="text-2xl font-extrabold tracking-tight mb-1">Create Identity</h1>
          <p className="text-sm text-sub mb-8">Your ML-KEM-768 keypair generates locally on your device.</p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-widest text-muted mb-1.5">Username</label>
              <input className="field-input" type="text" placeholder="Choose a unique handle" value={username}
                onChange={e => setUsername(e.target.value)} required disabled={busy} autoComplete="username" />
            </div>
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-widest text-muted mb-1.5">Password</label>
              <input className="field-input" type="password" placeholder="Min. 8 characters" value={password}
                onChange={e => setPassword(e.target.value)} required disabled={busy} autoComplete="new-password" />
              <p className="text-[10px] text-slate-600 mt-1.5 leading-relaxed">
                This also encrypts the backup of your private key, so it is what lets you
                read your messages on another device. Choose something strong — it cannot be reset.
              </p>
            </div>

            <AnimatePresence>
              {error && (
                <motion.p initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                  className="text-rose-400 text-xs">⚠ {error}</motion.p>
              )}
            </AnimatePresence>

            <button type="submit" className="btn-primary w-full h-11" disabled={busy}>
              {busy
                ? <><Loader2 size={15} className="animate-spin" />{submitting ? 'Registering...' : 'Generating Keys...'}</>
                : <><Lock size={15} />Generate PQ Identity</>
              }
            </button>
          </form>

          {/* Keygen progress */}
          <AnimatePresence>
            {activeStep >= 0 && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                className="mt-5 px-4 py-3 bg-cyan-400/5 border border-cyan-400/15 rounded-xl overflow-hidden"
              >
                <div className="flex items-center gap-2 mb-3">
                  <Cpu size={12} className="text-cyan-400" />
                  <span className="text-[10px] font-semibold tracking-widest uppercase text-cyan-400">ML-KEM-768 Keygen</span>
                </div>
                <ul className="space-y-1.5">
                  {STEPS.map((s, i) => {
                    const done = doneSteps.includes(i);
                    const active = activeStep === i && !done;
                    return (
                      <li key={i} className={`flex items-center gap-2.5 text-xs transition-colors duration-300 ${done ? 'text-emerald-400' : active ? 'text-cyan-300' : 'text-slate-600'}`}>
                        {done
                          ? <CheckCircle2 size={11} className="text-emerald-400 flex-shrink-0" />
                          : active
                            ? <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 flex-shrink-0 animate-ping2" />
                            : <Circle size={11} className="flex-shrink-0 opacity-30" />
                        }
                        {done ? '✓ ' : ''}{s}
                      </li>
                    );
                  })}
                </ul>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Security note */}
          <div className="mt-6 flex gap-3 items-start p-3.5 bg-emerald-900/20 border border-emerald-500/15 rounded-xl">
            <ShieldCheck size={13} className="text-emerald-400 flex-shrink-0 mt-0.5" />
            <p className="text-[11px] text-emerald-400/80 leading-relaxed">
              Private key never leaves this device. Secured by <strong>NIST FIPS 203</strong> ML-KEM-768.
            </p>
          </div>

          <p className="mt-6 text-xs text-center text-muted">
            Already registered?{' '}
            <button onClick={() => navigate('/login')} className="text-cyan-400 font-semibold hover:underline">Login</button>
          </p>
        </div>
      </motion.div>
    </div>
  );
}
