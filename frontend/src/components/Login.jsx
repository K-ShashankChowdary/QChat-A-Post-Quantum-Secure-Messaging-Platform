import React, { useState } from 'react';
import api from '../lib/api';
import { useNavigate } from 'react-router-dom';
import { generateKeyPair, b64encode } from '../crypto/encryption';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, Loader2, Lock, AlertTriangle } from 'lucide-react';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    try {
      const { data } = await api.post('/api/auth/login', { username, password });
      localStorage.setItem('qchat_token', data.token);
      localStorage.setItem('qchat_user', JSON.stringify(data.user));

      // Use persistent local storage for keys so they survive tab closures and account switching
      const privKeyName = `qchat_priv_${data.user.id}`;
      const pubKeyName  = `qchat_pub_${data.user.id}`;
      const existingPriv = localStorage.getItem(privKeyName);
      const existingPub  = localStorage.getItem(pubKeyName);

      if (!existingPriv || !existingPub) {
        // First time login on this device — generate a fresh keypair
        const kp = await generateKeyPair();
        const pubB64 = b64encode(kp.publicKey);
        localStorage.setItem(privKeyName, b64encode(kp.privateKey));
        localStorage.setItem(pubKeyName, pubB64);
        sessionStorage.removeItem('qchat_last_peer'); // clear last peer for fresh setup
        
        await api.post('/api/auth/update-key', { userId: data.user.id, publicKey: pubB64 });
        localStorage.setItem('qchat_user', JSON.stringify({ ...data.user, publicKey: pubB64 }));
      } else {
        // We already have a persistent key on this device! 
        // Force the backend to use THIS device's public key (in case they logged in elsewhere recently)
        if (data.user.publicKey !== existingPub) {
          await api.post('/api/auth/update-key', { userId: data.user.id, publicKey: existingPub });
        }
        localStorage.setItem('qchat_user', JSON.stringify({ ...data.user, publicKey: existingPub }));
      }

      navigate('/chat');
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen flex items-center justify-center p-6 overflow-hidden bg-navy-950">
      <div className="bg-grid" />
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
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-cyan-400 to-blue-500 flex items-center justify-center shadow-glow-cyan-sm flex-shrink-0">
              <ShieldAlert size={20} className="text-navy-950" />
            </div>
            <div>
              <p className="font-extrabold text-lg tracking-tight leading-none">QChat</p>
              <p className="text-[10px] text-slate-500 uppercase tracking-widest">Post-Quantum Secure</p>
            </div>
          </div>

          <h1 className="text-2xl font-extrabold tracking-tight mb-1">Welcome back</h1>
          <p className="text-sm text-sub mb-8">Sign in to resume your encrypted session.</p>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-widest text-muted mb-1.5">Username</label>
              <input className="field-input" type="text" placeholder="Your username" value={username}
                onChange={e => setUsername(e.target.value)} required disabled={isLoading} autoComplete="username" />
            </div>
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-widest text-muted mb-1.5">Passphrase</label>
              <input className="field-input" type="password" placeholder="Your password" value={password}
                onChange={e => setPassword(e.target.value)} required disabled={isLoading} autoComplete="current-password" />
            </div>

            <AnimatePresence>
              {error && (
                <motion.p initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                  className="text-rose-400 text-xs">⚠ {error}</motion.p>
              )}
            </AnimatePresence>

            <button type="submit" className="btn-primary w-full h-11" disabled={isLoading}>
              {isLoading
                ? <><Loader2 size={15} className="animate-spin" />Authenticating...</>
                : <><Lock size={15} />Enter Secure Session</>
              }
            </button>
          </form>

          <p className="mt-6 text-xs text-center text-muted">
            New to QChat?{' '}
            <button onClick={() => navigate('/register')} className="text-cyan-400 font-semibold hover:underline">Create an identity</button>
          </p>
        </div>
      </motion.div>
    </div>
  );
}
