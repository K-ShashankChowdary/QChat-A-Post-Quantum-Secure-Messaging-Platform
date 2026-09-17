import React, { useState } from 'react';
import api from '../lib/api';
import { useNavigate } from 'react-router-dom';
import {
  generateKeyPair, b64encode, b64decode,
  wrapPrivateKey, unwrapPrivateKey, publicKeyFromSecretKey,
} from '../crypto/encryption';
import { useToast } from './visuals/Toast';
import LatticeField from './visuals/LatticeField';
import Logo from './visuals/Logo';
import { motion, AnimatePresence } from 'framer-motion';
import { Loader2, Lock } from 'lucide-react';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [stage, setStage] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const toast = useToast();

  const handleLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    try {
      const { data } = await api.post('/api/auth/login', { username, password });
      localStorage.setItem('qchat_token', data.token);
      localStorage.setItem('qchat_user', JSON.stringify(data.user));

      const privKeyName = `qchat_priv_${data.user.id}`;
      const pubKeyName  = `qchat_pub_${data.user.id}`;
      const existingPriv = localStorage.getItem(privKeyName);
      const existingPub  = localStorage.getItem(pubKeyName);

      let publicKeyB64;

      if (data.keyBackup) {
        // The account has an encrypted backup, so that key IS the account key —
        // recover it rather than minting a replacement. This is what makes the
        // keypair per-user instead of per-browser.
        setStage('Recovering your key…');
        const restored = await unwrapPrivateKey(data.keyBackup, password);
        publicKeyB64 = b64encode(publicKeyFromSecretKey(restored));

        localStorage.setItem(privKeyName, b64encode(restored));
        localStorage.setItem(pubKeyName, publicKeyB64);

        if (data.user.publicKey !== publicKeyB64) {
          await api.post('/api/auth/update-key', { userId: data.user.id, publicKey: publicKeyB64 });
        }
      } else if (existingPriv && existingPub) {
        // Account predates backups but this device still holds the real key —
        // upload a backup now so no future sign-in has to regenerate.
        publicKeyB64 = existingPub;
        setStage('Backing up your key…');
        try {
          const keyBackup = await wrapPrivateKey(b64decode(existingPriv), password);
          await api.post('/api/auth/key-backup', { keyBackup });
        } catch {
          toast.info('Signed in, but your key could not be backed up this time.');
        }
        if (data.user.publicKey !== existingPub) {
          await api.post('/api/auth/update-key', { userId: data.user.id, publicKey: existingPub });
        }
      } else {
        // No backup and no local key. Generating one is destructive: everything
        // sealed to the old key becomes permanently unreadable. Say so first.
        const proceed = await toast.confirm({
          title: 'Create a new key for this device?',
          body: 'This account has no key backup and this browser has no stored key. '
              + 'Continuing generates a new keypair — any earlier messages will become '
              + 'permanently unreadable. If you have another device with the key, sign in there instead.',
          confirmLabel: 'Create new key',
          destructive: true,
        });

        if (!proceed) {
          localStorage.removeItem('qchat_token');
          localStorage.removeItem('qchat_user');
          setError('Sign-in cancelled — no new key was created.');
          return;
        }

        setStage('Generating your key…');
        const kp = await generateKeyPair();
        publicKeyB64 = b64encode(kp.publicKey);
        localStorage.setItem(privKeyName, b64encode(kp.privateKey));
        localStorage.setItem(pubKeyName, publicKeyB64);
        sessionStorage.removeItem('qchat_last_peer');

        await api.post('/api/auth/update-key', { userId: data.user.id, publicKey: publicKeyB64 });
        try {
          const keyBackup = await wrapPrivateKey(kp.privateKey, password);
          await api.post('/api/auth/key-backup', { keyBackup });
        } catch { /* non-fatal; the next sign-in will retry */ }
      }

      localStorage.setItem('qchat_user', JSON.stringify({ ...data.user, publicKey: publicKeyB64 }));
      navigate('/chat');
    } catch (err) {
      if (err.message === 'WRONG_PASSWORD') {
        // Login succeeded, so the password is right — the blob itself is bad.
        setError('Your key backup could not be opened. It may be corrupted; contact support or sign in on a device that still holds your key.');
      } else {
        setError(err.response?.data?.error || 'Login failed. Please try again.');
      }
    } finally {
      setIsLoading(false);
      setStage('');
    }
  };

  return (
    <div className="relative min-h-screen flex items-center justify-center p-6 overflow-hidden bg-navy-950">
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

          <h1 className="text-2xl font-extrabold tracking-tight mb-1">Welcome back</h1>
          <p className="text-sm text-sub mb-8">Sign in to resume your encrypted session.</p>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-widest text-muted mb-1.5">Username</label>
              <input className="field-input" type="text" placeholder="Your username" value={username}
                onChange={e => setUsername(e.target.value)} required disabled={isLoading} autoComplete="username" />
            </div>
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-widest text-muted mb-1.5">Password</label>
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
                ? <><Loader2 size={15} className="animate-spin" />{stage || 'Authenticating…'}</>
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
