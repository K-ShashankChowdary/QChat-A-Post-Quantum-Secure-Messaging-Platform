import React, { createContext, useCallback, useContext, useMemo, useState, useEffect, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { CheckCircle2, AlertTriangle, Info, X, AlertOctagon } from 'lucide-react';

const ToastContext = createContext(null);

/** useToast() -> { success, error, info, confirm } */
export const useToast = () => {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>');
  return ctx;
};

const TONES = {
  success: { Icon: CheckCircle2,  ring: 'border-emerald-500/30', accent: 'text-emerald-400' },
  error:   { Icon: AlertTriangle, ring: 'border-rose-500/30',    accent: 'text-rose-400' },
  info:    { Icon: Info,          ring: 'border-cyan-400/25',    accent: 'text-cyan-400' },
};

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const [dialog, setDialog] = useState(null);
  const timers = useRef(new Map());

  const dismiss = useCallback((id) => {
    setToasts(list => list.filter(t => t.id !== id));
    const timer = timers.current.get(id);
    if (timer) { clearTimeout(timer); timers.current.delete(id); }
  }, []);

  const push = useCallback((message, tone, ttl) => {
    const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    setToasts(list => [...list.slice(-3), { id, message, tone }]);
    timers.current.set(id, setTimeout(() => dismiss(id), ttl));
    return id;
  }, [dismiss]);

  useEffect(() => () => { timers.current.forEach(clearTimeout); timers.current.clear(); }, []);

  const value = useMemo(() => ({
    success: (m) => push(m, 'success', 3500),
    error:   (m) => push(m, 'error', 6000),
    info:    (m) => push(m, 'info', 4000),
    /** Promise-based replacement for window.confirm. */
    confirm: (opts) => new Promise(resolve => {
      setDialog({
        title: 'Are you sure?',
        body: '',
        confirmLabel: 'Confirm',
        cancelLabel: 'Cancel',
        destructive: false,
        ...opts,
        resolve,
      });
    }),
  }), [push]);

  const settle = useCallback((answer) => {
    setDialog(d => { d?.resolve(answer); return null; });
  }, []);

  useEffect(() => {
    if (!dialog) return;
    const onKey = (e) => {
      if (e.key === 'Escape') settle(false);
      if (e.key === 'Enter') settle(true);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [dialog, settle]);

  return (
    <ToastContext.Provider value={value}>
      {children}

      {/* ── Toasts ── */}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col items-end gap-2 pointer-events-none max-w-[calc(100vw-2rem)]">
        <AnimatePresence initial={false}>
          {toasts.map(({ id, message, tone }) => {
            const { Icon, ring, accent } = TONES[tone] || TONES.info;
            return (
              <motion.div
                key={id}
                layout
                initial={{ opacity: 0, y: 16, scale: 0.96 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, x: 24, scale: 0.96 }}
                transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
                className={`glass-sm pointer-events-auto flex items-start gap-2.5 pl-3.5 pr-2 py-2.5 border ${ring} shadow-xl max-w-sm`}
                role="status"
              >
                <Icon size={15} className={`${accent} mt-0.5 flex-shrink-0`} />
                <p className="text-[13px] text-slate-200 leading-snug flex-1">{message}</p>
                <button
                  onClick={() => dismiss(id)}
                  className="p-1 rounded-md text-slate-500 hover:text-white hover:bg-white/10 transition-colors flex-shrink-0"
                  aria-label="Dismiss"
                >
                  <X size={12} />
                </button>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>

      {/* ── Confirm dialog ── */}
      <AnimatePresence>
        {dialog && (
          <motion.div
            className="fixed inset-0 z-[110] flex items-center justify-center p-5"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          >
            <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={() => settle(false)} />
            <motion.div
              role="dialog" aria-modal="true"
              initial={{ scale: 0.95, y: 12 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.97, y: 8 }}
              transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
              className="glass relative w-full max-w-sm p-6"
            >
              <div className="flex items-start gap-3 mb-5">
                <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${dialog.destructive ? 'bg-rose-500/15' : 'bg-cyan-400/10'}`}>
                  <AlertOctagon size={17} className={dialog.destructive ? 'text-rose-400' : 'text-cyan-400'} />
                </div>
                <div className="min-w-0">
                  <h2 className="font-bold text-[15px] leading-snug">{dialog.title}</h2>
                  {dialog.body && <p className="text-sm text-sub leading-relaxed mt-1.5">{dialog.body}</p>}
                </div>
              </div>

              <div className="flex items-center justify-end gap-2">
                <button onClick={() => settle(false)} className="btn-ghost !px-4 h-9">
                  {dialog.cancelLabel}
                </button>
                <button
                  autoFocus
                  onClick={() => settle(true)}
                  className={`h-9 px-4 rounded-lg text-sm font-semibold transition-colors ${dialog.destructive
                    ? 'bg-rose-500/90 hover:bg-rose-500 text-white'
                    : 'bg-cyan-400 hover:bg-cyan-300 text-navy-950'}`}
                >
                  {dialog.confirmLabel}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </ToastContext.Provider>
  );
}
