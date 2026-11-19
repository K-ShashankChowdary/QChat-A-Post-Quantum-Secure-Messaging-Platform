import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck, ShieldAlert, ShieldQuestion, Loader2, X, GitCompare, CheckCircle2,
  XCircle, ArrowUp, CornerDownRight,
} from 'lucide-react';

/* ─── Presentation for the transcript Merkle tree ───
   The badge in the chat header, the integrity panel it opens, and the proof
   dialog for one message. All state lives in useTranscriptTree. */

const group = (hex = '', size = 4) => (hex.match(new RegExp(`.{1,${size}}`, 'g')) || []).join(' ').toUpperCase();
const short = (hex = '') => `${hex.slice(0, 8)}…${hex.slice(-6)}`.toUpperCase();
const when = (ts) => (ts ? new Date(ts).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '');

export const STATUS = {
  checking:    { label: 'Verifying',       tone: 'slate',   Icon: Loader2 },
  first:       { label: 'Tree verified',   tone: 'emerald', Icon: ShieldCheck },
  ok:          { label: 'Tree verified',   tone: 'emerald', Icon: ShieldCheck },
  benign:      { label: 'Tree verified',   tone: 'emerald', Icon: ShieldCheck },
  tampered:    { label: 'History changed', tone: 'rose',    Icon: ShieldAlert },
  unavailable: { label: 'Unverified',      tone: 'slate',   Icon: ShieldQuestion },
};

const TONE = {
  emerald: 'text-emerald-300 bg-emerald-400/[0.08] border-emerald-400/25 hover:bg-emerald-400/[0.14]',
  rose:    'text-rose-300 bg-rose-500/[0.12] border-rose-400/40 hover:bg-rose-500/[0.18] animate-pulse',
  slate:   'text-slate-400 bg-white/[0.03] border-white/10 hover:bg-white/[0.06]',
};

const FINDING = {
  modified: { text: 'was changed after this device verified it', serious: true },
  removed:  { text: 'has disappeared from the history', serious: true },
  inserted: { text: 'appeared inside already-verified history (back-dated)', serious: true },
  served:   { text: "doesn't match the server's own Merkle leaf for it", serious: true },
  deleted:  { text: 'was deleted by its sender', serious: false },
};

/** Header chip: status plus the first 8 hex chars of the root. */
export function TranscriptBadge({ status, root, size, onClick }) {
  if (!status) return null;
  // An empty conversation has nothing to verify — unless it became empty,
  // which is exactly what a tampered (or cleared) history looks like.
  if (size === 0 && status !== 'tampered' && status !== 'checking') return null;
  const { label, tone, Icon } = STATUS[status] || STATUS.checking;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={`${label}. Merkle root over ${size} message${size === 1 ? '' : 's'}. Open transcript integrity.`}
      title={`Merkle root over ${size} message${size === 1 ? '' : 's'} — click for details`}
      className={`inline-flex items-center gap-1.5 text-[10px] font-semibold tracking-wide border px-2 sm:px-2.5 py-1 rounded-full mr-1 transition-colors ${TONE[tone]}`}
    >
      <Icon size={11} className={status === 'checking' ? 'animate-spin' : ''} />
      <span className="hidden sm:inline">{label}</span>
      {root && <span className="hidden lg:inline font-mono tracking-[0.08em] opacity-80">{group(root.slice(0, 8))}</span>}
    </button>
  );
}

function Modal({ open, onClose, children, label }) {
  React.useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => { if (e.key === 'Escape') onClose?.(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-[90] flex items-center justify-center p-4"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        >
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
          <motion.div
            role="dialog" aria-modal="true" aria-label={label}
            initial={{ scale: 0.96, y: 12 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.97, y: 8 }}
            transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
            className="glass relative w-full max-w-lg max-h-[85vh] overflow-y-auto p-5 sm:p-6"
          >
            <button
              type="button" onClick={onClose} aria-label="Close"
              className="absolute top-3 right-3 p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-white/10"
            ><X size={14} /></button>
            {children}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

/** Whole-conversation view: root, verdict, findings, compare with the peer. */
export function TranscriptPanel({
  open, onClose, tree, peerName, onCompare, compare, onAccept, onJump,
}) {
  const { status, root, size, findings, appended, checkpointAt } = tree;
  const meta = STATUS[status] || STATUS.checking;
  const serious = findings.filter(f => FINDING[f.kind]?.serious);
  const benign = findings.filter(f => !FINDING[f.kind]?.serious);

  const summary = {
    checking: 'Rebuilding the tree from every message in this conversation…',
    first: 'First verification on this device. The tree has been checkpointed; from now on any change to these messages will be detected and named.',
    ok: `Every message verified since ${checkpointAt ? when(checkpointAt) : 'the last visit'} is unchanged${appended ? `, and ${appended} new message${appended === 1 ? ' was' : 's were'} appended` : ''}.`,
    benign: 'Nothing was altered. The only changes since the last visit are deletions by the sender.',
    tampered: size === 0 && findings.length > 0 && findings.every(f => f.kind === 'removed')
      ? `Every message this device had verified is gone. Either ${peerName} cleared the chat while you were away, or the server removed them. Accept the empty history only if you know it was cleared.`
      : 'This conversation no longer matches what this device verified before. The messages below were changed, removed or slipped in — by the server or by someone with access to its database.',
    unavailable: 'The server did not return the transcript leaves, so this conversation could not be verified.',
  }[status];

  return (
    <Modal open={open} onClose={onClose} label="Transcript integrity">
      <div className="flex items-start gap-3 mb-4 pr-6">
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${meta.tone === 'rose' ? 'bg-rose-500/15' : 'bg-emerald-400/10'}`}>
          <meta.Icon size={17} className={meta.tone === 'rose' ? 'text-rose-400' : meta.tone === 'slate' ? 'text-slate-400' : 'text-emerald-400'} />
        </div>
        <div>
          <h2 className="font-bold text-[15px]">Transcript integrity</h2>
          <p className="text-[11px] text-slate-500 mt-0.5">SHA-256 Merkle tree · RFC 6962 · {size} message{size === 1 ? '' : 's'}</p>
        </div>
      </div>

      <div className="rounded-xl bg-black/30 border border-white/[0.06] p-3 mb-4">
        <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Merkle root</p>
        <p className="font-mono text-[11px] leading-relaxed text-cyan-200 break-all">{root ? group(root) : '—'}</p>
      </div>

      <p className={`text-sm leading-relaxed mb-4 ${status === 'tampered' ? 'text-rose-200' : 'text-slate-300'}`}>{summary}</p>

      {(serious.length > 0 || benign.length > 0) && (
        <ul className="space-y-1.5 mb-4">
          {[...serious, ...benign].map((f, i) => (
            <li key={`${f.kind}-${f.id}-${i}`}
                className={`flex items-start gap-2 text-xs rounded-lg px-3 py-2 border ${FINDING[f.kind]?.serious
                  ? 'bg-rose-500/[0.08] border-rose-400/20 text-rose-200'
                  : 'bg-white/[0.03] border-white/[0.06] text-slate-400'}`}>
              <CornerDownRight size={12} className="mt-0.5 flex-shrink-0 opacity-70" />
              <span className="flex-1">
                {f.index !== undefined ? `Message #${f.index + 1}` : 'A message'}
                {f.timestamp ? ` (${when(f.timestamp)})` : ''} {FINDING[f.kind]?.text || f.kind}.
              </span>
              {onJump && f.kind !== 'removed' && (
                <button type="button" onClick={() => onJump(f.id)} className="text-[10px] font-semibold text-cyan-300 hover:text-cyan-200 flex-shrink-0">
                  Show
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button" onClick={onCompare} disabled={!root || compare?.state === 'waiting'}
          className="inline-flex items-center gap-1.5 h-9 px-3.5 rounded-lg text-sm font-semibold bg-cyan-400 hover:bg-cyan-300 text-navy-950 disabled:opacity-50"
        >
          {compare?.state === 'waiting' ? <Loader2 size={14} className="animate-spin" /> : <GitCompare size={14} />}
          Compare with {peerName}
        </button>
        {status === 'tampered' && (
          <button type="button" onClick={onAccept} className="btn-ghost !px-3.5 h-9 text-sm">
            Accept current history
          </button>
        )}
      </div>

      {compare && compare.state !== 'waiting' && (
        <div className={`mt-3 flex items-start gap-2 text-xs rounded-lg px-3 py-2 border ${
          compare.state === 'match' ? 'bg-emerald-400/[0.08] border-emerald-400/25 text-emerald-200'
          : compare.state === 'mismatch' ? 'bg-rose-500/[0.08] border-rose-400/25 text-rose-200'
          : 'bg-white/[0.03] border-white/[0.06] text-slate-400'}`}>
          {compare.state === 'match' ? <CheckCircle2 size={13} className="mt-0.5 flex-shrink-0" /> : <XCircle size={13} className="mt-0.5 flex-shrink-0" />}
          <span>
            {compare.state === 'match' && `${peerName}'s device has the identical root over the first ${compare.size} message${compare.size === 1 ? '' : 's'} — you are both looking at the same history.`}
            {compare.state === 'mismatch' && `${peerName}'s device computes a different root over the first ${compare.size} messages. The server has not shown you both the same history.`}
            {compare.state === 'timeout' && `${peerName} didn't answer — they need to be online with QChat open.`}
            {compare.state === 'error' && 'The comparison could not be completed.'}
          </span>
        </div>
      )}

      <p className="text-[11px] text-slate-500 leading-relaxed mt-5 border-t border-white/[0.06] pt-3">
        Each message is a leaf, hashed from its sender, id, time and ciphertext; pairs of hashes
        combine up to one root. Changing anything — even only the timestamp, which encryption alone
        does not protect — changes the root, and the leaf that moved names the message. It proves
        history wasn't rewritten; it does not prove who wrote a message.
      </p>
    </Modal>
  );
}

/** One message's inclusion proof, drawn from leaf to root. */
export function ProofDialog({ open, onClose, proof, missing, preview }) {
  return (
    <Modal open={open} onClose={onClose} label="Inclusion proof">
      {missing ? (
        <p className="text-sm text-slate-400 py-6 text-center">
          This message isn't in the tree yet — it is still being added. Try again in a moment.
        </p>
      ) : !proof ? (
        <div className="flex items-center gap-2 text-sm text-slate-400 py-6 justify-center">
          <Loader2 size={15} className="animate-spin" /> Building proof…
        </div>
      ) : (
        <>
          <div className="flex items-start gap-3 mb-4 pr-6">
            <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${proof.verified ? 'bg-emerald-400/10' : 'bg-rose-500/15'}`}>
              {proof.verified ? <ShieldCheck size={17} className="text-emerald-400" /> : <ShieldAlert size={17} className="text-rose-400" />}
            </div>
            <div className="min-w-0">
              <h2 className="font-bold text-[15px]">Inclusion proof</h2>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Leaf {proof.index + 1} of {proof.size} · {proof.path.length} sibling hash{proof.path.length === 1 ? '' : 'es'} (⌈log₂ {proof.size}⌉ = {Math.ceil(Math.log2(Math.max(proof.size, 1)))})
              </p>
            </div>
          </div>

          {preview && <p className="text-xs text-slate-400 italic truncate mb-3">“{preview}”</p>}

          <ol className="space-y-1.5 font-mono text-[11px]">
            <li className="rounded-lg bg-cyan-400/[0.08] border border-cyan-400/20 px-3 py-2">
              <span className="text-[10px] font-sans uppercase tracking-widest text-cyan-300/80 block mb-0.5">Leaf · SHA-256(0x00 ‖ record)</span>
              <span className="text-cyan-100 break-all">{group(proof.leaf)}</span>
            </li>
            {proof.path.map((step, i) => (
              <li key={i} className="flex items-center gap-2 pl-3">
                <ArrowUp size={11} className="text-slate-600 flex-shrink-0" />
                <span className={`font-sans text-[9px] font-bold px-1.5 py-0.5 rounded ${step.side === 'left' ? 'bg-violet-400/15 text-violet-300' : 'bg-amber-400/15 text-amber-300'}`}>
                  {step.side === 'left' ? 'L' : 'R'}
                </span>
                <span className="text-slate-400">
                  H(0x01 ‖ {step.side === 'left' ? 'sibling ‖ node' : 'node ‖ sibling'}) · sibling {short(step.hash)}
                </span>
              </li>
            ))}
            <li className={`rounded-lg px-3 py-2 border ${proof.verified ? 'bg-emerald-400/[0.08] border-emerald-400/25' : 'bg-rose-500/[0.08] border-rose-400/25'}`}>
              <span className="text-[10px] font-sans uppercase tracking-widest block mb-0.5 text-slate-400">Root</span>
              <span className={`break-all ${proof.verified ? 'text-emerald-200' : 'text-rose-200'}`}>{group(proof.root)}</span>
            </li>
          </ol>

          <p className={`mt-4 text-sm flex items-center gap-2 ${proof.verified ? 'text-emerald-300' : 'text-rose-300'}`}>
            {proof.verified ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
            {proof.verified
              ? 'Recomputed independently (RFC 9162 §2.1.3.2) — it reproduces the conversation root.'
              : 'The path does not reproduce the root.'}
          </p>
          <p className="text-[11px] text-slate-500 leading-relaxed mt-3">
            Proving this one message belongs to the conversation takes only these {proof.path.length} hashes,
            not the other {Math.max(proof.size - 1, 0)} messages — that is what a tree gives that a hash chain cannot.
          </p>
        </>
      )}
    </Modal>
  );
}
