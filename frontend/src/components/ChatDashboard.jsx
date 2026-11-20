import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { io } from 'socket.io-client';
import { useNavigate } from 'react-router-dom';
import api, { SOCKET_URL, clearSession } from '../lib/api';
import Logo from './visuals/Logo';
import LatticeField from './visuals/LatticeField';
import { useToast } from './visuals/Toast';
import { encryptForRecipients, decryptEnvelope, b64encode, b64decode, publicKeyFromSecretKey, keyFingerprint } from '../crypto/encryption';
import { useTranscriptTree, fetchTranscriptRoot } from '../hooks/useTranscriptTree';
import { TranscriptBadge, TranscriptPanel, ProofDialog } from './TranscriptPanel';
import { createMediaCrypto, withEncodedTransforms, mediaTransformSupport } from '../crypto/mediaTransport';
import {
  startShield, onShieldStatus, shieldStatus, shieldEnabled, setShieldEnabled, analyzeMessage, describeThreat,
} from '../ai/threatShield';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Send, Terminal, LogOut, Lock, ShieldCheck,
  Users, Zap, Trash2, Video, PhoneOff, Mic, MicOff, VideoOff, Check, CheckCheck,
  Paperclip, X, Reply, Smile, File, StopCircle, Trash, Download,
  Copy, UserPlus, Search, Loader2, Menu, KeyRound, ShieldAlert, ArrowDown, Bot, EyeOff, Eye
} from 'lucide-react';

/* ─── Avatar palette ─── */
const GRADIENTS = [
  'from-cyan-400 to-blue-500',
  'from-pink-400 to-rose-600',
  'from-emerald-400 to-cyan-500',
  'from-amber-400 to-orange-500',
  'from-violet-400 to-purple-600',
];
const avatarGrad = (name = '') => GRADIENTS[(name.charCodeAt(0) || 0) % GRADIENTS.length];

/* ─── Day separators ─── */
const dayKey = (ts) => new Date(ts).toDateString();
const dayLabel = (ts) => {
  const d = new Date(ts);
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return 'Today';
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], {
    day: 'numeric',
    month: 'short',
    ...(d.getFullYear() === today.getFullYear() ? {} : { year: 'numeric' }),
  });
};

/* ─── Format timestamp ─── */
const fmt = ts => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const formatLastSeen = ts => {
  if (!ts) return '';
  const d = new Date(ts);
  const now = new Date();
  const mins = Math.round((now - d) / 60000);

  if (mins < 1)  return 'Active just now';
  if (mins < 60) return `Active ${mins}m ago`;

  const midnight = new Date(now); midnight.setHours(0, 0, 0, 0);
  const days = Math.floor((midnight - d) / 86400000) + 1;

  if (days <= 0) return `Last seen today at ${fmt(ts)}`;
  if (days === 1) return `Last seen yesterday at ${fmt(ts)}`;
  if (days < 7)  return `Last seen ${d.toLocaleDateString(undefined, { weekday: 'long' })} at ${fmt(ts)}`;
  return `Last seen ${d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })}`;
};

const REACTION_EMOJIS = ['👍', '❤️', '😂', '😮', '😢'];

// How many messages to pull per page of history.
const PAGE_SIZE = 50;

/* ─── ICE / TURN ───
   STUN only tells a peer its public address; it cannot relay. Two peers behind
   symmetric NATs or strict firewalls will fail to connect without a TURN relay,
   which is the usual cause of a call that rings and never connects. Credentials
   come from env so a relay can be added without touching this file. */
const csv = (value) => (value || '').split(',').map(s => s.trim()).filter(Boolean);

const TURN_URLS = csv(import.meta.env.VITE_TURN_URLS);

const ICE_SERVERS = [
  { urls: csv(import.meta.env.VITE_STUN_URLS).length
      ? csv(import.meta.env.VITE_STUN_URLS)
      : ['stun:stun.l.google.com:19302'] },
  ...(TURN_URLS.length ? [{
    urls: TURN_URLS,
    username: import.meta.env.VITE_TURN_USERNAME || undefined,
    credential: import.meta.env.VITE_TURN_CREDENTIAL || undefined,
  }] : []),
];

export const HAS_TURN = TURN_URLS.length > 0;

/* ─── Connection status ─── */
const CONN_LABELS = {
  connected:    { label: 'Connected',    className: 'text-emerald-400', dot: 'bg-emerald-400' },
  connecting:   { label: 'Reconnecting', className: 'text-amber-400',   dot: 'bg-amber-400' },
  disconnected: { label: 'Disconnected', className: 'text-rose-400',    dot: 'bg-rose-400' },
};

/* ─── Attachment envelope ───
   Non-text messages travel as a JSON envelope so the filename and mime type
   survive the encryption round-trip. Messages sent before this existed are bare
   data URLs, so unpacking falls back to treating the whole string as the data. */
const ATTACHMENT_TAG = 'qchat.attachment.v1';

const packAttachment = ({ name, mime, data }) =>
  JSON.stringify({ __tag: ATTACHMENT_TAG, name, mime, data });

const unpackAttachment = (text) => {
  if (typeof text !== 'string') return { name: null, mime: null, data: '' };
  if (text.startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      if (parsed?.__tag === ATTACHMENT_TAG) {
        return { name: parsed.name || null, mime: parsed.mime || null, data: parsed.data || '' };
      }
    } catch { /* legacy plain data URL */ }
  }
  return { name: null, mime: null, data: text };
};

/* ─── Attachment URL guard ───
   An attachment's data is whatever the sender put in it. Rendered into an href
   it could be a javascript: URL — React 18 renders those, and Chromium runs
   them even on a link with a download attribute — which would hand a stranger
   this page, the private key in localStorage included. Only a base64 data: URL
   of the expected kind is ever rendered. */
const SAFE_DATA_URL = {
  image: /^data:image\/(png|jpe?g|gif|webp|bmp|avif|svg\+xml);base64,/i,
  audio: /^data:audio\/[\w.+-]+(;[\w.+-]+=[\w.+-]+)*;base64,/i,
  file:  /^data:([\w.+-]+\/[\w.+-]+)?(;[\w.+-]+=[\w.+-]+)*;base64,/i,
};
const safeDataUrl = (data, kind) =>
  (typeof data === 'string' && SAFE_DATA_URL[kind]?.test(data) ? data : null);

/* Optimistic bubbles carry a temp id until the server acks with the real one.
   Anything keyed off a server id (delete, react, reply) must wait for it. */
const isRealId = (id) => !!id && !String(id).startsWith('l-');

const previewText = (m) => {
  if (!m) return 'Original message';
  if (m.deleted) return 'Deleted message';
  if (m.type && m.type !== 'text') {
    const { name } = unpackAttachment(m.text);
    return name || `Attachment (${m.type})`;
  }
  return m.text || 'Original message';
};

export default function ChatDashboard() {
  const navigate = useNavigate();
  const toast = useToast();
  // These are read from localStorage on every render, so they MUST be memoised:
  // an unmemoised `privateKey` is a fresh Uint8Array each render, and any effect
  // that lists it as a dependency re-fires forever (infinite render loop).
  const currentUser   = useMemo(
    () => JSON.parse(localStorage.getItem('qchat_user') || '{}'),
    [],
  );
  const privateKeyB64 = currentUser.id ? localStorage.getItem(`qchat_priv_${currentUser.id}`) : null;
  const privateKey    = useMemo(
    () => (privateKeyB64 ? b64decode(privateKeyB64) : null),
    [privateKeyB64],
  );

  const socketRef = useRef(null);
  // Ids that arrived live in this session — only these get the arrival bloom,
  // so loading history doesn't set every bubble flashing at once. Capped: it
  // gates a one-shot animation, so anything older than the recent tail is dead
  // weight, and an unbounded set would grow for the life of the session.
  const freshIdsRef = useRef(new Set());
  const markFresh = useCallback((id) => {
    const set = freshIdsRef.current;
    set.add(String(id));
    if (set.size > 60) {
      // Sets iterate in insertion order, so this drops the oldest entries.
      for (const old of set) {
        if (set.size <= 40) break;
        set.delete(old);
      }
    }
  }, []);
  const [users, setUsers]               = useState([]);
  const [peer, setPeer]                 = useState(null);
  const [messages, setMessages]         = useState([]);
  const [input, setInput]               = useState('');
  const [logs, setLogs]                 = useState([]);
  const [encrypting, setEncrypting]     = useState(false);
  // The protocol console eats 144px — worth it on a desktop, not on a phone.
  const [showConsole, setShowConsole]   = useState(() => typeof window !== 'undefined' && window.innerWidth >= 1024);
  // Below lg the sidebar is a drawer rather than a permanent column.
  const [sidebarOpen, setSidebarOpen]   = useState(false);
  // AI layer (objective 3): on-device phishing and hate-speech detection.
  // `threats` holds verdicts for flagged incoming messages, by message id.
  const [shield, setShield]             = useState(() => shieldStatus());
  const [shieldOn, setShieldOn]         = useState(() => shieldEnabled());
  const [threats, setThreats]           = useState({});
  const [revealed, setRevealed]         = useState({});
  const scannedRef                      = useRef(new Map());   // id -> { phishing, toxicity } models applied
  const shieldOnRef                     = useRef(shieldOn);    // read by scans that finish after a toggle

  // Transcript Merkle tree UI: the integrity panel, a peer comparison in
  // flight, and the proof dialog for one message.
  const [showTranscript, setShowTranscript] = useState(false);
  const [compare, setCompare]           = useState(null);
  const [proofView, setProofView]       = useState(null);
  const compareWaitRef                  = useRef(null);
  const lastCompareFromRef              = useRef(new Map());   // peer id -> time of their last request
  const transcriptRef                   = useRef(null);
  // Demo mode (server DEMO_MODE=true): the attack simulator in the panel.
  const [demo, setDemo]                 = useState(null);
  const [attackBusy, setAttackBusy]     = useState(false);
  const refreshRef                      = useRef(null);
  const [connStatus, setConnStatus]     = useState('connecting');
  
  // WhatsApp Features State
  const [peerTyping, setPeerTyping]     = useState(false);
  const [replyingTo, setReplyingTo]     = useState(null);
  // Which message's reaction picker is open. Click-toggled, not hover —
  // a hover menu can't be reached on touch and dies crossing the gap.
  const [reactionPickerFor, setReactionPickerFor] = useState(null);

  // Contact discovery: you only see people you've added (plus anyone who has
  // messaged you), so the sidebar is no longer a directory of every account.
  const [myProfile, setMyProfile] = useState(null);
  // Is the key on this device actually the one the account advertises?
  const [keyStatus, setKeyStatus] = useState(null);
  const [copied, setCopied]       = useState(false);
  const [showAdd, setShowAdd]     = useState(false);
  const [addQuery, setAddQuery]   = useState('');
  const [addBusy, setAddBusy]     = useState(false);
  const [addError, setAddError]   = useState('');
  const [addResult, setAddResult] = useState(null);

  // History paging. `stickToBottom` stops a prepended page from yanking the
  // reader down, and also stops a new message doing it while they read back.
  const [hasMoreHistory, setHasMoreHistory] = useState(false);
  const [loadingOlder, setLoadingOlder]     = useState(false);
  const [atBottom, setAtBottom]             = useState(true);
  const scrollBoxRef      = useRef(null);

  /** True when there is nothing below the fold worth jumping to. */
  const measureAtBottom = useCallback(() => {
    const box = scrollBoxRef.current;
    if (!box) return true;
    // A thread shorter than the viewport doesn't scroll at all, so it is always
    // "at bottom" — the subtraction already yields 0, but be explicit.
    if (box.scrollHeight <= box.clientHeight) return true;
    return box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  }, []);

  const stickToBottomRef  = useRef(true);
  const loadingOlderRef   = useRef(false);
  const [attachment, setAttachment]     = useState(null);
  const [isRecording, setIsRecording]   = useState(false);
  const fileInputRef                    = useRef(null);
  const mediaRecorderRef                = useRef(null);
  const audioChunksRef                  = useRef([]);
  const typingTimeoutRef                = useRef(null);

  // WebRTC State
  const [callStatus, setCallStatus]     = useState('idle'); // idle, calling, receiving, connected
  const [localStream, setLocalStream]   = useState(null);
  const [remoteStream, setRemoteStream] = useState(null);
  const [isMuted, setIsMuted]           = useState(false);
  const [isVideoOff, setIsVideoOff]     = useState(false);
  const rtcPeerConnection               = useRef(null);
  // Socket handlers are bound once in a []-dep effect, so anything they touch
  // during teardown must live in a ref, not in state.
  const localStreamRef                  = useRef(null);
  const pendingCandidatesRef            = useRef([]);
  const localVideoRef                   = useRef(null);
  const remoteVideoRef                  = useRef(null);
  const callPayloadRef                  = useRef(null); // stores incoming offer
  // The person a call is with, pinned when it starts. Signals go to them and
  // only their signals are accepted. Keying both off the open chat let a call
  // follow you into another conversation, and let any account hang it up.
  const [callPeer, setCallPeer]         = useState(null);
  const callPeerRef                     = useRef(null);
  // Socket handlers are bound once, so they read call state from a ref.
  const callStatusRef                   = useRef('idle');
  const ringTimeoutRef                  = useRef(null);
  const usersRef                        = useRef([]);

  const updateCallStatus = (status) => {
    callStatusRef.current = status;
    setCallStatus(status);
  };

  const pinCallPeer = (u) => {
    callPeerRef.current = u ? { id: String(u.id), username: u.username, public_key: u.public_key } : null;
    setCallPeer(callPeerRef.current);
  };

  /* Persist selected peer across refreshes */
  const selectPeer = (u, { force = false } = {}) => {
    // Mid-call the conversation is locked to the call: the call UI lives in the
    // chat pane, and wandering off left it showing over someone else's thread.
    if (!force && u && callStatusRef.current !== 'idle' && String(u.id) !== callPeerRef.current?.id) {
      toast.info('Finish the current call before switching chats.');
      return;
    }
    setPeer(u);
    if (u) setUsers(prev => prev.map(x => (String(x.id) === String(u.id) ? { ...x, unread: 0 } : x)));
    setSidebarOpen(false);
    setReplyingTo(null);
    setReactionPickerFor(null);
    setAttachment(null);
    if (u) sessionStorage.setItem('qchat_last_peer', JSON.stringify(u));
    else    sessionStorage.removeItem('qchat_last_peer');
  };

  const bottomRef        = useRef(null);
  const inputRef         = useRef(null);
  const peerRestoredRef  = useRef(false);
  const peerRef          = useRef(null);

  useEffect(() => { peerRef.current = peer; }, [peer]);
  useEffect(() => { usersRef.current = users; }, [users]);

  const addLog = useCallback((msg, type = 'info') => {
    const t = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setLogs(prev => [...prev, { msg, type, t }].slice(-25));
  }, []);

  /* ─── WebRTC Logic ─── */
  const rtcConfig = { iceServers: ICE_SERVERS };

  // Per-call media crypto. The master secret is minted by the caller and rides
  // inside the ML-KEM-sealed offer, so the media key never crosses the wire in
  // a form a harvested recording could later expose.
  const mediaCryptoRef  = useRef(null);
  const mediaSecretRef  = useRef(null);
  // 'pq' when frames are sealed under the ML-KEM call key, 'srtp' when the
  // browser has no encoded-frame API. Shown in the call UI, because claiming
  // post-quantum media when it silently fell back would be the worst outcome.
  const [mediaProtection, setMediaProtection] = useState(null);

  const flushPendingCandidates = async () => {
    const pc = rtcPeerConnection.current;
    if (!pc) return;
    const queued = pendingCandidatesRef.current;
    pendingCandidatesRef.current = [];
    for (const candidate of queued) {
      try {
        await pc.addIceCandidate(new RTCIceCandidate(candidate));
      } catch (err) {
        addLog(`Discarded a stale ICE candidate: ${err.message}`, 'pink');
      }
    }
  };

  // `target` defaults to the pinned call peer; it is evaluated at call time, so
  // a cleanup that runs right after can't redirect a signal already being sent.
  const encryptAndSendSignal = async (signalData, target = callPeerRef.current) => {
    try {
      if (!target?.public_key) return;
      const payload = await encryptForRecipients(JSON.stringify(signalData), [
        { id: String(target.id), publicKey: b64decode(target.public_key) },
      ]);
      socketRef.current?.emit('webrtc_signal', { toId: target.id, signalPayload: payload });
      addLog(`Sent encrypted WebRTC signal (${signalData.type || 'candidate'})`, 'cyan');
    } catch (err) {
      addLog(`Failed to encrypt signal: ${err.message}`, 'pink');
    }
  };

  const initWebRTC = async (isInitiator) => {
    try {
      if (!HAS_TURN) {
        addLog('No TURN relay configured — a call may not connect across networks', 'pink');
      }

      // If a previous capture is somehow still live, stop it first — otherwise
      // that stream becomes unreachable and its camera light never goes out.
      stopLocalCapture();

      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      localStreamRef.current = stream;
      setLocalStream(stream);
      if (localVideoRef.current) localVideoRef.current.srcObject = stream;

      // The caller mints a media secret only if this browser can seal frames —
      // offering a key it couldn't use left the callee encrypting toward a peer
      // that sent plaintext. The callee already took the secret off the offer.
      const canSeal = mediaTransformSupport() !== 'none';
      if (isInitiator) mediaSecretRef.current = canSeal ? crypto.getRandomValues(new Uint8Array(32)) : null;
      const masterSecret = canSeal ? mediaSecretRef.current : null;

      // Chrome's encoded-streams flag is fixed at construction, and once set
      // every track must be piped through a transform or no media flows at all.
      // So it is set only when a transform really will be attached.
      const pc = new RTCPeerConnection(masterSecret ? withEncodedTransforms(rtcConfig) : rtcConfig);
      rtcPeerConnection.current = pc;

      const media = masterSecret
        ? await createMediaCrypto({
            masterSecret,
            isInitiator,
            onError: ({ mode, message }) =>
              addLog(`Media ${mode === 'encrypt' ? 'sealing' : 'opening'} failed: ${message}`, 'pink'),
            onFirst: ({ mode }) => {
              addLog(mode === 'encrypt'
                ? 'First outgoing frame sealed'
                : 'First incoming frame opened', 'green');
              // Only an opened incoming frame proves the round trip works;
              // sealing alone proves nothing about what the peer can read.
              if (mode === 'decrypt') setMediaProtection('pq');
            },
          })
        : null;
      mediaCryptoRef.current = media;

      if (media?.support === 'none' || !masterSecret) {
        setMediaProtection('srtp');
        addLog('This browser has no encoded-frame API — media falls back to DTLS-SRTP only', 'pink');
      } else {
        // Stays 'pending' until a frame is actually opened. Claiming protection
        // that silently failed is worse than admitting the fallback.
        setMediaProtection('pending');
        addLog(`Media transform path: ${media.support}`, 'cyan');
      }

      stream.getTracks().forEach(track => {
        const sender = pc.addTrack(track, stream);
        media?.applyToSender(sender);
      });

      // Pin VP8 for video whenever frames are being sealed.
      //
      // The cipher leaves a short codec header in the clear so the packetizer
      // can still fragment the frame, and those offsets (10 bytes on a key
      // frame, 3 on a delta) are VP8's. H.264 carries Annex-B NAL start codes
      // throughout the payload, so sealing past the first few bytes leaves the
      // packetizer hunting for boundaries in ciphertext: it splits in the wrong
      // places and the far end decodes a smear. macOS Chrome will happily pick
      // H.264 for hardware encoding, so the codec has to be forced, not hoped
      // for. This is why every insertable-streams implementation pins VP8.
      if (media && media.support !== 'none') {
        for (const transceiver of pc.getTransceivers()) {
          if (transceiver.sender?.track?.kind !== 'video') continue;
          if (typeof transceiver.setCodecPreferences !== 'function') continue;
          try {
            const supported = RTCRtpSender.getCapabilities('video')?.codecs || [];
            const vp8 = supported.filter(c => /vp8/i.test(c.mimeType));
            if (vp8.length) {
              // VP8 first, everything else after, so a peer that cannot do VP8
              // still negotiates something rather than failing outright.
              transceiver.setCodecPreferences([
                ...vp8,
                ...supported.filter(c => !/vp8/i.test(c.mimeType)),
              ]);
            }
          } catch (err) {
            addLog(`Could not pin VP8: ${err.message}`, 'pink');
          }
        }
      }

      // Report what was actually negotiated once the call settles — the pin is
      // a preference, not a guarantee, and a silent fallback to H.264 would
      // look like a rendering bug rather than a codec one.
      pc.addEventListener('connectionstatechange', async () => {
        if (pc.connectionState !== 'connected') return;
        try {
          const stats = await pc.getStats();
          const codecs = new Set();
          stats.forEach(r => {
            if (r.type === 'outbound-rtp' && r.kind === 'video' && r.codecId) {
              const c = stats.get(r.codecId);
              if (c?.mimeType) codecs.add(c.mimeType);
            }
          });
          if (codecs.size) addLog(`Video codec in use: ${[...codecs].join(', ')}`, 'cyan');
        } catch { /* stats are best effort */ }
      });

      pc.ontrack = (event) => {
        // Attach before the decoder sees anything, or the first frames arrive
        // as ciphertext and the picture opens corrupt.
        media?.applyToReceiver(event.receiver);
        setRemoteStream(event.streams[0]);
        if (remoteVideoRef.current) remoteVideoRef.current.srcObject = event.streams[0];
      };

      pc.onicecandidate = (event) => {
        if (event.candidate && callPeerRef.current) {
          encryptAndSendSignal({ type: 'candidate', candidate: event.candidate });
        }
      };

      if (isInitiator) {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        encryptAndSendSignal({
          type: 'offer',
          sdp: offer,
          // Sealed to the peer's ML-KEM public key along with the rest of the
          // signal, which is what makes the media layer post-quantum.
          mediaKey: mediaSecretRef.current ? b64encode(mediaSecretRef.current) : undefined,
        });
        updateCallStatus('calling');

        // Give up ringing after 45s rather than leaving the camera on forever.
        clearTimeout(ringTimeoutRef.current);
        ringTimeoutRef.current = setTimeout(() => {
          if (callStatusRef.current !== 'calling') return;
          encryptAndSendSignal({ type: 'end_call' });
          cleanupCall();
          toast.info('No answer.');
        }, 45_000);
      }
    } catch (err) {
      addLog(`WebRTC Init failed: ${err.message}`, 'pink');
      toast.error(`Could not start the call: ${err.message}`);
      // A callee that fails here would otherwise leave the caller ringing.
      if (!isInitiator) encryptAndSendSignal({ type: 'decline' });
      cleanupCall();
    }
  };

  /** A contact by id, refreshing the list once if they're new to it. */
  const findContact = async (id) => {
    const look = () => usersRef.current.find(u => String(u.id) === String(id));
    let u = look();
    if (!u) { await fetchUsers(); u = look(); }
    return u ? { ...u, id: String(u.id) } : null;
  };

  const handleWebRTCSignal = async (fromId, signalPayload) => {
    try {
      const decrypted = await decryptEnvelope(signalPayload, currentUser.id, privateKey);
      const signal = JSON.parse(decrypted);
      const from = String(fromId);
      const pinned = callPeerRef.current;
      addLog(`Received encrypted WebRTC signal (${signal.type || 'candidate'})`, 'green');

      if (signal.type === 'offer') {
        const status = callStatusRef.current;
        const fromCallPeer = pinned?.id === from;

        if (status === 'calling' && fromCallPeer) {
          // Both sides rang each other at once. The lower user id keeps its
          // call; the other drops its own attempt and takes this one instead.
          if (String(currentUser.id) < from) return;
          cleanupCall({ keepPeer: true, quiet: true });
        } else if (status !== 'idle') {
          // Already on (or ringing for) a call: say so, rather than silently
          // replacing the call in progress or leaving the caller ringing.
          const caller = await findContact(from);
          if (caller) encryptAndSendSignal({ type: 'busy' }, caller);
          addLog(`Turned away a call from ${caller?.username || from.slice(-6)} — already on a call`, 'pink');
          return;
        }

        const caller = fromCallPeer ? pinned : await findContact(from);
        if (!caller) return addLog('Ignored a call from an account not in your contacts', 'pink');

        pinCallPeer(caller);
        callPayloadRef.current = signal;
        // Lift the media key out now: initWebRTC needs it before it adds any
        // track, and it only ever travels inside this decrypted offer.
        mediaSecretRef.current = signal.mediaKey ? b64decode(signal.mediaKey) : null;
        // An incoming call opens that conversation, wherever you were — it
        // used to be dropped as a "missed call" unless that chat was open.
        if (String(peerRef.current?.id) !== caller.id) selectPeer(caller, { force: true });
        updateCallStatus('receiving');
        return;
      }

      // Every other signal belongs to the call in progress, and to nobody else.
      if (!pinned || pinned.id !== from) {
        return addLog(`Ignored a ${signal.type || 'candidate'} signal from outside this call`, 'pink');
      }

      if (signal.type === 'answer') {
        const pc = rtcPeerConnection.current;
        if (!pc) return;
        clearTimeout(ringTimeoutRef.current);
        await pc.setRemoteDescription(new RTCSessionDescription(signal.sdp));
        await flushPendingCandidates();
        // The callee couldn't seal frames, so stop sealing ours as well;
        // otherwise each side receives a stream it can't decode.
        if (signal.mediaSealed === false && mediaCryptoRef.current) {
          mediaCryptoRef.current.disable?.();
          setMediaProtection('srtp');
          addLog('Peer cannot seal media — both directions fall back to DTLS-SRTP', 'pink');
        }
        updateCallStatus('connected');
      } else if (signal.type === 'candidate') {
        const pc = rtcPeerConnection.current;
        // A candidate that arrives before the remote description is set throws
        // and is lost, which can leave the call stuck connecting. Queue instead.
        if (pc?.remoteDescription?.type) {
          await pc.addIceCandidate(new RTCIceCandidate(signal.candidate));
        } else {
          pendingCandidatesRef.current.push(signal.candidate);
        }
      } else if (signal.type === 'end_call' || signal.type === 'decline' || signal.type === 'busy') {
        const name = pinned.username || 'Your contact';
        const was = callStatusRef.current;
        cleanupCall();
        if (signal.type === 'decline') toast.info(`${name} declined the call.`);
        else if (signal.type === 'busy') toast.info(`${name} is on another call.`);
        else if (was === 'receiving') toast.info(`Missed call from ${name}.`);
      }
    } catch (err) {
      addLog(`Failed to process WebRTC signal: ${err.message}`, 'pink');
    }
  };

  const startCall = () => {
    if (!peer || callStatusRef.current !== 'idle') return;
    if (!peer.public_key) return toast.error(`${peer.username} has no encryption key yet.`);
    pinCallPeer(peer);
    initWebRTC(true);
  };

  const acceptCall = async () => {
    await initWebRTC(false);
    const pc = rtcPeerConnection.current;
    if (!pc || !callPayloadRef.current) return;
    try {
      await pc.setRemoteDescription(new RTCSessionDescription(callPayloadRef.current.sdp));
      await flushPendingCandidates();
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      encryptAndSendSignal({
        type: 'answer',
        sdp: answer,
        // Tells the caller whether we really seal frames, so it can drop its
        // own cipher instead of sending us a stream we can't open.
        mediaSealed: !!mediaCryptoRef.current?.attached?.encrypt,
      });
      updateCallStatus('connected');
      callPayloadRef.current = null;
    } catch (err) {
      addLog(`Could not answer the call: ${err.message}`, 'pink');
      encryptAndSendSignal({ type: 'decline' });
      cleanupCall();
    }
  };

  /** Turn an incoming call down and tell the caller, so they stop ringing. */
  const declineCall = () => {
    encryptAndSendSignal({ type: 'decline' });
    cleanupCall();
  };

  /**
   * Stop every capture track we can reach, from all three places one can hide:
   * the ref, the peer connection's senders, and whatever is bound to the video
   * elements. Stopping an already-stopped track is a no-op, so over-reaching is
   * safe and is the point — a track missed here keeps the camera light on.
   */
  const stopLocalCapture = () => {
    let stopped = 0;

    const stopTrack = (t) => {
      if (!t) return;
      if (t.readyState !== 'ended') { t.stop(); stopped++; }
    };

    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach(stopTrack);
      localStreamRef.current = null;
    }

    const pc = rtcPeerConnection.current;
    if (pc) {
      try { pc.getSenders().forEach(s => stopTrack(s.track)); } catch { /* pc already closed */ }
    }

    for (const ref of [localVideoRef, remoteVideoRef]) {
      const el = ref.current;
      if (el?.srcObject) {
        if (ref === localVideoRef) el.srcObject.getTracks?.().forEach(stopTrack);
        el.srcObject = null;
      }
    }

    return stopped;
  };

  const cleanupCall = ({ keepPeer = false, quiet = false } = {}) => {
    clearTimeout(ringTimeoutRef.current);
    // Capture is released before closing the connection, so a throw while
    // closing can never strand a live camera.
    const stopped = stopLocalCapture();

    if (rtcPeerConnection.current) {
      try { rtcPeerConnection.current.close(); } catch { /* already closed */ }
      rtcPeerConnection.current = null;
    }

    // Tear down the media crypto worker and forget the call key. Keeping the
    // secret past the call it belongs to buys nothing and widens the window in
    // which a compromised tab could leak it.
    try { mediaCryptoRef.current?.close(); } catch { /* already gone */ }
    mediaCryptoRef.current = null;
    if (mediaSecretRef.current) mediaSecretRef.current.fill(0);
    mediaSecretRef.current = null;
    setMediaProtection(null);

    setLocalStream(null);
    setRemoteStream(null);
    pendingCandidatesRef.current = [];
    callPayloadRef.current = null;
    updateCallStatus('idle');
    if (!keepPeer) pinCallPeer(null);
    setIsMuted(false);
    setIsVideoOff(false);
    if (!quiet) addLog(`Call ended — released ${stopped} media track(s)`, 'cyan');
  };

  const endCall = () => {
    encryptAndSendSignal({ type: 'end_call' });
    cleanupCall();
  };

  const toggleMute = () => {
    if (localStream) {
      const audioTrack = localStream.getAudioTracks()[0];
      if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        setIsMuted(!audioTrack.enabled);
      }
    }
  };

  const toggleVideo = () => {
    if (localStream) {
      const videoTrack = localStream.getVideoTracks()[0];
      if (videoTrack) {
        videoTrack.enabled = !videoTrack.enabled;
        setIsVideoOff(!videoTrack.enabled);
      }
    }
  };


  /* ─── Bind media to the video elements ───
     initWebRTC can't assign srcObject directly: when it runs, callStatus is
     still 'idle' (caller) or 'receiving' (callee), so neither <video> is
     mounted yet and the ref is null. Bind once they render. */
  useEffect(() => {
    if (localVideoRef.current && localStream) localVideoRef.current.srcObject = localStream;
  }, [localStream, callStatus]);

  useEffect(() => {
    if (remoteVideoRef.current && remoteStream) remoteVideoRef.current.srcObject = remoteStream;
  }, [remoteStream, callStatus]);

  /* Safety net: release the camera if this component goes away mid-call
     (logout, navigation, an unhandled render error). */
  useEffect(() => () => {
    clearTimeout(ringTimeoutRef.current);
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach(t => t.stop());
      localStreamRef.current = null;
    }
    if (rtcPeerConnection.current) {
      try { rtcPeerConnection.current.close(); } catch { /* already closed */ }
      rtcPeerConnection.current = null;
    }
  }, []);

  /* Own profile, for the shareable QChat ID. Fetched rather than read from
     localStorage so sessions created before IDs existed still get one. */
  useEffect(() => {
    api.get('/api/users/me')
      .then(({ data }) => setMyProfile(data))
      .catch(err => addLog(`Could not load your profile: ${err.message}`, 'pink'));
  }, []);

  /* Compare this device's private key against the public key the server holds
     for us. A mismatch is the real reason old messages stop opening, and it is
     worth saying precisely rather than showing a generic failure. */
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!privateKey) { if (!cancelled) setKeyStatus({ state: 'missing' }); return; }

      const derived = publicKeyFromSecretKey(privateKey);
      if (!derived) { if (!cancelled) setKeyStatus({ state: 'invalid' }); return; }

      const mine = await keyFingerprint(derived);
      const serverKey = myProfile?.public_key;
      if (!serverKey) { if (!cancelled) setKeyStatus({ state: 'ok', mine }); return; }

      const server = await keyFingerprint(b64decode(serverKey));
      if (!cancelled) setKeyStatus({ state: mine === server ? 'ok' : 'mismatch', mine, server });
    })().catch(() => { if (!cancelled) setKeyStatus(null); });
    return () => { cancelled = true; };
  }, [privateKey, myProfile]);

  /* Dismiss the reaction picker on an outside click or Escape. */
  useEffect(() => {
    if (!reactionPickerFor) return;
    const onPointerDown = (e) => {
      if (!e.target.closest?.('[data-reaction-ui]')) setReactionPickerFor(null);
    };
    const onKey = (e) => { if (e.key === 'Escape') setReactionPickerFor(null); };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [reactionPickerFor]);

  /* ─── Socket setup ─── */
  useEffect(() => {
    if (!currentUser.id) { navigate('/login'); return; }

    // The server verifies this token during the handshake and derives our
    // identity from it, so no event needs to send a user id any more.
    const s = io(SOCKET_URL, {
      auth: { token: localStorage.getItem('qchat_token') },
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: 10,
    });
    socketRef.current = s;

    s.on('connect', () => {
      setConnStatus('connected');
      addLog('Connected to secure relay server', 'cyan');
    });

    s.on('disconnect', () => {
      setConnStatus('disconnected');
      addLog('Server disconnected — attempting to reconnect', 'pink');
    });

    // 'reconnecting'/'reconnect' were socket.io v2 events and never fired on a
    // v4 socket; the manager exposes the real ones.
    s.io.on('reconnect_attempt', () => setConnStatus('connecting'));

    s.on('connect_error', (err) => {
      setConnStatus('disconnected');
      if (err.message === 'UNAUTHORIZED' || err.message === 'SESSION_EXPIRED') {
        addLog('Session rejected by server — signing out', 'pink');
        clearSession();
        navigate('/login');
        return;
      }
      addLog(`Connection error: ${err.message}`, 'pink');
    });

    s.on('new_message', async (msg) => {
      // A message deleted while we were offline arrives with an emptied payload;
      // render the tombstone instead of failing to decrypt it as a corrupt one.
      if (msg.deleted) {
        if (peerRef.current && String(peerRef.current.id) === String(msg.fromId)) {
          setMessages(prev => prev.some(m => String(m.id) === String(msg.id))
            ? prev
            : [...prev, { ...msg, text: '', isMine: false }]);
        }
        return;
      }

      try {
        const t0 = performance.now();
        const text = await decryptEnvelope(msg.payload, currentUser.id, privateKey);
        addLog(
          `Decapsulated content key · decrypted ${text.length}B in ${Math.round(performance.now() - t0)}ms`,
          'cyan',
        );

        if (peerRef.current && String(peerRef.current.id) === String(msg.fromId)) {
          setMessages(prev => {
            if (prev.some(m => String(m.id) === String(msg.id))) return prev;
            markFresh(msg.id);
            return [...prev, { ...msg, text, isMine: false }];
          });
          // Send read receipt if we are actively viewing this chat
          if (document.hasFocus()) {
            s.emit('message_read', { messageIds: [msg.id], toId: msg.fromId });
          }
        } else {
          noteBackgroundMessage(msg.fromId);
        }
      } catch {
        if (peerRef.current && String(peerRef.current.id) === String(msg.fromId)) {
          setMessages(prev => {
            if (prev.some(m => String(m.id) === String(msg.id))) return prev;
            markFresh(msg.id);
            return [...prev, { ...msg, text: '[Locked — previous session key]', isMine: false, error: true }];
          });
        } else {
          noteBackgroundMessage(msg.fromId);
        }
      }
    });

    // WhatsApp-like features
    s.on('message_delivered', ({ messageIds, toUserId }) => {
      if (peerRef.current && String(peerRef.current.id) === String(toUserId)) {
        setMessages(prev => prev.map(m => messageIds.includes(String(m.id)) ? { ...m, delivered: true } : m));
      }
    });

    s.on('message_read', ({ messageIds, byUserId }) => {
      if (peerRef.current && String(peerRef.current.id) === String(byUserId)) {
        setMessages(prev => prev.map(m => messageIds.includes(String(m.id)) ? { ...m, read: true, delivered: true } : m));
      }
    });

    s.on('message_deleted', ({ messageId }) => {
      setMessages(prev => prev.map(m => String(m.id) === String(messageId) ? { ...m, deleted: true, text: '', type: 'text', reactions: [] } : m));
    });

    // The server toggles and returns the authoritative array. Replacing rather
    // than appending is what stops your own reaction counting twice — once
    // optimistically, then again when the echo comes back.
    s.on('message_reaction', async ({ messageId, reactions }) => {
      const hydrated = await hydrateReactions(reactions);
      setMessages(prev => prev.map(m =>
        String(m.id) === String(messageId) ? { ...m, reactions: hydrated } : m
      ));
    });

    // Swap the optimistic temp id for the server's real one, so delivery ticks,
    // read receipts, deletes, reactions and replies all work on a fresh message.
    s.on('message_sent', ({ tempId, id, timestamp, delivered }) => {
      if (!tempId) return;
      if (freshIdsRef.current.delete(String(tempId))) markFresh(id);
      setMessages(prev => prev.map(m =>
        String(m.id) === String(tempId)
          ? { ...m, id, timestamp: timestamp || m.timestamp, delivered: !!delivered }
          : m
      ));
    });

    s.on('message_error', ({ tempId, error }) => {
      toast.error(error === 'PAYLOAD_TOO_LARGE'
        ? 'That attachment was too large to send.'
        : 'Your message could not be sent.');
      // Flagged as a failed send, not as `error`: `error` means "couldn't be
      // decrypted", and those are folded into the "encrypted to an earlier key"
      // line — which is where a failed send used to vanish, mislabelled.
      setMessages(prev => prev.map(m =>
        String(m.id) === String(tempId) ? { ...m, sendFailed: error || 'SEND_FAILED' } : m
      ));
    });

    s.on('typing', ({ fromId }) => {
      if (peerRef.current && String(peerRef.current.id) === String(fromId)) setPeerTyping(true);
    });

    s.on('stop_typing', ({ fromId }) => {
      if (peerRef.current && String(peerRef.current.id) === String(fromId)) setPeerTyping(false);
    });

    s.on('webrtc_signal', ({ fromId, signalPayload }) => {
      handleWebRTCSignal(fromId, signalPayload);
    });

    s.on('user_status', ({ userId, status, lastSeen }) => {
      setUsers(prev => prev.map(u => String(u.id) === String(userId) ? { ...u, isOnline: status === 'online', lastSeen } : u));
      if (peerRef.current && String(peerRef.current.id) === String(userId)) {
        setPeer(prev => ({ ...prev, isOnline: status === 'online', lastSeen }));
      }
    });

    s.on('chat_cleared', ({ byUserId }) => {
      if (peerRef.current && String(peerRef.current.id) === String(byUserId)) {
        setMessages([]);
        // A cleared chat is a legitimate rewrite of history; start the tree over
        // rather than flagging every message as removed.
        transcriptRef.current?.reset();
      }
    });

    s.on('transcript_check', ({ fromId, payload }) => {
      handleTranscriptCheck(fromId, payload);
    });

    // The server changed this conversation's stored history (the demo attack
    // simulator, or its restore): reload it and verify again.
    s.on('transcript_refresh', ({ peerId }) => {
      if (String(peerRef.current?.id) === String(peerId)) refreshRef.current?.(peerId);
    });

    fetchUsers();
    return () => {
      if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
      s.close();
    };
  }, []);

  /* ─── Load history on peer change ─── */
  useEffect(() => {
    if (!peer) return;
    setMessages([]); setPeerTyping(false);
    setCompare(null); setProofView(null); setShowTranscript(false);
    setHasMoreHistory(false);
    stickToBottomRef.current = true;
    loadHistory(peer.id);
    setTimeout(() => inputRef.current?.focus(), 100);
  }, [peer?.id]);

  /* ─── Window focus read receipts ─── */
  useEffect(() => {
    const onFocus = () => {
      if (peerRef.current && socketRef.current) {
        const unreadIds = messages.filter(m => !m.isMine && !m.read && !m.deleted).map(m => m.id);
        if (unreadIds.length > 0) {
          socketRef.current.emit('message_read', { messageIds: unreadIds, toId: peerRef.current.id });
          setMessages(prev => prev.map(m => unreadIds.includes(m.id) ? { ...m, read: true } : m));
        }
      }
    };
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [messages]);

  /* ─── Scroll on message update ─── */
  useEffect(() => {
    // Only follow new messages when the reader is already at the bottom.
    if (stickToBottomRef.current) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    // Re-measure after the DOM settles: the content that just changed decides
    // whether there is anything left to jump to.
    const id = requestAnimationFrame(() => setAtBottom(measureAtBottom()));
    return () => cancelAnimationFrame(id);
  }, [messages, peerTyping, measureAtBottom]);

  /* Re-measure when the pane itself resizes — opening the console or the
     drawer changes the viewport without ever firing a scroll event. */
  useEffect(() => {
    const box = scrollBoxRef.current;
    if (!box || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(() => setAtBottom(measureAtBottom()));
    ro.observe(box);
    return () => ro.disconnect();
  }, [peer?.id, measureAtBottom]);

  /* ─── Transcript Merkle tree (objective 2) ───
     All of the state lives in the hook; see hooks/useTranscriptTree.js. */
  const transcript = useTranscriptTree({
    myId: currentUser.id ? String(currentUser.id) : null,
    peerId: peer?.id ? String(peer.id) : null,
    messages,
  });
  useEffect(() => { transcriptRef.current = transcript; }, [transcript]);

  /* Re-fetch the open conversation and verify it again from scratch. The tree
     is suspended first so it never judges new leaves against old messages. */
  const refreshConversation = async (peerId) => {
    transcript.suspend();
    await loadHistory(peerId, { replace: true });
    transcript.reload();
  };
  useEffect(() => { refreshRef.current = refreshConversation; });

  // A tampered history opens the integrity panel on its own: a warning that
  // waits for someone to click a small badge is easy to miss.
  const lastStatusRef = useRef(null);
  useEffect(() => {
    if (transcript.status === 'tampered' && lastStatusRef.current !== 'tampered') setShowTranscript(true);
    if (transcript.status && transcript.status !== 'checking') lastStatusRef.current = transcript.status;
  }, [transcript.status]);

  useEffect(() => {
    api.get('/api/demo').then(({ data }) => setDemo(data?.enabled ? data : null)).catch(() => setDemo(null));
  }, []);

  const runAttack = async (mode, messageId) => {
    setAttackBusy(true);
    try {
      // The server tells both devices to re-verify (transcript_refresh).
      await api.post('/api/demo/tamper', { messageId, mode });
      addLog(`Simulated attack on message ${String(messageId).slice(-6)}: ${demo?.attacks?.[mode] || mode}`, 'pink');
    } catch (err) {
      toast.error(err.response?.data?.error || 'The attack could not be run.');
    } finally {
      setAttackBusy(false);
    }
  };

  const restoreAttacks = async () => {
    if (!peer) return;
    setAttackBusy(true);
    try {
      const { data } = await api.post('/api/demo/restore', { peerId: peer.id });
      toast.success(data.restored ? `Restored the database — ${data.restored} attack${data.restored === 1 ? '' : 's'} undone.` : 'Nothing to restore.');
    } catch (err) {
      toast.error(err.response?.data?.error || 'Could not restore.');
    } finally {
      setAttackBusy(false);
    }
  };

  const attackTargets = useMemo(() => messages
    .filter(m => isRealId(m.id) && !m.deleted && !m.sendFailed)
    .slice(-12)
    .map(m => {
      const n = transcript.indexOf(m.id);
      const who = m.isMine ? 'You' : (peer?.username || 'Them');
      const text = m.error ? '(undecryptable)' : previewText(m);
      return { id: String(m.id), label: `${n >= 0 ? `#${n + 1}` : '#?'} · ${who}: ${text.length > 40 ? `${text.slice(0, 40)}…` : text}` };
    }), [messages, transcript.indexOf, peer?.username]);

  /* ─── AI shield ─── */
  // A blurred message must not reappear in clear in a reply quote.
  const shieldedPreview = (m) => {
    const t = m && !m.isMine && threats[m.id];
    if (t && t.parts.some(p => p.kind === 'toxicity') && !revealed[m.id]) return 'Message hidden by the AI shield';
    return previewText(m);
  };

  useEffect(() => onShieldStatus(setShield), []);
  useEffect(() => { shieldOnRef.current = shieldOn; if (shieldOn) startShield(); }, [shieldOn]);

  const toggleShield = () => {
    const next = !shieldOn;
    setShieldEnabled(next);
    setShieldOn(next);
    if (!next) { setThreats({}); scannedRef.current.clear(); }
  };

  // Scan incoming text messages on this device once they are decrypted. A
  // message is scanned again when a model that wasn't ready the first time
  // (the transformer takes a while to download) becomes ready.
  useEffect(() => {
    if (!shieldOn) return;
    const phishingReady = shield.phishing === 'ready';
    const toxicityReady = shield.toxicity === 'ready';
    if (!phishingReady && !toxicityReady) return;

    for (const m of messages) {
      if (m.isMine || m.deleted || m.error || !isRealId(m.id) || (m.type && m.type !== 'text') || !m.text) continue;
      const done = scannedRef.current.get(m.id);
      if (done && (done.phishing || !phishingReady) && (done.toxicity || !toxicityReady)) continue;
      scannedRef.current.set(m.id, { phishing: phishingReady, toxicity: toxicityReady });
      // History is scanned in the background, so allow it time: a short
      // timeout here used to mark queued messages as scanned when their
      // result simply hadn't come back yet, and they were never flagged.
      analyzeMessage(m.text, 120_000).then((result) => {
        if (!shieldOnRef.current) return;
        if (!result) { scannedRef.current.delete(m.id); return; }
        const parts = describeThreat(result);
        if (parts) {
          setThreats(prev => ({ ...prev, [m.id]: { parts, result } }));
          addLog(`AI shield flagged a message on-device: ${parts.map(p => p.title).join(' + ')} · ${result.ms} ms`, 'pink');
        } else if (Date.now() - new Date(m.timestamp).getTime() < 60_000) {
          // Only live messages; a whole history page of "clean" lines buried the console.
          addLog(`AI shield: message clean · phishing ${result.phishing ? result.phishing.score : '—'} · toxicity ${result.toxicity ? result.toxicity.scores.toxic : '—'} · ${result.ms} ms on-device`, 'cyan');
        }
      });
    }
    if (scannedRef.current.size > 3000) scannedRef.current.clear();
  }, [messages, shield.phishing, shield.toxicity, shieldOn]);

  /** Ask the peer's device for its root over the same messages, and compare. */
  const compareWithPeer = async () => {
    const target = peerRef.current;
    if (!target?.public_key || !transcript.ready) return;
    try {
      const mine = await transcript.rootAt(transcript.size);
      const nonce = b64encode(crypto.getRandomValues(new Uint8Array(12)));
      const payload = await encryptForRecipients(
        JSON.stringify({ kind: 'request', nonce, size: mine.size, root: mine.root }),
        [{ id: String(target.id), publicKey: b64decode(target.public_key) }],
      );
      clearTimeout(compareWaitRef.current?.timer);
      setCompare({ state: 'waiting' });
      compareWaitRef.current = {
        nonce,
        peerId: String(target.id),
        timer: setTimeout(() => {
          if (compareWaitRef.current?.nonce !== nonce) return;
          compareWaitRef.current = null;
          setCompare({ state: 'timeout' });
        }, 8000),
      };
      socketRef.current?.emit('transcript_check', { toId: target.id, payload });
      addLog(`Asked ${target.username} for their Merkle root over ${mine.size} messages`, 'cyan');
    } catch (err) {
      setCompare({ state: 'error' });
      addLog(`Could not start the comparison: ${err.message}`, 'pink');
    }
  };

  /** Both halves of the comparison: answer a request, or settle our own. */
  const handleTranscriptCheck = async (fromId, payload) => {
    const from = String(fromId);
    try {
      const msg = JSON.parse(await decryptEnvelope(payload, currentUser.id, privateKey));
      const open = String(peerRef.current?.id) === from && transcriptRef.current?.ready;
      // The verified tree if that chat is open here; otherwise rebuilt from the
      // server's leaves for that conversation.
      const rootAt = (size) => (open ? transcriptRef.current.rootAt(size) : fetchTranscriptRoot(from, size));

      if (msg.kind === 'request') {
        // Answering means rebuilding a tree, so a contact can't make this
        // device do it (or pop a toast) more than once every few seconds.
        const last = lastCompareFromRef.current.get(from) || 0;
        if (Date.now() - last < 3000) return;
        lastCompareFromRef.current.set(from, Date.now());
        const sender = await findContact(from);
        if (!sender?.public_key) return;
        const mine = await rootAt(msg.size);
        const sealed = await encryptForRecipients(
          JSON.stringify({ kind: 'reply', nonce: msg.nonce, size: mine.size, root: mine.root }),
          [{ id: from, publicKey: b64decode(sender.public_key) }],
        );
        socketRef.current?.emit('transcript_check', { toId: from, payload: sealed });
        toast.info(`${sender.username} compared your conversation's Merkle root with theirs.`);
        addLog(`Answered a transcript comparison from ${sender.username} (${mine.size} messages)`, 'cyan');
      } else if (msg.kind === 'reply') {
        const pending = compareWaitRef.current;
        if (!pending || pending.nonce !== msg.nonce || pending.peerId !== from) return;
        clearTimeout(pending.timer);
        compareWaitRef.current = null;
        // Compare over the shorter history: the peer may not have the newest
        // message yet, and that is not a disagreement.
        const mine = await rootAt(msg.size);
        const match = mine.size === msg.size && mine.root === msg.root;
        setCompare({ state: match ? 'match' : 'mismatch', size: msg.size });
        addLog(`Transcript comparison: ${match ? 'roots match' : 'ROOTS DIFFER'} over ${msg.size} messages`, match ? 'green' : 'pink');
      }
    } catch (err) {
      addLog(`Transcript comparison failed: ${err.message}`, 'pink');
      if (compareWaitRef.current?.peerId === from) {
        clearTimeout(compareWaitRef.current.timer);
        compareWaitRef.current = null;
        setCompare({ state: 'error' });
      }
    }
  };

  const openProof = async (msg) => {
    setProofView({ proof: null, missing: false, preview: previewText(msg) });
    const proof = await transcript.proofFor(msg.id);
    setProofView(v => (v ? { ...v, proof, missing: !proof } : v));
  };

  const jumpToMessage = (id) => {
    const el = document.getElementById(`msg-${id}`);
    if (!el) {
      toast.info('That message is further back — scroll up to load it.');
      return;
    }
    setShowTranscript(false);
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.add('ring-2', 'ring-rose-400/70', 'rounded-2xl');
    setTimeout(() => el.classList.remove('ring-2', 'ring-rose-400/70', 'rounded-2xl'), 2400);
  };

  const fetchUsers = useCallback(async () => {
    try {
      const { data: raw } = await api.get(`/api/users?_t=${Date.now()}`);
      // The open chat is being read, so it never shows an unread count.
      const data = raw.map(u => (String(u.id) === String(peerRef.current?.id) ? { ...u, unread: 0 } : u));
      setUsers(data);
      usersRef.current = data;   // callers awaiting this read the ref straight away
      if (peerRef.current) {
        const refreshed = data.find(u => String(u.id) === String(peerRef.current.id));
        if (refreshed) {
          setPeer(prev => ({ ...prev, public_key: refreshed.public_key, isOnline: refreshed.isOnline, lastSeen: refreshed.lastSeen }));
        }
      }
      const savedPeer = sessionStorage.getItem('qchat_last_peer');
      if (savedPeer && !peerRestoredRef.current) {
        peerRestoredRef.current = true;
        try {
          const sp    = JSON.parse(savedPeer);
          const found = data.find(u => String(u.id) === String(sp.id));
          if (found) setPeer({ ...found, id: String(found.id) });
        } catch { }
      }
    } catch (err) {
      console.error('Failed to fetch peers', err);
    }
  }, []);

  /** A message for a chat that isn't open: count it, and surface a new sender. */
  const noteBackgroundMessage = (fromId) => {
    addLog(`New background message from ${String(fromId).slice(-6)}`, 'info');
    const known = usersRef.current.some(u => String(u.id) === String(fromId));
    if (known) {
      setUsers(prev => prev.map(u => (String(u.id) === String(fromId) ? { ...u, unread: (u.unread || 0) + 1 } : u)));
    } else {
      // A first message from someone not in the list — it used to stay
      // invisible until a reload. The refreshed list carries the unread count.
      fetchUsers();
    }
  };

  /** Decrypt one page of history rows into renderable messages. */
  const decryptRows = (rows, unreadIds) => Promise.all(rows.map(async msg => {
    const isMine = String(msg.fromId) === String(currentUser.id);
    if (!isMine && !msg.read && !msg.deleted) unreadIds?.push(msg.id);

    if (msg.deleted) return { ...msg, text: '', isMine, reactions: [] };

    const reactions = await hydrateReactions(msg.reactions);

    // v2 addresses both parties in one payload; v1 kept a separate sender copy.
    try {
      return { ...msg, reactions, text: await decryptEnvelope(msg.payload, currentUser.id, privateKey), isMine };
    } catch { /* fall through to the v1 sender copy */ }

    if (isMine && msg.senderPayload) {
      try {
        return { ...msg, reactions, text: await decryptEnvelope(msg.senderPayload, currentUser.id, privateKey), isMine: true };
      } catch { /* fall through to the placeholder */ }
    }

    return {
      ...msg, reactions, isMine, error: true,
      text: isMine ? '[Sent — previous session]' : '[Locked — previous session key]',
    };
  }));

  const loadHistory = async (peerId, { replace = false } = {}) => {
    try {
      const unreadIds = [];
      const { data } = await api.get(`/api/messages/${peerId}?limit=${PAGE_SIZE}&_t=${Date.now()}`);
      const t0 = performance.now();
      const history = await decryptRows(data, unreadIds);
      // The reader may have moved to another chat while this was in flight; a
      // late page must not land in the wrong conversation.
      if (String(peerRef.current?.id) !== String(peerId)) return;
      // Merge rather than replace: a live message that arrived during the fetch
      // is already on screen and may not be in this page.
      // With `replace`, the fetched page is the truth — anything the server no
      // longer returns is dropped, apart from sends still in flight.
      setMessages(prev => {
        const known = new Set(history.map(m => String(m.id)));
        return [...history, ...prev.filter(m => !known.has(String(m.id)) && (!replace || !isRealId(m.id)))];
      });
      if (data.length) {
        const opened = history.filter(m => !m.error).length;
        addLog(
          `Opened ${opened}/${data.length} stored message${data.length === 1 ? '' : 's'} ` +
          `in ${Math.round(performance.now() - t0)}ms`,
          'green',
        );
      }
      // A full page suggests there is more behind it; a short page is the end.
      setHasMoreHistory(data.length === PAGE_SIZE);

      if (unreadIds.length > 0 && document.hasFocus() && socketRef.current) {
        socketRef.current.emit('message_read', { messageIds: unreadIds, toId: peerId });
        setMessages(prev => prev.map(m => unreadIds.includes(m.id) ? { ...m, read: true } : m));
      }
    } catch (err) {
      addLog(`Could not load history: ${err.message}`, 'pink');
    }
  };

  const loadOlderMessages = async () => {
    const peerId = peerRef.current?.id;
    const oldest = messages[0];
    // Guard with a ref, not state: scroll fires far faster than React re-renders.
    if (!peerId || !oldest || loadingOlderRef.current || !hasMoreHistory) return;

    loadingOlderRef.current = true;
    setLoadingOlder(true);

    const box = scrollBoxRef.current;
    const prevHeight = box?.scrollHeight ?? 0;
    const prevTop    = box?.scrollTop ?? 0;

    try {
      // Cursor on the oldest loaded message rather than an offset, so live
      // arrivals can't shift the window and skip a page.
      // The id breaks ties between messages that share a millisecond.
      const before = new Date(oldest.timestamp).toISOString();
      const tie = isRealId(oldest.id) ? `&beforeId=${encodeURIComponent(oldest.id)}` : '';
      const { data } = await api.get(
        `/api/messages/${peerId}?limit=${PAGE_SIZE}&before=${encodeURIComponent(before)}${tie}`
      );
      if (String(peerRef.current?.id) !== String(peerId)) return;

      if (data.length === 0) { setHasMoreHistory(false); return; }

      const older = await decryptRows(data, null);
      if (String(peerRef.current?.id) !== String(peerId)) return;
      setMessages(prev => {
        const known = new Set(prev.map(m => String(m.id)));
        return [...older.filter(m => !known.has(String(m.id))), ...prev];
      });
      setHasMoreHistory(data.length === PAGE_SIZE);

      // Hold the reader's place: the prepended block grows scrollHeight, so
      // shift scrollTop by exactly that much.
      requestAnimationFrame(() => {
        if (box) box.scrollTop = prevTop + (box.scrollHeight - prevHeight);
      });
    } catch (err) {
      addLog(`Could not load older messages: ${err.message}`, 'pink');
    } finally {
      loadingOlderRef.current = false;
      setLoadingOlder(false);
    }
  };

  const handleMessagesScroll = (e) => {
    const box = e.currentTarget;
    const nearBottom = measureAtBottom();
    stickToBottomRef.current = nearBottom;
    setAtBottom(nearBottom);
    if (box.scrollTop < 80) loadOlderMessages();
  };

  const jumpToLatest = () => {
    stickToBottomRef.current = true;
    setAtBottom(true);
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleTyping = (e) => {
    setInput(e.target.value);
    if (!socketRef.current || !peer) return;
    socketRef.current.emit('typing', { toId: peer.id });

    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      socketRef.current?.emit('stop_typing', { toId: peer.id });
    }, 1500);
  };

  /* ─── File Attachment Logic ─── */
  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    // MVP limit to ~2MB because it goes into mongodb doc + socket payload encoded in base64.
    if (file.size > 2 * 1024 * 1024) {
      return toast.error(`"${file.name}" is ${(file.size / 1024 / 1024).toFixed(1)}MB — the limit is 2MB.`);
    }
    const reader = new FileReader();
    reader.onload = () => {
      // Audio picked from disk used to fall through to 'file' and render as an
      // unplayable generic attachment.
      const kind = file.type.startsWith('image/') ? 'image'
        : file.type.startsWith('audio/') ? 'audio'
        : 'file';
      setAttachment({ name: file.name, mime: file.type, type: kind, base64: reader.result });
      setTimeout(() => inputRef.current?.focus(), 100);
    };
    reader.readAsDataURL(file);
    e.target.value = null; // reset
  };

  /* ─── Audio Recording Logic ─── */
  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      mediaRecorderRef.current = new MediaRecorder(stream);
      audioChunksRef.current = [];
      mediaRecorderRef.current.ondataavailable = e => { if (e.data.size > 0) audioChunksRef.current.push(e.data); };
      mediaRecorderRef.current.onstop = () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        const reader = new FileReader();
        reader.onload = () => {
          setAttachment({ name: 'voice-note.webm', mime: 'audio/webm', type: 'audio', base64: reader.result });
        };
        reader.readAsDataURL(audioBlob);
        stream.getTracks().forEach(t => t.stop());
      };
      mediaRecorderRef.current.start();
      setIsRecording(true);
    } catch (err) {
      addLog('Microphone access denied', 'pink');
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
    }
  };

  const sendMessage = async (e) => {
    e?.preventDefault();
    // Pinned up front: switching chats during the encryption await used to
    // drop the bubble into the new chat while the message went to the old one.
    const target = peerRef.current;
    if ((!input.trim() && !attachment) || !target || !socketRef.current || encrypting) return;
    if (!target.public_key) {
      toast.error(`${target.username} has no encryption key yet — nothing was sent.`);
      return;
    }
    const draft = { input, attachment, replyingTo };

    // Attachments travel as an envelope so the filename/mime survive the trip.
    const textToSend = attachment
      ? packAttachment({ name: attachment.name, mime: attachment.mime, data: attachment.base64 })
      : input.trim();
    const msgType = attachment ? attachment.type : 'text';
    const currentReplyTo = replyingTo;
    // Only a server-assigned id is a valid reply target. A temp id used to be
    // sent through and failed the ObjectId cast, silently losing the message.
    const replyToId = isRealId(currentReplyTo?.id) ? currentReplyTo.id : undefined;

    // AI layer, before anything is encrypted (report Fig. 4.1): if the
    // on-device models flag the draft, stop and ask. The check runs in a
    // worker on this device, and gives up after 1.5 s rather than hold a
    // message hostage to a model that is still loading.
    if (shieldOn && msgType === 'text') {
      setEncrypting(true);
      const verdict = await analyzeMessage(textToSend, 1500, { priority: true });
      setEncrypting(false);
      if (!verdict && (shield.phishing === 'ready' || shield.toxicity === 'ready')) {
        addLog('AI shield check took over 1.5 s — sent without it', 'pink');
      }
      const parts = describeThreat(verdict);
      if (parts) {
        addLog(`AI shield flagged your draft on-device: ${parts.map(p => p.title).join(' + ')} · ${verdict.ms} ms`, 'pink');
        const send = await toast.confirm({
          title: 'The on-device AI flagged this message',
          body: parts.map(p => (p.detail?.length ? `${p.title}: ${p.detail.join('; ')}.` : `${p.title}.`)).join(' ')
            + ' Nothing has been sent, and this check never left your device.',
          confirmLabel: 'Send anyway',
          cancelLabel: 'Edit message',
          destructive: true,
        });
        if (!send) return;
      }
    }

    setInput('');
    setAttachment(null);
    setReplyingTo(null);

    socketRef.current.emit('stop_typing', { toId: target.id });
    setEncrypting(true);
    try {
      // v2: encrypt once and wrap the content key per party. v1 encrypted the
      // whole message twice, doubling both the lattice work and stored bytes.
      const recipients = buildRecipients(target);
      if (recipients.length === 0) throw new Error('NO_RECIPIENT_KEYS');
      const t0 = performance.now();
      const payload = await encryptForRecipients(textToSend, recipients);
      const ms = Math.round(performance.now() - t0);
      addLog(
        `ML-KEM-768 encapsulated to ${recipients.length} recipient${recipients.length === 1 ? '' : 's'} · ` +
        `AES-256-GCM sealed ${textToSend.length}B in ${ms}ms`,
        'green',
      );

      const tempId = `l-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      if (String(peerRef.current?.id) === String(target.id)) {
        markFresh(tempId);
        setMessages(prev => [...prev, {
          id: tempId, text: textToSend, isMine: true, timestamp: new Date(),
          delivered: false, read: false, type: msgType, replyToId,
          // Kept so this device can compute the message's Merkle leaf itself
          // once the server acks it with a real id and timestamp.
          fromId: String(currentUser.id), payload,
        }]);
      }

      socketRef.current?.emit('send_message', {
        tempId, toId: target.id, payload, type: msgType, replyToId,
      });
    } catch (err) {
      addLog(`Encryption failed: ${err.message}`, 'pink');
      toast.error('That message could not be encrypted, so it was not sent.');
      // Give the draft back instead of losing what was typed.
      if (String(peerRef.current?.id) === String(target.id)) {
        setInput(draft.input);
        setAttachment(draft.attachment);
        setReplyingTo(draft.replyingTo);
      }
    } finally {
      setEncrypting(false);
    }
  };

  /** Send a failed message again — its sealed payload is still on the bubble. */
  const retrySend = (msg) => {
    const target = peerRef.current;
    if (!target || !socketRef.current || !msg.payload) return;
    setMessages(prev => prev.map(m => (m.id === msg.id ? { ...m, sendFailed: null } : m)));
    socketRef.current.emit('send_message', {
      tempId: msg.id, toId: target.id, payload: msg.payload, type: msg.type, replyToId: msg.replyToId,
    });
  };

  const discardFailed = (id) => setMessages(prev => prev.filter(m => m.id !== id));

  const deleteMessage = async (messageId) => {
    if (!isRealId(messageId)) return toast.info('Still sending — try again in a moment.');

    const ok = await toast.confirm({
      title: 'Delete this message?',
      body: 'It will be removed for both of you. This cannot be undone.',
      confirmLabel: 'Delete',
      destructive: true,
    });
    if (!ok) return;

    socketRef.current?.emit('delete_message', { messageId });
    setMessages(prev => prev.map(m => String(m.id) === String(messageId) ? { ...m, deleted: true, text: '', type: 'text', reactions: [] } : m));
  };

  const sendReaction = async (messageId, emoji) => {
    if (!isRealId(messageId)) return addLog('Still sending — try again in a moment', 'pink');

    const target  = messages.find(m => String(m.id) === String(messageId));
    const current = target?.reactions?.find(r => String(r.user_id) === String(currentUser.id))?.emojis || [];
    const next    = current.includes(emoji) ? current.filter(e => e !== emoji) : [...current, emoji];

    // The server stores the emoji set encrypted and can't inspect it, so the
    // toggle is computed here and the whole set is sent.
    setMessages(prev => prev.map(m => String(m.id) !== String(messageId) ? m : {
      ...m,
      reactions: [
        ...(m.reactions || []).filter(r => String(r.user_id) !== String(currentUser.id)),
        ...(next.length ? [{ user_id: String(currentUser.id), emojis: next }] : []),
      ],
    }));

    try {
      const payload = next.length
        ? await encryptForRecipients(JSON.stringify(next), buildRecipients())
        : null;
      addLog(payload ? 'Reaction sealed under the thread key' : 'Reaction cleared', 'cyan');
      socketRef.current?.emit('message_reaction', { messageId, payload });
    } catch (err) {
      addLog(`Could not send reaction: ${err.message}`, 'pink');
    }
  };

  /** Everyone who should be able to read what we send: the peer and ourselves. */
  const buildRecipients = (target = peerRef.current) => {
    const stored = JSON.parse(localStorage.getItem('qchat_user') || '{}');
    const myPub = stored.publicKey || stored.public_key;
    const list = [];
    if (target?.public_key) {
      list.push({ id: String(target.id), publicKey: b64decode(target.public_key) });
    }
    if (myPub) list.push({ id: String(currentUser.id), publicKey: b64decode(myPub) });
    return list;
  };

  /** Turn stored reaction rows into { user_id, emojis } the UI can aggregate. */
  const hydrateReactions = async (rows) => Promise.all((rows || []).map(async (r) => {
    if (r.payload) {
      try {
        const emojis = JSON.parse(await decryptEnvelope(r.payload, currentUser.id, privateKey));
        return { user_id: String(r.user_id), emojis: Array.isArray(emojis) ? emojis : [] };
      } catch {
        return { user_id: String(r.user_id), emojis: [] };
      }
    }
    // Pre-v2 plaintext reaction.
    return { user_id: String(r.user_id), emojis: r.emoji ? [r.emoji] : [] };
  }));

  const copyMyId = async () => {
    if (!myProfile?.qchatId) return;
    try {
      await navigator.clipboard.writeText(myProfile.qchatId);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
      toast.success('QChat ID copied.');
    } catch {
      toast.error('Clipboard blocked by the browser — select and copy the ID manually.');
    }
  };

  const resetAddPanel = () => { setAddQuery(''); setAddError(''); setAddResult(null); };

  const findByQChatId = async (e) => {
    e?.preventDefault();
    const q = addQuery.trim();
    if (!q || addBusy) return;
    setAddBusy(true); setAddError(''); setAddResult(null);
    try {
      const { data } = await api.get(`/api/users/lookup?q=${encodeURIComponent(q)}`);
      setAddResult(data);
    } catch (err) {
      setAddError(err.response?.data?.error || 'Lookup failed');
    } finally {
      setAddBusy(false);
    }
  };

  const confirmAddContact = async () => {
    if (!addResult || addBusy) return;
    setAddBusy(true);
    try {
      const { data } = await api.post('/api/users/contacts', { userId: addResult.id });
      await fetchUsers();
      setShowAdd(false);
      resetAddPanel();
      selectPeer({ ...data, id: String(data.id) });
      toast.success(`${data.username} added to contacts.`);
    } catch (err) {
      setAddError(err.response?.data?.error || 'Could not add contact');
    } finally {
      setAddBusy(false);
    }
  };

  const removeContact = async (u, e) => {
    e.stopPropagation();

    const ok = await toast.confirm({
      title: `Remove ${u.username}?`,
      body: 'They disappear from your contacts. Your messages are kept, and they reappear if they message you again.',
      confirmLabel: 'Remove',
      destructive: true,
    });
    if (!ok) return;

    try {
      await api.delete(`/api/users/contacts/${u.id}`);
      if (peerRef.current && String(peerRef.current.id) === String(u.id)) selectPeer(null);
      await fetchUsers();
      toast.success(`${u.username} removed from contacts.`);
    } catch (err) {
      toast.error(`Could not remove contact: ${err.message}`);
    }
  };

  const clearChat = async () => {
    if (!peer) return;

    const ok = await toast.confirm({
      title: `Clear your chat with ${peer.username}?`,
      body: 'Every message in this conversation is deleted for both of you. This cannot be undone.',
      confirmLabel: 'Clear chat',
      destructive: true,
    });
    if (!ok) return;

    try {
      await api.delete(`/api/messages/${peer.id}`);
      setMessages([]);
      transcript.reset();
      toast.success('Conversation cleared.');
    } catch (err) {
      toast.error(`Could not clear chat: ${err.message}`);
    }
  };

  const handleKeyDown = e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } };
  const logout = () => {
    // Hang up first so the other side isn't left in a dead call, and clear the
    // remembered chat so the next account on this browser doesn't reopen it.
    if (callStatusRef.current !== 'idle') endCall();
    socketRef.current?.close();
    clearSession();
    navigate('/login');
  };

  // The self-view is shaped like the camera that feeds it (16:9, 4:3, or a
  // phone held upright), so nothing is cropped away.
  const localAspect = localStream?.getVideoTracks?.()[0]?.getSettings?.().aspectRatio || 4 / 3;

  const renderBubbleContent = (msg) => {
    if (msg.deleted) {
      return <div className="text-slate-400 italic flex items-center gap-1 opacity-75"><Trash size={12}/> This message was deleted</div>;
    }
    
    let content = msg.text;
    if (msg.type && msg.type !== 'text') {
      const { name, data } = unpackAttachment(msg.text);
      const src = safeDataUrl(data, msg.type === 'image' || msg.type === 'audio' ? msg.type : 'file');
      if (!src) {
        content = (
          <div className="text-xs text-amber-300/90 italic flex items-center gap-1.5 mt-1">
            <ShieldAlert size={12} /> Attachment blocked — not a recognised file format
          </div>
        );
      } else if (msg.type === 'image') {
        content = <img src={src} alt={name || 'Attachment'} className="max-w-[240px] max-h-[240px] rounded-md border border-white/10 mt-1 object-cover" />;
      } else if (msg.type === 'audio') {
        content = <audio controls src={src} className="w-[200px] h-8 outline-none mt-1" />;
      } else {
        // Previously a received file had no filename and no way to open it —
        // the decrypted bytes just sat in the bubble, unreachable.
        content = (
          <a href={src} download={name || 'qchat-attachment'}
             className="flex items-center gap-2 bg-black/20 hover:bg-black/30 transition-colors p-2 rounded-md mt-1">
            <File size={16} />
            <span className="text-xs truncate max-w-[160px]">{name || 'Secure File Attachment'}</span>
            <Download size={14} className="ml-auto opacity-70 flex-shrink-0" />
          </a>
        );
      }
    }

    // Incoming message flagged by the on-device AI. Phishing gets a warning
    // above it; abuse is blurred until the reader chooses to see it.
    const threat = !msg.isMine && threats[msg.id];
    if (threat && (!msg.type || msg.type === 'text')) {
      const abusive = threat.parts.find(p => p.kind === 'toxicity');
      const phishing = threat.parts.find(p => p.kind === 'phishing');
      const hidden = abusive && !revealed[msg.id];
      content = (
        <div className="flex flex-col gap-1.5">
          {phishing && (
            <div className="flex items-start gap-1.5 text-[11px] leading-snug rounded-lg px-2 py-1.5 bg-rose-500/15 border border-rose-400/30 text-rose-200">
              <ShieldAlert size={12} className="mt-0.5 flex-shrink-0" />
              <span>
                <b>Possible phishing</b>
                {phishing.detail.length > 0 && ` — ${phishing.detail.slice(0, 3).join('; ')}`}. Don't open links or share codes.
              </span>
            </div>
          )}
          {abusive && (
            <div className="flex items-center gap-1.5 text-[11px] rounded-lg px-2 py-1.5 bg-amber-400/10 border border-amber-400/30 text-amber-200">
              <Bot size={12} className="flex-shrink-0" />
              <span className="flex-1">{abusive.title} by on-device AI</span>
              <button
                type="button"
                onClick={() => setRevealed(prev => ({ ...prev, [msg.id]: !prev[msg.id] }))}
                className="inline-flex items-center gap-1 font-semibold text-amber-100 hover:text-white"
              >
                {hidden ? <><Eye size={11} /> Show</> : <><EyeOff size={11} /> Hide</>}
              </button>
            </div>
          )}
          <div className={hidden ? 'blur-sm select-none pointer-events-none' : ''} aria-hidden={hidden || undefined}>{content}</div>
        </div>
      );
    }

    return (
      <div className="flex flex-col relative z-10">
        {msg.replyToId && (
          <div className="text-xs bg-black/20 px-2 py-1 mb-1 rounded border-l-2 border-emerald-400 opacity-80 cursor-pointer hover:opacity-100 transition-opacity"
               onClick={() => {
                 const el = document.getElementById(`msg-${msg.replyToId}`);
                 if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
               }}>
            <span className="font-semibold text-emerald-400 block mb-0.5">Reply</span>
            <p className="truncate w-40 text-slate-300">{shieldedPreview(messages.find(m => String(m.id) === String(msg.replyToId)))}</p>
          </div>
        )}
        {content}
      </div>
    );
  };

  /** Click-toggled reaction menu. */
  const renderReactionButton = (msg, align = 'left') => {
    const open = reactionPickerFor === msg.id;
    const myEmojis = (msg.reactions || []).find(r => String(r.user_id) === String(currentUser.id))?.emojis || [];
    return (
      <div className="relative">
        <button
          type="button"
          aria-label="Add reaction"
          aria-haspopup="menu"
          aria-expanded={open}
          onClick={() => setReactionPickerFor(open ? null : msg.id)}
          className={`p-2 rounded-full transition-colors ${open
            ? 'bg-cyan-400/20 text-cyan-300'
            : 'bg-navy-800 text-slate-400 hover:text-white hover:bg-navy-700'}`}
        >
          <Smile size={14} />
        </button>

        {open && (
          <div
            role="menu"
            className={`absolute bottom-full mb-2 ${align === 'right' ? 'right-0' : 'left-0'} flex items-center gap-0.5 bg-navy-800 p-1.5 rounded-full border border-white/10 shadow-xl z-50`}
          >
            {REACTION_EMOJIS.map(em => {
              const active = myEmojis.includes(em);
              return (
                <button
                  key={em}
                  type="button"
                  role="menuitem"
                  title={active ? `Remove ${em}` : `React with ${em}`}
                  onClick={() => { sendReaction(msg.id, em); setReactionPickerFor(null); }}
                  className={`w-11 h-11 flex items-center justify-center rounded-full text-[28px] leading-none transition-transform hover:scale-125 hover:bg-white/10 ${active ? 'bg-cyan-400/20 ring-1 ring-cyan-400/40' : ''}`}
                >
                  {em}
                </button>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  /**
   * Flatten messages into render rows, inserting day separators and collapsing
   * consecutive unreadable messages. A run of twenty red bubbles reads as
   * twenty failures; it is one fact, stated once.
   */
  const renderRows = React.useMemo(() => {
    const rows = [];
    let locked = [];
    let lastDay = null;

    const flushLocked = () => {
      if (locked.length === 0) return;
      rows.push({ kind: 'locked', count: locked.length, key: `locked-${locked[0].id}` });
      locked = [];
    };

    for (const msg of messages) {
      const key = dayKey(msg.timestamp);
      if (key !== lastDay) {
        flushLocked();
        rows.push({ kind: 'day', label: dayLabel(msg.timestamp), key: `day-${key}` });
        lastDay = key;
      }
      if (msg.error && !msg.deleted) { locked.push(msg); continue; }
      flushLocked();
      rows.push({ kind: 'msg', msg, key: msg.id });
    }
    flushLocked();

    // Mark run boundaries so consecutive messages from one person read as a
    // single block: only the last gets a tail corner, a timestamp and an avatar.
    rows.forEach((row, i) => {
      if (row.kind !== 'msg') return;
      const prev = rows[i - 1];
      const next = rows[i + 1];
      row.groupStart = !(prev?.kind === 'msg' && prev.msg.isMine === row.msg.isMine);
      row.groupEnd   = !(next?.kind === 'msg' && next.msg.isMine === row.msg.isMine);
    });

    return rows;
  }, [messages]);

  const renderReactions = (msg) => {
    const reactions = msg.reactions || [];
    if (reactions.length === 0) return null;
    // Each row is one user's whole emoji set; flatten into per-emoji counts.
    const counts = {};
    for (const row of reactions) {
      for (const emoji of row.emojis || []) {
        const entry = counts[emoji] || (counts[emoji] = { count: 0, mine: false });
        entry.count++;
        if (String(row.user_id) === String(currentUser.id)) entry.mine = true;
      }
    }
    if (Object.keys(counts).length === 0) return null;
    return (
      <div className={`flex items-center gap-1 -mt-2 z-20 relative drop-shadow-md ${
        msg.isMine ? 'mr-2' : 'ml-2'
      }`}>
        {Object.entries(counts).map(([emoji, { count, mine: isMine }]) => (
          <button
            key={emoji}
            type="button"
            title={isMine ? 'Remove your reaction' : `React with ${emoji}`}
            onClick={() => sendReaction(msg.id, emoji)}
            className={`border rounded-full flex items-center gap-1 shadow-sm ring-2 ring-navy-950
                        pl-1.5 pr-1.5 py-[3px] transition-transform hover:scale-110 active:scale-95 ${isMine
              ? 'bg-cyan-400/20 border-cyan-400/40 text-cyan-200'
              : 'bg-navy-800 border-white/10 text-slate-200 hover:bg-navy-700'}`}
          >
            <span className="text-[17px] leading-none">{emoji}</span>
            {count > 1 && <span className="text-[11px] font-semibold leading-none opacity-70 pr-0.5">{count}</span>}
          </button>
        ))}
      </div>
    );
  };

  return (
    <div className="relative h-[100dvh] flex overflow-hidden bg-navy-950">
      <div className="bg-grid" />
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        <div className="orb w-[700px] h-[700px] bg-blue-900/20 -top-60 -left-40" />
        <div className="orb w-[500px] h-[500px] bg-indigo-900/15 -bottom-40 -right-20" style={{ animationDelay: '-9s' }} />
      </div>

      {/* Backdrop for the mobile drawer */}
      {sidebarOpen && (
        <div
          onClick={() => setSidebarOpen(false)}
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
          aria-hidden="true"
        />
      )}

      <aside
        className={`fixed lg:relative inset-y-0 left-0 z-40 w-72 max-w-[85vw] flex flex-col flex-shrink-0
                    glass sidebar-shell !rounded-none lg:!rounded-2xl m-0 lg:m-3 lg:mr-0
                    transition-transform duration-300 ease-out
                    ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0`}
      >
        <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-white/[0.06]">
          <div className="flex items-center gap-2.5">
            <Logo size={32} />
            <span className="font-extrabold text-sm tracking-tight">QChat</span>
          </div>
          <span className="badge-pq hidden sm:inline-flex"><Zap size={9} />PQ-Secure</span>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5"
            aria-label="Close contacts"
          >
            <X size={16} />
          </button>
        </div>
        {/* The ID you hand out so people can find you */}
        <div className="mx-3 mt-3 px-3 py-2 rounded-xl bg-white/[0.03] border border-white/[0.06]">
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mb-1">Your QChat ID</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 font-mono text-[13px] tracking-wider text-cyan-300 truncate">
              {myProfile?.qchatId || '·········'}
            </code>
            <button
              type="button" onClick={copyMyId} disabled={!myProfile?.qchatId}
              title="Copy your QChat ID"
              className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-300 hover:bg-white/5 transition-colors disabled:opacity-40"
            >
              {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
            </button>
          </div>
          <p className="text-[9px] text-slate-600 mt-1">Share this so others can add you</p>
          {keyStatus?.mine && (
            <div className="mt-2 pt-2 border-t border-white/[0.05] flex items-center gap-1.5">
              <KeyRound size={9} className={keyStatus.state === 'ok' ? 'text-emerald-400' : 'text-amber-400'} />
              <span className="text-[9px] font-mono text-slate-500 truncate" title="Fingerprint of this device's key">
                {keyStatus.mine}
              </span>
            </div>
          )}
        </div>

        {/* AI shield: what the on-device models are doing, and an off switch */}
        <div className="mx-3 mt-2 px-3 py-2 rounded-xl bg-white/[0.03] border border-white/[0.06] flex items-center gap-2.5">
          <Bot size={14} className={shieldOn ? 'text-violet-300' : 'text-slate-600'} />
          <div className="flex-1 min-w-0">
            <p className="text-[10px] font-semibold text-slate-300">On-device AI shield</p>
            <p className="text-[9px] text-slate-500 truncate" title={shield.error || ''}>
              {!shieldOn ? 'Off — messages are not scanned'
                : `Phishing ${shield.phishing === 'ready' ? '✓' : shield.phishing === 'error' ? '✗' : '…'} · `
                  + `Hate speech ${shield.toxicity === 'ready' ? '✓' : shield.toxicity === 'error' ? '✗'
                    : shield.progress ? `${shield.progress}%` : '…'}`}
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={shieldOn}
            aria-label="On-device AI shield"
            onClick={toggleShield}
            className={`relative w-8 h-[18px] rounded-full transition-colors flex-shrink-0 ${shieldOn ? 'bg-violet-500/80' : 'bg-white/10'}`}
          >
            <span className={`absolute top-[2px] w-[14px] h-[14px] rounded-full bg-white transition-all ${shieldOn ? 'left-[16px]' : 'left-[2px]'}`} />
          </button>
        </div>

        <div className="px-5 pt-3 pb-2 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Users size={11} className="text-slate-600" />
            <span className="text-[10px] font-semibold uppercase tracking-widest text-muted">
              {users.length} contact{users.length === 1 ? '' : 's'}
            </span>
          </div>
          <button
            type="button"
            onClick={() => { setShowAdd(v => !v); resetAddPanel(); }}
            title="Add someone by QChat ID"
            className={`p-1.5 rounded-lg transition-colors ${showAdd ? 'bg-cyan-400/20 text-cyan-300' : 'text-slate-400 hover:text-cyan-300 hover:bg-white/5'}`}
          >
            <UserPlus size={14} />
          </button>
        </div>

        <AnimatePresence>
          {showAdd && (
            <motion.div
              initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
              className="mx-3 mb-2 overflow-hidden"
            >
              <form onSubmit={findByQChatId} className="flex items-center gap-1.5">
                <input
                  autoFocus value={addQuery} onChange={e => setAddQuery(e.target.value)}
                  placeholder="QC-XXXX-XXXX" autoComplete="off" spellCheck="false"
                  className="field-input flex-1 !py-2 !px-3 !mb-0 !text-xs font-mono tracking-wider"
                />
                <button
                  type="submit" disabled={!addQuery.trim() || addBusy}
                  className="p-2 rounded-lg bg-cyan-400/15 text-cyan-300 hover:bg-cyan-400/25 disabled:opacity-40 transition-colors flex-shrink-0"
                >
                  {addBusy ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
                </button>
              </form>

              {addError && <p className="text-[10px] text-rose-400 mt-1.5 px-1 leading-relaxed">{addError}</p>}

              {addResult && (
                <div className="mt-2 p-2.5 rounded-xl bg-white/[0.04] border border-white/[0.08] flex items-center gap-2.5">
                  <div className={`w-8 h-8 rounded-full bg-gradient-to-br ${avatarGrad(addResult.username)} flex items-center justify-center font-bold text-xs text-white flex-shrink-0`}>
                    {addResult.username[0].toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold truncate">{addResult.username}</p>
                    <p className="text-[10px] font-mono text-slate-500 truncate">{addResult.qchatId}</p>
                  </div>
                  <button
                    type="button" onClick={confirmAddContact} disabled={addBusy}
                    className="text-[11px] font-semibold px-2.5 py-1.5 rounded-lg bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 disabled:opacity-40 transition-colors flex-shrink-0"
                  >
                    Add
                  </button>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>

        <div className="flex-1 overflow-y-auto px-2.5 pb-2 space-y-0.5">
          {users.length === 0 ? (
            <div className="px-5 py-8 text-center">
              <div className="w-12 h-12 rounded-2xl bg-white/5 flex items-center justify-center mx-auto mb-3">
                <Users size={20} className="text-slate-600" />
              </div>
              <p className="text-xs text-slate-400 font-medium">No contacts yet</p>
              <p className="text-[10px] text-slate-600 mt-1 leading-relaxed">
                Share your QChat ID above, or add someone with the + button.
              </p>
            </div>
          ) : users.map(u => (
            // A div, not a button, because the remove control nests inside it and
            // nested buttons are invalid. That costs keyboard access unless we
            // put it back by hand.
            <div
              key={u.id}
              role="button"
              tabIndex={0}
              aria-pressed={peer?.id === String(u.id)}
              aria-label={`Chat with ${u.username}${u.qchatId ? `, ${u.qchatId}` : ''}`}
              title={u.qchatId || u.username}
              onClick={() => selectPeer({ ...u, id: String(u.id) })}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  selectPeer({ ...u, id: String(u.id) });
                }
              }}
              className={`user-row w-full text-left group/row focus:outline-none focus-visible:ring-2
                          focus-visible:ring-cyan-400/60 focus-visible:ring-offset-1 focus-visible:ring-offset-navy-900
                          ${peer?.id === String(u.id) ? 'active' : ''}`}
            >
              <div className={`relative w-9 h-9 rounded-full bg-gradient-to-br ${avatarGrad(u.username)} flex items-center justify-center font-bold text-sm text-white flex-shrink-0`}>
                {u.username[0].toUpperCase()}
                {u.isOnline && <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-navy-800 shadow-glow-green" />}
              </div>
              <div className="min-w-0 flex-1">
                <p className="font-semibold text-sm truncate">{u.username}</p>
                {u.isOnline ? (
                  <p className="text-[10px] font-medium text-emerald-400/90 truncate">Online</p>
                ) : u.lastSeen ? (
                  <p className="text-[10px] text-slate-500 truncate">{formatLastSeen(u.lastSeen)}</p>
                ) : (
                  <p className="text-[10px] font-mono text-slate-500 truncate">{u.qchatId || '—'}</p>
                )}
              </div>
              {u.unread > 0 && peer?.id !== String(u.id) && (
                <span
                  className="min-w-[18px] h-[18px] px-1 rounded-full bg-cyan-400 text-navy-950 text-[10px] font-bold flex items-center justify-center flex-shrink-0"
                  aria-label={`${u.unread} unread`}
                >
                  {u.unread > 99 ? '99+' : u.unread}
                </span>
              )}
              <button
                type="button" onClick={(e) => removeContact(u, e)} title={`Remove ${u.username}`}
                className="opacity-0 group-hover/row:opacity-100 focus:opacity-100 p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-white/5 transition-all flex-shrink-0"
              >
                <X size={12} />
              </button>
            </div>
          ))}
        </div>
        <div className="px-4 py-3.5 border-t border-white/[0.06] flex items-center gap-2.5">
          <div className={`w-8 h-8 rounded-full bg-gradient-to-br ${avatarGrad(currentUser.username || '')} flex items-center justify-center font-bold text-sm text-white flex-shrink-0`}>
            {(currentUser.username || 'U')[0].toUpperCase()}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold truncate">{currentUser.username}</p>
            <p className={`text-[10px] flex items-center gap-1 ${CONN_LABELS[connStatus]?.className || 'text-slate-500'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${CONN_LABELS[connStatus]?.dot || 'bg-slate-500'}`} />
              {CONN_LABELS[connStatus]?.label || 'Unknown'}
            </p>
          </div>
          <button onClick={logout} className="btn-ghost p-2 rounded-lg" title="Log out"><LogOut size={14} /></button>
        </div>
      </aside>

      <main className="relative z-10 flex-1 min-w-0 flex flex-col glass !rounded-none lg:!rounded-2xl m-0 lg:m-3 overflow-hidden">
        {peer ? (
          <>
            <div className="chat-header-bar relative z-10 flex items-center justify-between px-3 sm:px-5 py-3 sm:py-3.5 flex-shrink-0 gap-2 sm:gap-3 backdrop-blur-md">
              <div className="flex items-center gap-2 sm:gap-3 min-w-0">
                <button
                  onClick={() => setSidebarOpen(true)}
                  className="lg:hidden p-2 -ml-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 flex-shrink-0"
                  aria-label="Open contacts"
                >
                  <Menu size={18} />
                </button>
                <div className={`relative w-9 h-9 rounded-full bg-gradient-to-br ${avatarGrad(peer.username)} flex items-center justify-center font-bold text-sm text-white flex-shrink-0`}>
                  {peer.username[0].toUpperCase()}
                </div>
                <div className="min-w-0">
                  <p className="font-bold text-base leading-tight truncate">{peer.username}</p>
                  {peerTyping ? (
                    <span className="flex items-center gap-1.5 text-cyan-400 text-xs font-medium">
                      typing
                      <span className="typing-dot !w-1 !h-1" />
                      <span className="typing-dot !w-1 !h-1" style={{ animationDelay: '0.16s' }} />
                      <span className="typing-dot !w-1 !h-1" style={{ animationDelay: '0.32s' }} />
                    </span>
                  ) : peer.isOnline ? (
                    <p className="text-[10px] text-emerald-400 font-medium">Online</p>
                  ) : (
                    <p className="text-[10px] text-slate-500">{formatLastSeen(peer.lastSeen)}</p>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <TranscriptBadge
                  status={transcript.status}
                  root={transcript.root}
                  size={transcript.size}
                  onClick={() => setShowTranscript(true)}
                />

                {/* One control group, one icon size — not three loose buttons. */}
                <div className="flex items-center gap-0.5 bg-white/[0.03] border border-white/[0.06] rounded-xl p-1">
                  {callStatus === 'idle' && (
                    <button
                      onClick={startCall} aria-label="Start secure video call" title="Secure video call"
                      className="p-2 rounded-lg text-emerald-400 hover:bg-emerald-400/10 transition-colors"
                    ><Video size={15} /></button>
                  )}
                  <button
                    onClick={() => setShowConsole(v => !v)}
                    aria-label="Toggle protocol console" aria-pressed={showConsole} title="Protocol console"
                    className={`p-2 rounded-lg transition-colors ${showConsole
                      ? 'text-cyan-300 bg-cyan-400/10'
                      : 'text-slate-500 hover:text-white hover:bg-white/[0.06]'}`}
                  ><Terminal size={15} /></button>
                  <button
                    onClick={clearChat} aria-label="Clear this conversation" title="Clear conversation"
                    className="p-2 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-400/10 transition-colors"
                  ><Trash2 size={15} /></button>
                </div>
              </div>
            </div>

            {/* WEBRTC OVERLAY */}
            <AnimatePresence>
              {callStatus !== 'idle' && (
                <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }} className="absolute inset-0 z-50 bg-navy-950/95 backdrop-blur-md flex flex-col">
                  {callStatus === 'receiving' ? (
                    <div className="flex-1 flex flex-col items-center justify-center">
                      <div className={`w-24 h-24 rounded-full bg-gradient-to-br ${avatarGrad((callPeer || peer).username)} flex items-center justify-center font-bold text-4xl text-white mb-6 animate-pulse`}>
                        {(callPeer || peer).username[0].toUpperCase()}
                      </div>
                      <h2 className="text-2xl font-bold mb-2">{(callPeer || peer).username} is calling…</h2>
                      <p className="text-cyan-400 flex items-center gap-2 mb-8"><Lock size={14}/> ML-KEM-768 Secured</p>
                      <div className="flex gap-6">
                        <button onClick={declineCall} aria-label="Decline call" className="w-14 h-14 rounded-full bg-rose-500 hover:bg-rose-600 flex items-center justify-center shadow-lg shadow-rose-500/20"><PhoneOff size={24} className="text-white"/></button>
                        <button onClick={acceptCall} aria-label="Accept call" className="w-14 h-14 rounded-full bg-emerald-500 hover:bg-emerald-600 flex items-center justify-center shadow-lg shadow-emerald-500/20"><Video size={24} className="text-white"/></button>
                      </div>
                    </div>
                  ) : (
                    // min-h-0 and an absolutely placed <video> keep the stage the size of
                    // the pane. As a plain flex child the video's intrinsic height set the
                    // stage's minimum, so a 4:3 camera pushed the controls off the bottom.
                    <div className="relative flex-1 min-h-0 bg-black overflow-hidden">
                      {/* contain, not cover: the whole frame is shown, letterboxed if
                          needed, instead of a cropped close-up of the middle. */}
                      <video ref={remoteVideoRef} autoPlay playsInline className="absolute inset-0 w-full h-full object-contain" />
                      {!remoteStream && (
                        <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-slate-400">
                          <Loader2 size={22} className="animate-spin text-cyan-400" />
                          <p className="text-sm">
                            {callStatus === 'calling' ? `Calling ${(callPeer || peer).username}…` : 'Connecting…'}
                          </p>
                        </div>
                      )}

                      {/* Self-view follows the camera's own shape and is mirrored, like
                          every call app, instead of a portrait box cropping a landscape feed. */}
                      <div
                        className="absolute top-4 right-4 z-10 w-28 sm:w-40 md:w-52 bg-navy-900 rounded-xl overflow-hidden shadow-2xl border border-white/15"
                        style={{ aspectRatio: localAspect }}
                      >
                        <video ref={localVideoRef} autoPlay playsInline muted className="w-full h-full object-cover [transform:scaleX(-1)]" />
                        {isVideoOff && (
                          <div className="absolute inset-0 flex items-center justify-center bg-navy-900 text-slate-500">
                            <VideoOff size={18} />
                          </div>
                        )}
                      </div>

                      {mediaProtection && (
                        <div className={`absolute top-4 left-4 z-10 max-w-[calc(100%-10rem)] sm:max-w-[calc(100%-13rem)] flex items-center gap-2 px-3 py-1.5 rounded-full text-[11px] font-semibold bg-navy-950/75 backdrop-blur-md border shadow-lg ${
                          mediaProtection === 'pq'
                            ? 'border-emerald-400/40 text-emerald-300'
                            : mediaProtection === 'pending'
                            ? 'border-cyan-400/40 text-cyan-300'
                            : 'border-amber-400/40 text-amber-300'
                        }`}>
                          <Lock size={11} className="flex-shrink-0" />
                          <span className="truncate">
                            {mediaProtection === 'pq'
                              ? 'Video sealed · ML-KEM-768 + AES-256-GCM'
                              : mediaProtection === 'pending'
                              ? 'Negotiating sealed media…'
                              : 'Video on DTLS-SRTP only — not quantum-safe'}
                          </span>
                        </div>
                      )}

                      <div className="absolute inset-x-0 bottom-5 z-10 flex justify-center pointer-events-none">
                      <div className="pointer-events-auto flex items-center gap-4 bg-navy-950/75 backdrop-blur-lg px-5 py-2.5 rounded-full border border-white/10 shadow-xl">
                        <button onClick={toggleMute} aria-label={isMuted ? 'Unmute' : 'Mute'} className={`p-3 rounded-full ${isMuted ? 'bg-rose-500/20 text-rose-500' : 'bg-white/10 text-white hover:bg-white/20'}`}>
                          {isMuted ? <MicOff size={20}/> : <Mic size={20}/>}
                        </button>
                        <button onClick={toggleVideo} aria-label={isVideoOff ? 'Turn camera on' : 'Turn camera off'} className={`p-3 rounded-full ${isVideoOff ? 'bg-rose-500/20 text-rose-500' : 'bg-white/10 text-white hover:bg-white/20'}`}>
                          {isVideoOff ? <VideoOff size={20}/> : <Video size={20}/>}
                        </button>
                        <button onClick={endCall} aria-label="End call" className="p-3 rounded-full bg-rose-500 text-white hover:bg-rose-600 shadow-lg shadow-rose-500/20">
                          <PhoneOff size={20}/>
                        </button>
                      </div>
                      </div>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>

            {/* The backdrop belongs to the message region, so it is sized to
                it — not stretched across the header and console as well. It
                stays outside the scroll container: in the scroll flow it added
                its own height and produced a phantom gap under the messages. */}
            <div className="relative flex-1 min-h-0 flex flex-col">
              <div className="absolute inset-0 z-0 overflow-hidden pointer-events-none" aria-hidden="true">
                <div className="chat-ambient absolute inset-0" />
                <LatticeField className="lattice-ambient" />
                <div className="canvas-breathe" />
              </div>

            <div ref={scrollBoxRef} onScroll={handleMessagesScroll} className="relative z-10 flex-1 min-h-0 overflow-y-auto px-3 sm:px-4 py-4 sm:py-5">
              <div className="relative z-10 flex flex-col">
                {loadingOlder && (
                  <div className="flex items-center justify-center gap-2 py-2 text-[10px] text-slate-500">
                    <Loader2 size={11} className="animate-spin" /> Loading older messages…
                  </div>
                )}
                {hasMoreHistory && !loadingOlder && (
                  <button
                    type="button" onClick={loadOlderMessages}
                    className="mx-auto text-[10px] text-slate-500 hover:text-cyan-300 px-3 py-1 rounded-full border border-white/10 hover:border-cyan-400/30 transition-colors"
                  >
                    Load older messages
                  </button>
                )}
                {keyStatus && keyStatus.state !== 'ok' && (
                  <div className="mx-auto mb-2 max-w-lg glass-sm !border-amber-500/25 p-4 flex items-start gap-3">
                    <ShieldAlert size={16} className="text-amber-400 flex-shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      {keyStatus.state === 'missing' && (
                        <>
                          <p className="text-[13px] font-semibold text-amber-300 mb-1">No private key on this device</p>
                          <p className="text-xs text-sub leading-relaxed">
                            Nothing can be decrypted here. Sign out and back in to generate a
                            keypair — anything sent to your previous key stays unreadable.
                          </p>
                        </>
                      )}

                      {keyStatus.state === 'mismatch' && (
                        <>
                          <p className="text-[13px] font-semibold text-amber-300 mb-1">This device holds a different key</p>
                          <p className="text-xs text-sub leading-relaxed mb-2.5">
                            Your account advertises one public key, but this browser stores a
                            different one — so messages encrypted to the account key cannot be
                            opened here. This happens when a keypair is regenerated, which
                            signing in without a stored key will do.
                          </p>
                          <div className="grid grid-cols-[auto,1fr] gap-x-3 gap-y-1 text-[11px] font-mono">
                            <span className="text-slate-500">this device</span>
                            <span className="text-slate-300">{keyStatus.mine}</span>
                            <span className="text-slate-500">account</span>
                            <span className="text-slate-300">{keyStatus.server}</span>
                          </div>
                        </>
                      )}

                      {keyStatus.state === 'invalid' && (
                        <>
                          <p className="text-[13px] font-semibold text-amber-300 mb-1">Stored key is unreadable</p>
                          <p className="text-xs text-sub leading-relaxed">
                            The private key in this browser is not a valid ML-KEM-768 key.
                            Sign out and back in to generate a fresh one.
                          </p>
                        </>
                      )}
                    </div>
                  </div>
                )}

                {!hasMoreHistory && messages.length > 0 && (
                  <div className="text-center text-[10px] text-slate-600 pt-2 pb-0">
                    Beginning of your encrypted conversation
                  </div>
                )}

                {messages.length === 0 && !loadingOlder && (
                  <div className="flex flex-col items-center justify-center py-16 text-center">
                    <Logo size={44} className="mb-4 opacity-30" withGlow={false} />
                    <p className="text-sm text-slate-400 font-medium">No messages yet</p>
                    <p className="text-xs text-slate-600 mt-1.5 max-w-[15rem] leading-relaxed">
                      Say something to {peer.username}. It is encrypted on this device before it leaves.
                    </p>
                  </div>
                )}
                <AnimatePresence initial={false}>
                  {renderRows.map((row, i) => {
                    if (row.kind === 'day') {
                      return (
                        <div key={row.key} className="flex items-center justify-center mt-6 mb-2 pointer-events-none">
                          <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400
                                           bg-navy-900/90 backdrop-blur-md border border-white/[0.08]
                                           shadow-lg shadow-black/30 px-3 py-1 rounded-full">
                            {row.label}
                          </span>
                        </div>
                      );
                    }

                    if (row.kind === 'locked') {
                      return (
                        <div key={row.key} className="flex items-center justify-center my-4">
                          <div
                            className="flex items-center gap-2 text-[11px] text-slate-500 bg-white/[0.03] border border-white/[0.07] px-3 py-1.5 rounded-full"
                            title="These were encrypted to a key this device no longer holds. Generating a new keypair — by signing in on a new device or after clearing site data — makes older messages unreadable here."
                          >
                            <KeyRound size={11} className="text-slate-500" />
                            {row.count === 1 ? '1 message' : `${row.count} messages`} encrypted to an earlier key
                          </div>
                        </div>
                      );
                    }

                    const msg = row.msg;
                    const isGrouped = !row.groupStart;
                    // A separator directly above already supplies the gap, so
                    // the row must not stack its own on top of it.
                    const afterBreak = renderRows[i - 1] && renderRows[i - 1].kind !== 'msg';

                    // Hover actions, built once and placed inboard of the bubble on
                    // either side, so they never collide with the window edge.
                    const actions = msg.deleted || msg.error || msg.sendFailed ? null : (
                      <div
                        data-reaction-ui
                        className={`flex items-center gap-1 self-center transition-opacity duration-150 ${
                          reactionPickerFor === msg.id
                            ? 'opacity-100'
                            : 'opacity-0 group-hover:opacity-100 focus-within:opacity-100'
                        }`}
                      >
                        {msg.isMine && (
                          <button
                            type="button"
                            title="Delete message"
                            aria-label="Delete message"
                            onClick={() => deleteMessage(msg.id)}
                            className="p-2 rounded-full bg-navy-800 text-slate-400 hover:text-rose-400 hover:bg-navy-700 transition-colors"
                          >
                            <Trash size={14} />
                          </button>
                        )}
                        {isRealId(msg.id) && (
                          <button
                            type="button"
                            title="Verify in the Merkle tree"
                            aria-label="Verify this message in the Merkle tree"
                            onClick={() => openProof(msg)}
                            className="p-2 rounded-full bg-navy-800 text-slate-400 hover:text-emerald-300 hover:bg-navy-700 transition-colors"
                          >
                            <ShieldCheck size={14} />
                          </button>
                        )}
                        {renderReactionButton(msg, msg.isMine ? 'right' : 'left')}
                        <button
                          type="button"
                          title="Reply"
                          aria-label="Reply to message"
                          onClick={() => setReplyingTo(msg)}
                          className="p-2 rounded-full bg-navy-800 text-slate-400 hover:text-white hover:bg-navy-700 transition-colors"
                        >
                          <Reply size={14} />
                        </button>
                      </div>
                    );

                    return (
                      <motion.div
                        id={`msg-${msg.id}`}
                        key={row.key || i}
                        className={`flex items-end gap-2 group ${msg.isMine ? 'justify-end' : 'justify-start'} ${afterBreak ? 'mt-0' : isGrouped ? 'mt-[3px]' : 'mt-4'}`}
                        initial={{ opacity: 0, y: 8, x: msg.isMine ? 10 : -10 }}
                        animate={{ opacity: 1, y: 0, x: 0 }}
                        transition={{ type: 'spring', stiffness: 380, damping: 30 }}
                      >
                        
                        {/* Avatar anchors the end of a received run */}
                        {!msg.isMine && (
                          row.groupEnd ? (
                            <div className={`w-7 h-7 rounded-full bg-gradient-to-br ${avatarGrad(peer.username)} flex items-center justify-center text-[11px] font-bold text-white flex-shrink-0 self-end mb-1`}>
                              {peer.username[0].toUpperCase()}
                            </div>
                          ) : <div className="w-7 flex-shrink-0" aria-hidden="true" />
                        )}

                        {/* Your own actions sit inboard of the bubble, not at the screen edge */}
                        {msg.isMine && actions}

                        <div className={`flex flex-col max-w-[82%] sm:max-w-[68%] ${msg.isMine ? 'items-end' : 'items-start'}`}>
                          <div className={[
                            msg.isMine ? 'bubble-mine' : 'bubble-theirs',
                            row.groupEnd ? (msg.isMine ? 'bubble-tail-mine' : 'bubble-tail-theirs') : '',
                            msg.error || msg.sendFailed ? 'bubble-error' : '',
                            freshIdsRef.current.has(String(msg.id)) ? 'bubble-arrive' : '',
                          ].filter(Boolean).join(' ')}>
                            {renderBubbleContent(msg)}
                          </div>

                          {renderReactions(msg)}

                          {msg.sendFailed ? (
                            <div className="flex items-center gap-2 px-1 mt-1 text-[10px] font-semibold text-rose-300">
                              <ShieldAlert size={11} />
                              {msg.sendFailed === 'PAYLOAD_TOO_LARGE' ? 'Not sent — attachment too large' : 'Not sent'}
                              {msg.sendFailed !== 'PAYLOAD_TOO_LARGE' && msg.payload && (
                                <button type="button" onClick={() => retrySend(msg)} className="text-cyan-300 hover:text-cyan-200">Retry</button>
                              )}
                              <button type="button" onClick={() => discardFailed(msg.id)} className="text-slate-400 hover:text-slate-200">Discard</button>
                            </div>
                          ) : row.groupEnd && (
                            <div className={`flex items-center gap-1 px-1 ${msg.reactions?.length ? 'mt-1.5' : 'mt-1'}`}>
                              <span className="text-[10px] text-muted font-mono">{fmt(msg.timestamp)}</span>
                              {msg.isMine && !msg.deleted && (
                                msg.read ? <CheckCheck size={12} className="text-cyan-400" /> :
                                msg.delivered ? <CheckCheck size={12} className="text-slate-400" /> :
                                <Check size={12} className="text-slate-500" />
                              )}
                            </div>
                          )}
                        </div>

                        {!msg.isMine && actions}

                      </motion.div>
                    );
                  })}
                </AnimatePresence>
                {peerTyping && (
                  <motion.div
                    initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
                    className="flex items-end gap-2 justify-start mt-3"
                  >
                    <div className={`w-7 h-7 rounded-full bg-gradient-to-br ${avatarGrad(peer.username)} flex items-center justify-center text-[11px] font-bold text-white flex-shrink-0`}>
                      {peer.username[0].toUpperCase()}
                    </div>
                    <div className="bubble-theirs bubble-tail-theirs flex items-center gap-1 !py-3">
                      <span className="typing-dot" />
                      <span className="typing-dot" style={{ animationDelay: '0.16s' }} />
                      <span className="typing-dot" style={{ animationDelay: '0.32s' }} />
                    </div>
                  </motion.div>
                )}

                <div ref={bottomRef} />
              </div>
            </div>

            {/* Inside the message region, so `bottom` is measured from the top
                of the composer — no magic offsets to dodge the console. */}
            <div className="absolute inset-x-0 bottom-4 z-20 flex justify-center pointer-events-none">
              <AnimatePresence>
                {!atBottom && (
                  <motion.button
                    type="button" onClick={jumpToLatest}
                    initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 8 }}
                    className="jump-latest pointer-events-auto"
                  >
                    <ArrowDown size={12} /> Jump to latest
                  </motion.button>
                )}
              </AnimatePresence>
            </div>
            </div>


            {/* Input Area */}
            <div className="composer-bar composer-glow relative px-3 sm:px-4 py-3 sm:py-3.5 flex-shrink-0 backdrop-blur-md z-10 pb-[max(0.75rem,env(safe-area-inset-bottom))]">
              
              {replyingTo && (
                <div className="mb-2 flex items-center justify-between bg-black/40 p-2 rounded-lg border-l-4 border-emerald-400">
                  <div className="flex flex-col overflow-hidden">
                    <span className="text-xs font-semibold text-emerald-400">Replying to {replyingTo.isMine ? 'yourself' : peer.username}</span>
                    <span className="text-xs text-slate-300 truncate">{shieldedPreview(replyingTo)}</span>
                  </div>
                  <button onClick={() => setReplyingTo(null)} className="text-slate-400 hover:text-white"><X size={14}/></button>
                </div>
              )}

              {attachment && (
                <div className="mb-2 flex items-center justify-between bg-black/40 p-2 rounded-lg border border-white/10">
                  <div className="flex items-center gap-2">
                    {attachment.type === 'image' ? <img src={attachment.base64} className="w-10 h-10 object-cover rounded" alt="Preview"/> : <File size={20} className="text-slate-400"/>}
                    <span className="text-xs text-slate-300 truncate max-w-[200px]">{attachment.name}</span>
                  </div>
                  <button onClick={() => setAttachment(null)} className="text-slate-400 hover:text-white"><X size={14}/></button>
                </div>
              )}

              <form onSubmit={sendMessage} className="flex items-center gap-3">
                <input type="file" ref={fileInputRef} onChange={handleFileChange} className="hidden" accept="image/*, audio/*, .pdf, .txt" />
                <button type="button" onClick={() => fileInputRef.current?.click()} className="p-2 text-slate-400 hover:text-white rounded-full hover:bg-white/5 transition-colors">
                  <Paperclip size={20} />
                </button>
                
                <input ref={inputRef} className="field-input flex-1 !rounded-full !py-2.5 !px-5 !mb-0 bg-navy-900 border-white/10 transition-colors" 
                       type="text" placeholder={attachment ? "Add a caption..." : "Type a message..."} 
                       value={input} onChange={handleTyping} onKeyDown={handleKeyDown} disabled={encrypting || isRecording} autoComplete="off" />
                
                {input.trim() || attachment ? (
                  <motion.button
                    type="submit" disabled={encrypting}
                    initial={{ scale: 0.85, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
                    transition={{ type: 'spring', stiffness: 500, damping: 24 }}
                    whileTap={{ scale: 0.92 }}
                    className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-400 to-blue-500 flex items-center justify-center text-navy-950 shadow-glow-cyan-sm hover:shadow-glow-cyan transition-shadow flex-shrink-0 disabled:opacity-50"
                  >
                    <Send size={17} className="ml-0.5" />
                  </motion.button>
                ) : isRecording ? (
                  <button type="button" onClick={stopRecording} className="w-10 h-10 rounded-full bg-rose-500 hover:bg-rose-600 flex items-center justify-center text-white shadow-lg shadow-rose-500/20 animate-pulse">
                    <StopCircle size={20} />
                  </button>
                ) : (
                  <button type="button" onClick={startRecording} aria-label="Record a voice note" className="w-10 h-10 rounded-full bg-navy-800 hover:bg-navy-700 hover:text-cyan-300 flex items-center justify-center text-slate-300 transition-all hover:scale-105 flex-shrink-0">
                    <Mic size={19} />
                  </button>
                )}
              </form>
            </div>
            
            <AnimatePresence>
              {showConsole && (
                <motion.div initial={{ height: 0 }} animate={{ height: 144 }} exit={{ height: 0 }} className="relative z-10 flex-shrink-0 border-t border-white/[0.06] bg-navy-950/70 backdrop-blur-md overflow-hidden">
                  <div className="flex items-center gap-2 px-3.5 py-2 border-b border-white/[0.05]">
                    <Terminal size={11} className="text-slate-600" />
                    <span className="text-[10px] font-semibold tracking-widest uppercase text-slate-600">Quantum Protocol Stream</span>
                  </div>
                  <div className="h-[88px] overflow-y-auto px-3.5 py-2 space-y-0.5">
                    {logs.map((l, i) => (
                      <div key={i} className="console-line"><span className="text-slate-600">[{l.t}]</span> <span className={l.type === 'green' ? 'text-emerald-400' : l.type === 'cyan' ? 'text-cyan-400' : 'text-slate-400'}>{l.msg}</span></div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </>
        ) : (
          <div className="h-full flex flex-col items-center justify-center px-6 text-center">
            <Logo size={56} className="mb-4 opacity-40" withGlow={false} />
            <p className="text-sm text-slate-400">Select a contact to start a quantum-secure chat</p>
            <button
              onClick={() => setSidebarOpen(true)}
              className="btn-ghost mt-5 lg:hidden"
            >
              <Menu size={14} /> Open contacts
            </button>
          </div>
        )}
      </main>

      {peer && (
        <TranscriptPanel
          open={showTranscript}
          onClose={() => setShowTranscript(false)}
          tree={transcript}
          peerName={peer.username}
          onCompare={compareWithPeer}
          compare={compare}
          onAccept={async () => { await transcript.acceptCurrent(); toast.success('Current history accepted as the new checkpoint.'); }}
          onJump={jumpToMessage}
          demo={demo ? {
            attacks: demo.attacks,
            targets: attackTargets,
            onAttack: runAttack,
            onRestore: restoreAttacks,
            busy: attackBusy,
          } : null}
        />
      )}
      <ProofDialog
        open={!!proofView}
        onClose={() => setProofView(null)}
        proof={proofView?.proof}
        missing={proofView?.missing}
        preview={proofView?.preview}
      />
    </div>
  );
}
