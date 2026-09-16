import React, { useState, useEffect, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import { useNavigate } from 'react-router-dom';
import api, { SOCKET_URL, clearSession } from '../lib/api';
import { encryptMessage, decryptMessage, b64decode, calculateIntegrity } from '../crypto/encryption';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Send, Terminal, LogOut, Lock, Fingerprint,
  Users, Zap, ShieldCheck, Trash2, Video, PhoneOff, Mic, MicOff, VideoOff, Check, CheckCheck,
  Paperclip, X, Reply, Smile, File, StopCircle, Trash, Download,
  Copy, UserPlus, Search, Loader2
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

/* ─── Format timestamp ─── */
const fmt = ts => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const formatLastSeen = ts => {
  if (!ts) return '';
  const d = new Date(ts);
  const today = new Date();
  if (d.toDateString() === today.toDateString()) return `Last seen today at ${fmt(ts)}`;
  return `Last seen ${d.toLocaleDateString()} at ${fmt(ts)}`;
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
  const currentUser   = JSON.parse(localStorage.getItem('qchat_user') || '{}');
  const privateKeyB64 = currentUser.id ? localStorage.getItem(`qchat_priv_${currentUser.id}`) : null;
  const privateKey    = privateKeyB64 ? b64decode(privateKeyB64) : null;

  const socketRef = useRef(null);
  const [users, setUsers]               = useState([]);
  const [peer, setPeer]                 = useState(null);
  const [messages, setMessages]         = useState([]);
  const [input, setInput]               = useState('');
  const [logs, setLogs]                 = useState([]);
  const [encrypting, setEncrypting]     = useState(false);
  const [showConsole, setShowConsole]   = useState(true);
  const [integrity, setIntegrity]       = useState(null);
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
  const scrollBoxRef      = useRef(null);
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

  /* Persist selected peer across refreshes */
  const selectPeer = (u) => {
    setPeer(u);
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

  const addLog = useCallback((msg, type = 'info') => {
    const t = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setLogs(prev => [...prev, { msg, type, t }].slice(-25));
  }, []);

  /* ─── WebRTC Logic ─── */
  const rtcConfig = { iceServers: ICE_SERVERS };

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

  const encryptAndSendSignal = async (signalData, toId) => {
    try {
      if (!peerRef.current?.public_key) return;
      const recipientPubKey = b64decode(peerRef.current.public_key);
      const payload = await encryptMessage(JSON.stringify(signalData), recipientPubKey);
      socketRef.current?.emit('webrtc_signal', { toId, signalPayload: payload });
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

      const pc = new RTCPeerConnection(rtcConfig);
      rtcPeerConnection.current = pc;

      stream.getTracks().forEach(track => pc.addTrack(track, stream));

      pc.ontrack = (event) => {
        setRemoteStream(event.streams[0]);
        if (remoteVideoRef.current) remoteVideoRef.current.srcObject = event.streams[0];
      };

      pc.onicecandidate = (event) => {
        if (event.candidate && peerRef.current) {
          encryptAndSendSignal({ type: 'candidate', candidate: event.candidate }, peerRef.current.id);
        }
      };

      if (isInitiator) {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        encryptAndSendSignal({ type: 'offer', sdp: offer }, peerRef.current.id);
        setCallStatus('calling');
      }
    } catch (err) {
      addLog(`WebRTC Init failed: ${err.message}`, 'pink');
      setCallStatus('idle');
    }
  };

  const handleWebRTCSignal = async (fromId, signalPayload) => {
    try {
      const decrypted = await decryptMessage(signalPayload, privateKey);
      const signal = JSON.parse(decrypted);
      addLog(`Received encrypted WebRTC signal (${signal.type || 'candidate'})`, 'green');

      if (signal.type === 'offer') {
        if (peerRef.current && String(peerRef.current.id) === String(fromId)) {
          callPayloadRef.current = signal;
          setCallStatus('receiving');
        } else {
          addLog(`Missed call from ${fromId} (not in active chat)`, 'pink');
        }
      } else if (signal.type === 'answer') {
        if (rtcPeerConnection.current) {
          await rtcPeerConnection.current.setRemoteDescription(new RTCSessionDescription(signal.sdp));
          await flushPendingCandidates();
          setCallStatus('connected');
        }
      } else if (signal.type === 'candidate') {
        const pc = rtcPeerConnection.current;
        // A candidate that arrives before the remote description is set throws
        // and is lost, which can leave the call stuck connecting. Queue instead.
        if (pc?.remoteDescription?.type) {
          await pc.addIceCandidate(new RTCIceCandidate(signal.candidate));
        } else {
          pendingCandidatesRef.current.push(signal.candidate);
        }
      } else if (signal.type === 'end_call') {
        cleanupCall();
      }
    } catch (err) {
      addLog(`Failed to process WebRTC signal: ${err.message}`, 'pink');
    }
  };

  const startCall = () => {
    if (!peer) return;
    initWebRTC(true);
  };

  const acceptCall = async () => {
    await initWebRTC(false);
    const pc = rtcPeerConnection.current;
    if (pc && callPayloadRef.current) {
      await pc.setRemoteDescription(new RTCSessionDescription(callPayloadRef.current.sdp));
      await flushPendingCandidates();
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      encryptAndSendSignal({ type: 'answer', sdp: answer }, peerRef.current.id);
      setCallStatus('connected');
      callPayloadRef.current = null;
    }
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

  const cleanupCall = () => {
    // Capture is released before closing the connection, so a throw while
    // closing can never strand a live camera.
    const stopped = stopLocalCapture();

    if (rtcPeerConnection.current) {
      try { rtcPeerConnection.current.close(); } catch { /* already closed */ }
      rtcPeerConnection.current = null;
    }

    setLocalStream(null);
    setRemoteStream(null);
    pendingCandidatesRef.current = [];
    callPayloadRef.current = null;
    setCallStatus('idle');
    setIsMuted(false);
    setIsVideoOff(false);
    addLog(`Call ended — released ${stopped} media track(s)`, 'cyan');
  };

  const endCall = () => {
    if (peerRef.current) encryptAndSendSignal({ type: 'end_call' }, peerRef.current.id);
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

    const localPub = localStorage.getItem(`qchat_pub_${currentUser.id}`);
    if (localPub) {
      api.post('/api/auth/update-key', { userId: currentUser.id, publicKey: localPub })
        .catch(err => addLog(`Key sync failed: ${err.message}`, 'pink'));
    }

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
        const text = await decryptMessage(msg.payload, privateKey);
        
        if (peerRef.current && String(peerRef.current.id) === String(msg.fromId)) {
          setMessages(prev => {
            if (prev.some(m => String(m.id) === String(msg.id))) return prev;
            return [...prev, { ...msg, text, isMine: false }];
          });
          // Send read receipt if we are actively viewing this chat
          if (document.hasFocus()) {
            s.emit('message_read', { messageIds: [msg.id], toId: msg.fromId });
          }
        } else {
          addLog(`New background message from ${String(msg.fromId).slice(-6)}`, 'info');
        }
      } catch {
        if (peerRef.current && String(peerRef.current.id) === String(msg.fromId)) {
          setMessages(prev => {
            if (prev.some(m => String(m.id) === String(msg.id))) return prev;
            return [...prev, { ...msg, text: '[Locked — previous session key]', isMine: false, error: true }];
          });
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
      setMessages(prev => prev.map(m => String(m.id) === String(messageId) ? { ...m, deleted: true, text: '', type: 'text' } : m));
    });

    // The server toggles and returns the authoritative array. Replacing rather
    // than appending is what stops your own reaction counting twice — once
    // optimistically, then again when the echo comes back.
    s.on('message_reaction', ({ messageId, reactions }) => {
      setMessages(prev => prev.map(m =>
        String(m.id) === String(messageId) ? { ...m, reactions: reactions || [] } : m
      ));
    });

    // Swap the optimistic temp id for the server's real one, so delivery ticks,
    // read receipts, deletes, reactions and replies all work on a fresh message.
    s.on('message_sent', ({ tempId, id, timestamp, delivered }) => {
      if (!tempId) return;
      setMessages(prev => prev.map(m =>
        String(m.id) === String(tempId)
          ? { ...m, id, timestamp: timestamp || m.timestamp, delivered: !!delivered }
          : m
      ));
    });

    s.on('message_error', ({ tempId, error }) => {
      addLog(`Message rejected: ${error}`, 'pink');
      setMessages(prev => prev.map(m =>
        String(m.id) === String(tempId)
          ? { ...m, error: true, text: error === 'PAYLOAD_TOO_LARGE' ? '[Not sent — attachment too large]' : '[Not sent]' }
          : m
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
        setMessages([]); setIntegrity(null);
      }
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
    setMessages([]); setIntegrity(null); setPeerTyping(false);
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

  /* ─── Scroll + integrity on message update ─── */
  useEffect(() => {
    // Only follow new messages when the reader is already at the bottom.
    if (stickToBottomRef.current) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, peerTyping]);

  // Integrity depends only on the message chain. Recomputing it on replyingTo
  // also scroll-jumped the view every time a reply was picked.
  useEffect(() => {
    const ok = messages.filter(m => !m.error && !m.deleted);
    if (ok.length) calculateIntegrity(ok).then(setIntegrity).catch(() => setIntegrity(null));
    else setIntegrity(null);
  }, [messages]);

  const fetchUsers = useCallback(async () => {
    try {
      const { data } = await api.get(`/api/users?_t=${Date.now()}`);
      setUsers(data);
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

  /** Decrypt one page of history rows into renderable messages. */
  const decryptRows = (rows, unreadIds) => Promise.all(rows.map(async msg => {
    const isMine = String(msg.fromId) === String(currentUser.id);
    if (!isMine && !msg.read && !msg.deleted) unreadIds?.push(msg.id);

    if (msg.deleted) return { ...msg, text: '', isMine };

    if (isMine) {
      if (msg.senderPayload) {
        try {
          return { ...msg, text: await decryptMessage(msg.senderPayload, privateKey), isMine: true };
        } catch { /* fall through to the placeholder */ }
      }
      return { ...msg, text: '[Sent — previous session]', isMine: true, error: true };
    }
    try {
      return { ...msg, text: await decryptMessage(msg.payload, privateKey), isMine: false };
    } catch {
      return { ...msg, text: '[Locked — previous session key]', isMine: false, error: true };
    }
  }));

  const loadHistory = async (peerId) => {
    try {
      const unreadIds = [];
      const { data } = await api.get(`/api/messages/${peerId}?limit=${PAGE_SIZE}&_t=${Date.now()}`);
      const history = await decryptRows(data, unreadIds);
      setMessages(history);
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
      const before = new Date(oldest.timestamp).toISOString();
      const { data } = await api.get(
        `/api/messages/${peerId}?limit=${PAGE_SIZE}&before=${encodeURIComponent(before)}`
      );

      if (data.length === 0) { setHasMoreHistory(false); return; }

      const older = await decryptRows(data, null);
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
    stickToBottomRef.current = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
    if (box.scrollTop < 80) loadOlderMessages();
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
    if (file.size > 2 * 1024 * 1024) return alert('File too large (max 2MB for MVP).');
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
    if ((!input.trim() && !attachment) || !peer || !socketRef.current || encrypting) return;
    
    // Attachments travel as an envelope so the filename/mime survive the trip.
    const textToSend = attachment
      ? packAttachment({ name: attachment.name, mime: attachment.mime, data: attachment.base64 })
      : input.trim();
    const msgType = attachment ? attachment.type : 'text';
    const currentReplyTo = replyingTo;
    // Only a server-assigned id is a valid reply target. A temp id used to be
    // sent through and failed the ObjectId cast, silently losing the message.
    const replyToId = isRealId(currentReplyTo?.id) ? currentReplyTo.id : undefined;

    setInput('');
    setAttachment(null);
    setReplyingTo(null);

    socketRef.current.emit('stop_typing', { toId: peer.id });
    setEncrypting(true);
    try {
      const recipientPubKey = b64decode(peer.public_key);
      const payload = await encryptMessage(textToSend, recipientPubKey);
      let senderPayload = null;
      const parsedUser = JSON.parse(localStorage.getItem('qchat_user') || '{}');
      const myPubKeyB64 = parsedUser.publicKey || parsedUser.public_key;
      if (myPubKeyB64) {
        senderPayload = await encryptMessage(textToSend, b64decode(myPubKeyB64));
      }
      
      const tempId = `l-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      setMessages(prev => [...prev, {
        id: tempId, text: textToSend, isMine: true, timestamp: new Date(),
        delivered: false, read: false, type: msgType, replyToId
      }]);

      socketRef.current?.emit('send_message', {
        tempId, toId: peer.id, payload, senderPayload,
        type: msgType, replyToId
      });
    } catch (err) {
      addLog(`Encryption failed: ${err.message}`, 'pink');
    } finally {
      setEncrypting(false);
    }
  };

  const deleteMessage = (messageId) => {
    if (!isRealId(messageId)) return addLog('Still sending — try again in a moment', 'pink');
    if (!window.confirm("Delete this message for everyone?")) return;
    socketRef.current?.emit('delete_message', { messageId });
    setMessages(prev => prev.map(m => String(m.id) === String(messageId) ? { ...m, deleted: true, text: '', type: 'text' } : m));
  };

  const sendReaction = (messageId, emoji) => {
    if (!isRealId(messageId)) return addLog('Still sending — try again in a moment', 'pink');
    socketRef.current?.emit('message_reaction', { messageId, emoji });
    // Mirror the server's toggle so the bubble doesn't flicker before the echo.
    setMessages(prev => prev.map(m => {
      if (String(m.id) !== String(messageId)) return m;
      const reactions = m.reactions || [];
      const idx = reactions.findIndex(r => String(r.user_id) === String(currentUser.id) && r.emoji === emoji);
      return {
        ...m,
        reactions: idx >= 0 ? reactions.filter((_, i) => i !== idx)
                            : [...reactions, { emoji, user_id: currentUser.id }],
      };
    }));
  };

  const copyMyId = async () => {
    if (!myProfile?.qchatId) return;
    try {
      await navigator.clipboard.writeText(myProfile.qchatId);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      addLog('Clipboard blocked by the browser — copy the ID manually', 'pink');
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
      addLog(`Added ${data.username} to contacts`, 'green');
    } catch (err) {
      setAddError(err.response?.data?.error || 'Could not add contact');
    } finally {
      setAddBusy(false);
    }
  };

  const removeContact = async (u, e) => {
    e.stopPropagation();
    if (!window.confirm(`Remove ${u.username} from your contacts?`)) return;
    try {
      const { data } = await api.delete(`/api/users/contacts/${u.id}`);
      if (data.stillVisible) {
        addLog(`${u.username} stays listed — you still have message history`, 'info');
      } else if (peerRef.current && String(peerRef.current.id) === String(u.id)) {
        selectPeer(null);
      }
      await fetchUsers();
    } catch (err) {
      addLog(`Could not remove contact: ${err.message}`, 'pink');
    }
  };

  const clearChat = async () => {
    if (!peer) return;
    if (!window.confirm(`Clear all messages with ${peer.username}?`)) return;
    try {
      await api.delete(`/api/messages/${peer.id}`);
      setMessages([]); setIntegrity(null);
    } catch (err) {
      addLog(`Could not clear chat: ${err.message}`, 'pink');
    }
  };

  const handleKeyDown = e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } };
  const logout = () => { localStorage.removeItem('qchat_token'); localStorage.removeItem('qchat_user'); navigate('/login'); };

  const renderBubbleContent = (msg) => {
    if (msg.deleted) {
      return <div className="text-slate-400 italic flex items-center gap-1 opacity-75"><Trash size={12}/> This message was deleted</div>;
    }
    
    let content = msg.text;
    if (msg.type && msg.type !== 'text') {
      const { name, data } = unpackAttachment(msg.text);
      if (msg.type === 'image') {
        content = <img src={data} alt={name || 'Attachment'} className="max-w-[240px] max-h-[240px] rounded-md border border-white/10 mt-1 object-cover" />;
      } else if (msg.type === 'audio') {
        content = <audio controls src={data} className="w-[200px] h-8 outline-none mt-1" />;
      } else {
        // Previously a received file had no filename and no way to open it —
        // the decrypted bytes just sat in the bubble, unreachable.
        content = (
          <a href={data} download={name || 'qchat-attachment'}
             className="flex items-center gap-2 bg-black/20 hover:bg-black/30 transition-colors p-2 rounded-md mt-1">
            <File size={16} />
            <span className="text-xs truncate max-w-[160px]">{name || 'Secure File Attachment'}</span>
            <Download size={14} className="ml-auto opacity-70 flex-shrink-0" />
          </a>
        );
      }
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
            <p className="truncate w-40 text-slate-300">{previewText(messages.find(m => String(m.id) === String(msg.replyToId)))}</p>
          </div>
        )}
        {content}
      </div>
    );
  };

  /** Click-toggled reaction menu. */
  const renderReactionButton = (msg, align = 'left') => {
    const open = reactionPickerFor === msg.id;
    const mine = msg.reactions || [];
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
              const active = mine.some(r => String(r.user_id) === String(currentUser.id) && r.emoji === em);
              return (
                <button
                  key={em}
                  type="button"
                  role="menuitem"
                  title={active ? `Remove ${em}` : `React with ${em}`}
                  onClick={() => { sendReaction(msg.id, em); setReactionPickerFor(null); }}
                  className={`w-8 h-8 flex items-center justify-center rounded-full text-base leading-none transition-transform hover:scale-125 hover:bg-white/10 ${active ? 'bg-cyan-400/20 ring-1 ring-cyan-400/40' : ''}`}
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

  const renderReactions = (msg) => {
    const reactions = msg.reactions || [];
    if (reactions.length === 0) return null;
    // Group identical emojis, tracking whether this user is among the reactors.
    const counts = reactions.reduce((acc, r) => {
      const entry = acc[r.emoji] || (acc[r.emoji] = { count: 0, mine: false });
      entry.count++;
      if (String(r.user_id) === String(currentUser.id)) entry.mine = true;
      return acc;
    }, {});
    return (
      <div className="flex items-center gap-1 mt-1 -mb-3 ml-1 z-20 relative drop-shadow-md">
        {Object.entries(counts).map(([emoji, { count, mine: isMine }]) => (
          <button
            key={emoji}
            type="button"
            title={isMine ? 'Remove your reaction' : `React with ${emoji}`}
            onClick={() => sendReaction(msg.id, emoji)}
            className={`border text-[10px] px-1.5 py-0.5 rounded-full flex items-center gap-1 shadow-sm transition-colors ${isMine
              ? 'bg-cyan-400/20 border-cyan-400/40 text-cyan-200'
              : 'bg-navy-800 border-white/10 text-slate-200 hover:bg-navy-700'}`}
          >
            <span>{emoji}</span> {count > 1 && <span className="opacity-70">{count}</span>}
          </button>
        ))}
      </div>
    );
  };

  return (
    <div className="relative h-screen flex overflow-hidden bg-navy-950">
      <div className="bg-grid" />
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        <div className="orb w-[700px] h-[700px] bg-blue-900/20 -top-60 -left-40" />
        <div className="orb w-[500px] h-[500px] bg-indigo-900/15 -bottom-40 -right-20" style={{ animationDelay: '-9s' }} />
      </div>

      <aside className="relative z-10 w-72 flex flex-col m-3 mr-0 glass flex-shrink-0">
        <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-white/[0.06]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-blue-500 flex items-center justify-center shadow-glow-cyan-sm">
              <ShieldCheck size={15} className="text-navy-950" />
            </div>
            <span className="font-extrabold text-sm tracking-tight">QChat</span>
          </div>
          <span className="badge-pq"><Zap size={9} />PQ-Secure</span>
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
            <div
              key={u.id}
              onClick={() => selectPeer({ ...u, id: String(u.id) })}
              className={`user-row w-full text-left group/row ${peer?.id === String(u.id) ? 'active' : ''}`}
            >
              <div className={`relative w-9 h-9 rounded-full bg-gradient-to-br ${avatarGrad(u.username)} flex items-center justify-center font-bold text-sm text-white flex-shrink-0`}>
                {u.username[0].toUpperCase()}
                {u.isOnline && <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-navy-800 shadow-glow-green" />}
              </div>
              <div className="min-w-0 flex-1">
                <p className="font-semibold text-sm truncate">{u.username}</p>
                <p className="text-[10px] font-mono text-slate-500 truncate">{u.qchatId || '—'}</p>
              </div>
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

      <main className="relative z-10 flex-1 flex flex-col m-3 glass overflow-hidden">
        {peer ? (
          <>
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/[0.06] flex-shrink-0 gap-3">
              <div className="flex items-center gap-3 min-w-0">
                <div className={`relative w-9 h-9 rounded-full bg-gradient-to-br ${avatarGrad(peer.username)} flex items-center justify-center font-bold text-sm text-white flex-shrink-0`}>
                  {peer.username[0].toUpperCase()}
                </div>
                <div className="min-w-0">
                  <p className="font-bold text-base leading-tight truncate">{peer.username}</p>
                  {peerTyping ? (
                    <p className="text-cyan-400 text-xs font-medium animate-pulse">typing...</p>
                  ) : peer.isOnline ? (
                    <p className="text-[10px] text-emerald-400 font-medium">Online</p>
                  ) : (
                    <p className="text-[10px] text-slate-500">{formatLastSeen(peer.lastSeen)}</p>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                {integrity && <span className="flex items-center gap-1 text-[10px] text-slate-500 font-mono mr-2"><Fingerprint size={10} className="text-cyan-400" />{integrity}</span>}
                {callStatus === 'idle' && (
                  <button onClick={startCall} className="btn-ghost p-2 rounded-lg text-emerald-400 hover:bg-emerald-400/10" title="Secure Video Call"><Video size={16} /></button>
                )}
                <button className="btn-ghost p-2 rounded-lg text-slate-500 hover:text-rose-400" onClick={clearChat} title="Clear Chat"><Trash2 size={14} /></button>
                <button className={`btn-ghost p-2 rounded-lg ${showConsole ? 'text-cyan-400' : ''}`} onClick={() => setShowConsole(v => !v)} title="Toggle Console"><Terminal size={14} /></button>
              </div>
            </div>

            {/* WEBRTC OVERLAY */}
            <AnimatePresence>
              {callStatus !== 'idle' && (
                <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }} className="absolute inset-0 z-50 bg-navy-950/95 backdrop-blur-md flex flex-col">
                  {callStatus === 'receiving' ? (
                    <div className="flex-1 flex flex-col items-center justify-center">
                      <div className={`w-24 h-24 rounded-full bg-gradient-to-br ${avatarGrad(peer.username)} flex items-center justify-center font-bold text-4xl text-white mb-6 animate-pulse`}>
                        {peer.username[0].toUpperCase()}
                      </div>
                      <h2 className="text-2xl font-bold mb-2">{peer.username} is calling...</h2>
                      <p className="text-cyan-400 flex items-center gap-2 mb-8"><Lock size={14}/> ML-KEM-768 Secured</p>
                      <div className="flex gap-6">
                        <button onClick={cleanupCall} className="w-14 h-14 rounded-full bg-rose-500 hover:bg-rose-600 flex items-center justify-center shadow-lg shadow-rose-500/20"><PhoneOff size={24} className="text-white"/></button>
                        <button onClick={acceptCall} className="w-14 h-14 rounded-full bg-emerald-500 hover:bg-emerald-600 flex items-center justify-center shadow-lg shadow-emerald-500/20"><Video size={24} className="text-white"/></button>
                      </div>
                    </div>
                  ) : (
                    <div className="relative flex-1 bg-black">
                      <video ref={remoteVideoRef} autoPlay playsInline className="w-full h-full object-cover" />
                      <div className="absolute top-4 right-4 w-32 md:w-48 aspect-[3/4] bg-navy-900 rounded-xl overflow-hidden shadow-2xl border border-white/10">
                        <video ref={localVideoRef} autoPlay playsInline muted className="w-full h-full object-cover" />
                      </div>
                      <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex items-center gap-4 bg-navy-900/80 backdrop-blur-lg px-6 py-3 rounded-full border border-white/10">
                        <button onClick={toggleMute} className={`p-3 rounded-full ${isMuted ? 'bg-rose-500/20 text-rose-500' : 'bg-white/10 text-white hover:bg-white/20'}`}>
                          {isMuted ? <MicOff size={20}/> : <Mic size={20}/>}
                        </button>
                        <button onClick={toggleVideo} className={`p-3 rounded-full ${isVideoOff ? 'bg-rose-500/20 text-rose-500' : 'bg-white/10 text-white hover:bg-white/20'}`}>
                          {isVideoOff ? <VideoOff size={20}/> : <Video size={20}/>}
                        </button>
                        <button onClick={endCall} className="p-3 rounded-full bg-rose-500 text-white hover:bg-rose-600 shadow-lg shadow-rose-500/20">
                          <PhoneOff size={20}/>
                        </button>
                      </div>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>

            <div ref={scrollBoxRef} onScroll={handleMessagesScroll} className="flex-1 overflow-y-auto px-4 py-5" style={{ backgroundImage: "url('/whatsapp-bg.png')", backgroundSize: 'cover', backgroundBlendMode: 'overlay', backgroundColor: 'rgba(10,15,30,0.92)' }}>
              <div className="flex flex-col gap-3">
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
                {!hasMoreHistory && messages.length > 0 && (
                  <div className="text-center text-[10px] text-slate-600 py-1">
                    Beginning of your encrypted conversation
                  </div>
                )}
                <AnimatePresence initial={false}>
                  {messages.map((msg, i) => {
                    const isGrouped = i > 0 && messages[i - 1].isMine === msg.isMine;
                    return (
                      <motion.div id={`msg-${msg.id}`} key={msg.id || i} className={`flex items-end gap-2 group ${msg.isMine ? 'justify-end' : 'justify-start'} ${isGrouped ? 'mt-0.5' : 'mt-2'}`} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}>
                        
                        {/* Hover actions (Theirs) */}
                        {!msg.isMine && !msg.deleted && (
                          <div data-reaction-ui className={`flex items-center gap-1 transition-opacity mb-2 focus-within:opacity-100 ${reactionPickerFor === msg.id ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
                            <button type="button" aria-label="Reply" title="Reply" onClick={() => setReplyingTo(msg)} className="p-2 text-slate-400 hover:text-white hover:bg-navy-700 rounded-full bg-navy-800 transition-colors"><Reply size={14}/></button>
                            {renderReactionButton(msg, 'left')}
                          </div>
                        )}

                        <div className={`flex flex-col ${msg.isMine ? 'items-end' : 'items-start'}`} style={{ maxWidth: '68%' }}>
                          <div className={[msg.isMine ? 'bubble-mine' : 'bubble-theirs', msg.error ? 'bubble-error' : ''].filter(Boolean).join(' ')}>
                            {renderBubbleContent(msg)}
                          </div>
                          
                          {renderReactions(msg)}

                          <div className={`flex items-center gap-1 px-1 ${msg.reactions?.length ? 'mt-3' : 'mt-1'}`}>
                            <span className="text-[10px] text-muted font-mono">{fmt(msg.timestamp)}</span>
                            {msg.isMine && !msg.deleted && (
                              msg.read ? <CheckCheck size={12} className="text-blue-400" /> :
                              msg.delivered ? <CheckCheck size={12} className="text-slate-400" /> :
                              <Check size={12} className="text-slate-500" />
                            )}
                          </div>
                        </div>

                        {/* Hover actions (Mine) */}
                        {msg.isMine && !msg.deleted && (
                          <div data-reaction-ui className={`flex items-center gap-1 transition-opacity mb-2 focus-within:opacity-100 ${reactionPickerFor === msg.id ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
                            {renderReactionButton(msg, 'right')}
                            <button type="button" aria-label="Reply" title="Reply" onClick={() => setReplyingTo(msg)} className="p-2 text-slate-400 hover:text-white hover:bg-navy-700 rounded-full bg-navy-800 transition-colors"><Reply size={14}/></button>
                            <button type="button" aria-label="Delete message" title="Delete" onClick={() => deleteMessage(msg.id)} className="p-2 text-slate-400 hover:text-rose-400 hover:bg-navy-700 rounded-full bg-navy-800 transition-colors"><Trash2 size={14}/></button>
                          </div>
                        )}

                      </motion.div>
                    );
                  })}
                </AnimatePresence>
                <div ref={bottomRef} />
              </div>
            </div>

            {/* Input Area */}
            <div className="relative px-4 py-3.5 border-t border-white/[0.06] flex-shrink-0 bg-navy-950/70 backdrop-blur-md z-10">
              
              {replyingTo && (
                <div className="mb-2 flex items-center justify-between bg-black/40 p-2 rounded-lg border-l-4 border-emerald-400">
                  <div className="flex flex-col overflow-hidden">
                    <span className="text-xs font-semibold text-emerald-400">Replying to {replyingTo.isMine ? 'yourself' : peer.username}</span>
                    <span className="text-xs text-slate-300 truncate">{previewText(replyingTo)}</span>
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
                
                <input ref={inputRef} className="field-input flex-1 !rounded-full !py-2.5 !px-5 !mb-0 bg-navy-900 border-white/10 focus:border-emerald-400/50 transition-colors" 
                       type="text" placeholder={attachment ? "Add a caption..." : "Type a message..."} 
                       value={input} onChange={handleTyping} onKeyDown={handleKeyDown} disabled={encrypting || isRecording} autoComplete="off" />
                
                {input.trim() || attachment ? (
                  <button type="submit" className="w-10 h-10 rounded-full bg-emerald-500 hover:bg-emerald-600 flex items-center justify-center text-white shadow-lg shadow-emerald-500/20 transition-transform hover:scale-105" disabled={encrypting}>
                    <Send size={18} className="ml-0.5" />
                  </button>
                ) : isRecording ? (
                  <button type="button" onClick={stopRecording} className="w-10 h-10 rounded-full bg-rose-500 hover:bg-rose-600 flex items-center justify-center text-white shadow-lg shadow-rose-500/20 animate-pulse">
                    <StopCircle size={20} />
                  </button>
                ) : (
                  <button type="button" onClick={startRecording} className="w-10 h-10 rounded-full bg-navy-800 hover:bg-navy-700 flex items-center justify-center text-slate-300 transition-transform hover:scale-105">
                    <Mic size={20} />
                  </button>
                )}
              </form>
            </div>
            
            <AnimatePresence>
              {showConsole && (
                <motion.div initial={{ height: 0 }} animate={{ height: 144 }} exit={{ height: 0 }} className="flex-shrink-0 border-t border-white/[0.06] bg-black/25 overflow-hidden">
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
          <div className="h-full flex flex-col items-center justify-center">
            <div className="w-16 h-16 rounded-2xl bg-white/5 flex items-center justify-center mb-4"><ShieldCheck size={32} className="text-slate-600"/></div>
            <p className="text-sm text-slate-400">Select a peer to start a quantum-secure chat</p>
          </div>
        )}
      </main>
    </div>
  );
}
