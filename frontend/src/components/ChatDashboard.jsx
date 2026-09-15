import React, { useState, useEffect, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { encryptMessage, decryptMessage, b64decode, calculateIntegrity } from '../crypto/encryption';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Send, Terminal, Shield, LogOut, Lock, Fingerprint,
  Users, Zap, ShieldCheck, Trash2, Video, PhoneOff, Mic, MicOff, VideoOff, Check, CheckCheck,
  Paperclip, X, Reply, Smile, File, StopCircle, Trash
} from 'lucide-react';

/* ─── Avatar palette ─── */
const GRADIENTS = [
  'from-cyan-400 to-blue-500',
  'from-pink-400 to-rose-600',
  'from-emerald-400 to-cyan-500',
  'from-amber-400 to-orange-500',
  'from-violet-400 to-purple-600',
];
const avatarGrad = (name = '') => GRADIENTS[name.charCodeAt(0) % GRADIENTS.length];

/* ─── Format timestamp ─── */
const fmt = ts => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const formatLastSeen = ts => {
  if (!ts) return '';
  const d = new Date(ts);
  const today = new Date();
  if (d.toDateString() === today.toDateString()) return `Last seen today at ${fmt(ts)}`;
  return `Last seen ${d.toLocaleDateString()} at ${fmt(ts)}`;
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
  const localVideoRef                   = useRef(null);
  const remoteVideoRef                  = useRef(null);
  const callPayloadRef                  = useRef(null); // stores incoming offer

  /* Persist selected peer across refreshes */
  const selectPeer = (u) => {
    setPeer(u);
    setReplyingTo(null);
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
  const rtcConfig = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

  const encryptAndSendSignal = async (signalData, toId) => {
    try {
      const recipientPubKey = b64decode(peerRef.current.public_key);
      const payload = await encryptMessage(JSON.stringify(signalData), recipientPubKey);
      socketRef.current?.emit('webrtc_signal', { toId, fromId: currentUser.id, signalPayload: payload });
      addLog(`Sent encrypted WebRTC signal (${signalData.type || 'candidate'})`, 'cyan');
    } catch (err) {
      addLog(`Failed to encrypt signal: ${err.message}`, 'pink');
    }
  };

  const initWebRTC = async (isInitiator) => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
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
        if (event.candidate) {
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
          setCallStatus('connected');
        }
      } else if (signal.type === 'candidate') {
        if (rtcPeerConnection.current) {
          await rtcPeerConnection.current.addIceCandidate(new RTCIceCandidate(signal.candidate));
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
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      encryptAndSendSignal({ type: 'answer', sdp: answer }, peerRef.current.id);
      setCallStatus('connected');
      callPayloadRef.current = null;
    }
  };

  const cleanupCall = () => {
    if (rtcPeerConnection.current) {
      rtcPeerConnection.current.close();
      rtcPeerConnection.current = null;
    }
    if (localStream) {
      localStream.getTracks().forEach(t => t.stop());
      setLocalStream(null);
    }
    setRemoteStream(null);
    setCallStatus('idle');
  };

  const endCall = () => {
    encryptAndSendSignal({ type: 'end_call' }, peerRef.current.id);
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


  /* ─── Socket setup ─── */
  useEffect(() => {
    if (!currentUser.id) { navigate('/login'); return; }

    const localPub = localStorage.getItem(`qchat_pub_${currentUser.id}`);
    if (localPub) {
      axios.post('/api/auth/update-key', 
        { userId: currentUser.id, publicKey: localPub },
        { headers: { Authorization: `Bearer ${localStorage.getItem('qchat_token')}` } }
      ).catch(() => {});
    }

    const s = io('http://localhost:5000', {
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: 10,
    });
    socketRef.current = s;

    s.on('connect', () => {
      setConnStatus('connected');
      s.emit('register_socket', currentUser.id);
      addLog('Connected to secure relay server', 'cyan');
    });

    s.on('disconnect', () => {
      setConnStatus('disconnected');
      addLog('Server disconnected — attempting to reconnect', 'pink');
    });

    s.on('reconnecting', () => { setConnStatus('connecting'); });
    s.on('reconnect', () => {
      setConnStatus('connected');
      s.emit('register_socket', currentUser.id);
    });

    s.on('new_message', async (msg) => {
      try {
        const text = await decryptMessage(msg.payload, privateKey);
        
        if (peerRef.current && String(peerRef.current.id) === String(msg.fromId)) {
          setMessages(prev => {
            if (prev.some(m => String(m.id) === String(msg.id))) return prev;
            return [...prev, { ...msg, text, isMine: false }];
          });
          // Send read receipt if we are actively viewing this chat
          if (document.hasFocus()) {
            s.emit('message_read', { messageIds: [msg.id], fromId: currentUser.id, toId: msg.fromId });
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

    s.on('message_reaction', ({ messageId, reaction }) => {
      setMessages(prev => prev.map(m => {
        if (String(m.id) === String(messageId)) {
          const newReactions = [...(m.reactions || [])];
          newReactions.push(reaction);
          return { ...m, reactions: newReactions };
        }
        return m;
      }));
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
    return () => s.close();
  }, []);

  /* ─── Load history on peer change ─── */
  useEffect(() => {
    if (!peer) return;
    setMessages([]); setIntegrity(null); setPeerTyping(false);
    loadHistory(peer.id);
    setTimeout(() => inputRef.current?.focus(), 100);
  }, [peer?.id]);

  /* ─── Window focus read receipts ─── */
  useEffect(() => {
    const onFocus = () => {
      if (peerRef.current && socketRef.current) {
        const unreadIds = messages.filter(m => !m.isMine && !m.read && !m.deleted).map(m => m.id);
        if (unreadIds.length > 0) {
          socketRef.current.emit('message_read', { messageIds: unreadIds, fromId: currentUser.id, toId: peerRef.current.id });
          setMessages(prev => prev.map(m => unreadIds.includes(m.id) ? { ...m, read: true } : m));
        }
      }
    };
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [messages]);

  /* ─── Scroll + integrity on message update ─── */
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    const ok = messages.filter(m => !m.error && !m.deleted);
    if (ok.length) calculateIntegrity(ok).then(setIntegrity);
  }, [messages, peerTyping, replyingTo]);

  const fetchUsers = useCallback(async () => {
    try {
      const { data } = await axios.get(`/api/users?_t=${Date.now()}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('qchat_token')}` }
      });
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
    } catch { }
  }, []);

  const loadHistory = async (peerId) => {
    try {
      const { data } = await axios.get(`/api/messages/${peerId}?_t=${Date.now()}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('qchat_token')}` }
      });
      const unreadIds = [];
      const history = await Promise.all(data.map(async msg => {
        const isMine = String(msg.fromId) === String(currentUser.id);
        if (!isMine && !msg.read && !msg.deleted) unreadIds.push(msg.id);
        
        if (msg.deleted) {
          return { ...msg, text: '', isMine };
        }

        if (isMine) {
          if (msg.senderPayload) {
            try {
              const text = await decryptMessage(msg.senderPayload, privateKey);
              return { ...msg, text, isMine: true };
            } catch { }
          }
          return { ...msg, text: '[Sent — previous session]', isMine: true, error: true };
        }
        try {
          return { ...msg, text: await decryptMessage(msg.payload, privateKey), isMine: false };
        } catch {
          return { ...msg, text: '[Locked — previous session key]', isMine: false, error: true };
        }
      }));
      setMessages(history);

      if (unreadIds.length > 0 && document.hasFocus() && socketRef.current) {
        socketRef.current.emit('message_read', { messageIds: unreadIds, fromId: currentUser.id, toId: peerId });
        setMessages(prev => prev.map(m => unreadIds.includes(m.id) ? { ...m, read: true } : m));
      }
    } catch { }
  };

  const handleTyping = (e) => {
    setInput(e.target.value);
    if (!socketRef.current || !peer) return;
    socketRef.current.emit('typing', { toId: peer.id, fromId: currentUser.id });
    
    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      socketRef.current?.emit('stop_typing', { toId: peer.id, fromId: currentUser.id });
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
      setAttachment({ name: file.name, type: file.type.startsWith('image/') ? 'image' : 'file', base64: reader.result });
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
          setAttachment({ name: 'Voice Note', type: 'audio', base64: reader.result });
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
    
    const textToSend = attachment ? attachment.base64 : input.trim();
    const msgType = attachment ? attachment.type : 'text';
    const currentReplyTo = replyingTo;
    
    setInput('');
    setAttachment(null);
    setReplyingTo(null);
    
    socketRef.current.emit('stop_typing', { toId: peer.id, fromId: currentUser.id });
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
      
      const tempId = `l-${Date.now()}`;
      setMessages(prev => [...prev, { 
        id: tempId, text: textToSend, isMine: true, timestamp: new Date(), 
        delivered: false, read: false, type: msgType, replyToId: currentReplyTo?.id 
      }]);
      
      socketRef.current?.emit('send_message', { 
        toId: peer.id, fromId: currentUser.id, payload, senderPayload, 
        type: msgType, replyToId: currentReplyTo?.id 
      });
    } catch (err) {
      addLog(`Encryption failed: ${err.message}`, 'pink');
    } finally {
      setEncrypting(false);
    }
  };

  const deleteMessage = (messageId) => {
    if (!window.confirm("Delete this message for everyone?")) return;
    socketRef.current?.emit('delete_message', { messageId, fromId: currentUser.id, toId: peer.id });
    setMessages(prev => prev.map(m => String(m.id) === String(messageId) ? { ...m, deleted: true, text: '', type: 'text' } : m));
  };

  const sendReaction = (messageId, emoji) => {
    socketRef.current?.emit('message_reaction', { messageId, emoji, fromId: currentUser.id, toId: peer.id });
    setMessages(prev => prev.map(m => {
      if (String(m.id) === String(messageId)) {
        return { ...m, reactions: [...(m.reactions || []), { emoji, user_id: currentUser.id }] };
      }
      return m;
    }));
  };

  const clearChat = async () => {
    if (!peer) return;
    if (!window.confirm(`Clear all messages with ${peer.username}?`)) return;
    try {
      await axios.delete(`/api/messages/${peer.id}`, { headers: { Authorization: `Bearer ${localStorage.getItem('qchat_token')}` } });
      setMessages([]); setIntegrity(null);
    } catch { }
  };

  const handleKeyDown = e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } };
  const logout = () => { localStorage.removeItem('qchat_token'); localStorage.removeItem('qchat_user'); navigate('/login'); };

  const renderBubbleContent = (msg) => {
    if (msg.deleted) {
      return <div className="text-slate-400 italic flex items-center gap-1 opacity-75"><Trash size={12}/> This message was deleted</div>;
    }
    
    let content = msg.text;
    if (msg.type === 'image') {
      content = <img src={msg.text} alt="Attachment" className="max-w-[240px] max-h-[240px] rounded-md border border-white/10 mt-1 object-cover" />;
    } else if (msg.type === 'audio') {
      content = <audio controls src={msg.text} className="w-[200px] h-8 outline-none mt-1" />;
    } else if (msg.type === 'file') {
      content = <div className="flex items-center gap-2 bg-black/20 p-2 rounded-md mt-1"><File size={16}/> <span className="text-xs">Secure File Attachment</span></div>;
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
            <p className="truncate w-40 text-slate-300">{messages.find(m => String(m.id) === String(msg.replyToId))?.text || 'Original message'}</p>
          </div>
        )}
        {content}
      </div>
    );
  };

  const renderReactions = (reactions) => {
    if (!reactions || reactions.length === 0) return null;
    // Group identical emojis
    const counts = reactions.reduce((acc, r) => { acc[r.emoji] = (acc[r.emoji] || 0) + 1; return acc; }, {});
    return (
      <div className="flex items-center gap-1 mt-1 -mb-3 ml-1 z-20 relative drop-shadow-md">
        {Object.entries(counts).map(([emoji, count]) => (
          <div key={emoji} className="bg-navy-800 border border-white/10 text-[10px] px-1.5 py-0.5 rounded-full flex items-center gap-1 shadow-sm">
            <span>{emoji}</span> {count > 1 && <span className="text-slate-400">{count}</span>}
          </div>
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
        <div className="px-5 pt-4 pb-2 flex items-center gap-2">
          <Users size={11} className="text-slate-600" />
          <span className="text-[10px] font-semibold uppercase tracking-widest text-muted">{users.length} peers</span>
        </div>
        <div className="flex-1 overflow-y-auto px-2.5 pb-2 space-y-0.5">
          {users.map(u => (
            <motion.button
              key={u.id} whileTap={{ scale: 0.98 }} onClick={() => selectPeer({ ...u, id: String(u.id) })}
              className={`user-row w-full text-left ${peer?.id === String(u.id) ? 'active' : ''}`}
            >
              <div className={`relative w-9 h-9 rounded-full bg-gradient-to-br ${avatarGrad(u.username)} flex items-center justify-center font-bold text-sm text-white flex-shrink-0`}>
                {u.username[0].toUpperCase()}
                {u.isOnline && <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-navy-800 shadow-glow-green" />}
              </div>
              <div className="min-w-0">
                <p className="font-semibold text-sm truncate">{u.username}</p>
                <p className="text-[10px] flex items-center gap-1 text-emerald-400/80"><Shield size={9} /> {u.isOnline ? 'Online' : 'Offline'}</p>
              </div>
            </motion.button>
          ))}
        </div>
        <div className="px-4 py-3.5 border-t border-white/[0.06] flex items-center gap-2.5">
          <div className={`w-8 h-8 rounded-full bg-gradient-to-br ${avatarGrad(currentUser.username || '')} flex items-center justify-center font-bold text-sm text-white flex-shrink-0`}>
            {(currentUser.username || 'U')[0].toUpperCase()}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold truncate">{currentUser.username}</p>
            <p className="text-[10px] text-emerald-400 flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400"/>Connected</p>
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

            <div className="flex-1 overflow-y-auto px-4 py-5" style={{ backgroundImage: "url('/whatsapp-bg.png')", backgroundSize: 'cover', backgroundBlendMode: 'overlay', backgroundColor: 'rgba(10,15,30,0.92)' }}>
              <div className="flex flex-col gap-3">
                <AnimatePresence initial={false}>
                  {messages.map((msg, i) => {
                    const isGrouped = i > 0 && messages[i - 1].isMine === msg.isMine;
                    return (
                      <motion.div id={`msg-${msg.id}`} key={msg.id || i} className={`flex items-end gap-2 group ${msg.isMine ? 'justify-end' : 'justify-start'} ${isGrouped ? 'mt-0.5' : 'mt-2'}`} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}>
                        
                        {/* Hover actions (Theirs) */}
                        {!msg.isMine && !msg.deleted && (
                          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity mb-2">
                            <button onClick={() => setReplyingTo(msg)} className="p-1.5 text-slate-400 hover:text-white rounded-full bg-navy-800"><Reply size={12}/></button>
                            <div className="relative group/emoji">
                              <button className="p-1.5 text-slate-400 hover:text-white rounded-full bg-navy-800"><Smile size={12}/></button>
                              <div className="absolute bottom-full mb-1 left-0 hidden group-hover/emoji:flex items-center gap-1 bg-navy-800 p-1 rounded-full border border-white/10 shadow-xl z-50">
                                {['👍','❤️','😂','😮','😢'].map(em => (
                                  <button key={em} onClick={() => sendReaction(msg.id, em)} className="hover:scale-125 transition-transform text-base">{em}</button>
                                ))}
                              </div>
                            </div>
                          </div>
                        )}

                        <div className={`flex flex-col ${msg.isMine ? 'items-end' : 'items-start'}`} style={{ maxWidth: '68%' }}>
                          <div className={[msg.isMine ? 'bubble-mine' : 'bubble-theirs', msg.error ? 'bubble-error' : ''].filter(Boolean).join(' ')}>
                            {renderBubbleContent(msg)}
                          </div>
                          
                          {renderReactions(msg.reactions)}

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
                          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity mb-2">
                            <div className="relative group/emoji">
                              <button className="p-1.5 text-slate-400 hover:text-white rounded-full bg-navy-800"><Smile size={12}/></button>
                              <div className="absolute bottom-full mb-1 right-0 hidden group-hover/emoji:flex items-center gap-1 bg-navy-800 p-1 rounded-full border border-white/10 shadow-xl z-50">
                                {['👍','❤️','😂','😮','😢'].map(em => (
                                  <button key={em} onClick={() => sendReaction(msg.id, em)} className="hover:scale-125 transition-transform text-base">{em}</button>
                                ))}
                              </div>
                            </div>
                            <button onClick={() => setReplyingTo(msg)} className="p-1.5 text-slate-400 hover:text-white rounded-full bg-navy-800"><Reply size={12}/></button>
                            <button onClick={() => deleteMessage(msg.id)} className="p-1.5 text-slate-400 hover:text-rose-400 rounded-full bg-navy-800"><Trash2 size={12}/></button>
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
                    <span className="text-xs text-slate-300 truncate">{replyingTo.type !== 'text' ? `Attachment (${replyingTo.type})` : replyingTo.text}</span>
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
