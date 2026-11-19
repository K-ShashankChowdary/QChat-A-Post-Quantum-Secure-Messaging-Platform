/**
 * The one wire shape for a stored message. The socket relay, offline delivery
 * and the history route each used to build this object by hand, and the three
 * copies had already started to drift.
 *
 * `senderPayload` is only meaningful to the sender (it is the v1 self-copy), so
 * it is included only where the reader can be the sender: history.
 */
export function serializeMessage(msg, { includeSenderPayload = false } = {}) {
  const wire = {
    id:        msg._id,
    fromId:    msg.from_user_id,
    toId:      msg.to_user_id,
    payload:   msg.payload,
    timestamp: msg.timestamp,
    delivered: msg.delivered,
    read:      msg.read,
    replyToId: msg.reply_to_id,
    deleted:   msg.deleted,
    type:      msg.type,
    reactions: msg.reactions,
  };
  if (includeSenderPayload) wire.senderPayload = msg.sender_payload;
  return wire;
}
