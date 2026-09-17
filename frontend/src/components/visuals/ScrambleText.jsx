import React, { useEffect, useRef, useState } from 'react';

const GLYPHS = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789/\\<>[]{}=+*#';

/**
 * Resolves text character by character out of noise — a decrypting effect.
 * Spaces are never scrambled so the line keeps its shape while it settles.
 */
export default function ScrambleText({ text, speed = 28, revealEvery = 2, className = '', as: Tag = 'span' }) {
  const [display, setDisplay] = useState(text);
  const frameRef = useRef(null);

  useEffect(() => {
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      setDisplay(text);
      return;
    }

    let tick = 0;
    let revealed = 0;
    const chars = [...text];

    const step = () => {
      tick++;
      if (tick % revealEvery === 0) revealed++;

      setDisplay(
        chars
          .map((ch, i) => {
            if (ch === ' ' || ch === '\n') return ch;
            if (i < revealed) return ch;
            return GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
          })
          .join('')
      );

      if (revealed <= chars.length) {
        frameRef.current = setTimeout(step, speed);
      }
    };

    setDisplay(chars.map(ch => (ch === ' ' ? ch : GLYPHS[Math.floor(Math.random() * GLYPHS.length)])).join(''));
    frameRef.current = setTimeout(step, speed);

    return () => clearTimeout(frameRef.current);
  }, [text, speed, revealEvery]);

  return <Tag className={className}>{display}</Tag>;
}
