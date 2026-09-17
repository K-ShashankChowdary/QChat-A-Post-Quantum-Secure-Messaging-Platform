import React, { useEffect, useRef } from 'react';

/**
 * Animated lattice backdrop.
 *
 * ML-KEM's security rests on how hard it is to find short vectors in a
 * high-dimensional lattice, so the background is a literal lattice: points on a
 * grid, drifting around their ideal positions, with edges drawn between
 * neighbours. The cursor perturbs nearby points — the picture only resolves
 * where you are looking, which is roughly the intuition for the hard problem.
 *
 * Neighbour lookup is index-based rather than distance-testing every pair, so
 * cost is linear in the number of points, not quadratic.
 */
export default function LatticeField({ className = '' }) {
  const canvasRef = useRef(null);
  const pointerRef = useRef({ x: -9999, y: -9999 });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

    let width = 0, height = 0, cols = 0, rows = 0, spacing = 0;
    let points = [];
    let frame = 0;
    let raf = null;

    const SPACING_TARGET = 92;
    const DPR_CAP = 2;

    function build() {
      const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP);
      const rect = canvas.getBoundingClientRect();
      width = rect.width;
      height = rect.height;

      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      spacing = SPACING_TARGET;
      cols = Math.ceil(width / spacing) + 2;
      rows = Math.ceil(height / spacing) + 2;

      points = new Array(cols * rows);
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const bx = (c - 1) * spacing;
          const by = (r - 1) * spacing;
          points[r * cols + c] = {
            bx, by, x: bx, y: by,
            // Per-point phase so the drift never looks like a marching grid.
            phase: Math.random() * Math.PI * 2,
            speed: 0.4 + Math.random() * 0.5,
            amp: spacing * (0.12 + Math.random() * 0.16),
          };
        }
      }
    }

    function draw() {
      frame++;
      const t = frame * 0.006;
      const { x: px, y: py } = pointerRef.current;
      const INFLUENCE = 190;

      ctx.clearRect(0, 0, width, height);

      for (let i = 0; i < points.length; i++) {
        const p = points[i];
        if (reduced) {
          p.x = p.bx;
          p.y = p.by;
        } else {
          p.x = p.bx + Math.cos(t * p.speed + p.phase) * p.amp;
          p.y = p.by + Math.sin(t * p.speed * 0.85 + p.phase) * p.amp;
        }

        // Pull points gently toward the cursor.
        const dx = px - p.x;
        const dy = py - p.y;
        const dist = Math.hypot(dx, dy);
        p.near = dist < INFLUENCE ? 1 - dist / INFLUENCE : 0;
        if (p.near > 0) {
          p.x += dx * p.near * 0.16;
          p.y += dy * p.near * 0.16;
        }
      }

      // Edges: each point links right and down only, so every edge is drawn once.
      ctx.lineWidth = 1;
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const p = points[r * cols + c];
          for (const n of [
            c + 1 < cols ? points[r * cols + c + 1] : null,
            r + 1 < rows ? points[(r + 1) * cols + c] : null,
          ]) {
            if (!n) continue;
            const glow = Math.max(p.near, n.near);
            const alpha = 0.045 + glow * 0.4;
            ctx.strokeStyle = glow > 0.02
              ? `rgba(${Math.round(80 + glow * 60)}, ${Math.round(200 + glow * 40)}, 255, ${alpha})`
              : `rgba(90, 140, 190, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(n.x, n.y);
            ctx.stroke();
          }
        }
      }

      // Vertices
      for (let i = 0; i < points.length; i++) {
        const p = points[i];
        const radius = 1.1 + p.near * 2.2;
        ctx.fillStyle = p.near > 0.02
          ? `rgba(34, 211, 238, ${0.25 + p.near * 0.7})`
          : 'rgba(120, 170, 220, 0.22)';
        ctx.beginPath();
        ctx.arc(p.x, p.y, radius, 0, Math.PI * 2);
        ctx.fill();
      }

      raf = requestAnimationFrame(draw);
    }

    function start() {
      if (raf == null) raf = requestAnimationFrame(draw);
    }
    function stop() {
      if (raf != null) { cancelAnimationFrame(raf); raf = null; }
    }

    const onPointer = (e) => {
      const rect = canvas.getBoundingClientRect();
      pointerRef.current = { x: e.clientX - rect.left, y: e.clientY - rect.top };
    };
    const onLeave = () => { pointerRef.current = { x: -9999, y: -9999 }; };
    const onResize = () => { build(); };
    // Don't burn frames on a tab nobody is looking at.
    const onVisibility = () => (document.hidden ? stop() : start());

    build();
    if (reduced) {
      draw();
      stop();
    } else {
      start();
    }

    window.addEventListener('resize', onResize);
    window.addEventListener('pointermove', onPointer, { passive: true });
    window.addEventListener('pointerleave', onLeave);
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      stop();
      window.removeEventListener('resize', onResize);
      window.removeEventListener('pointermove', onPointer);
      window.removeEventListener('pointerleave', onLeave);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  return <canvas ref={canvasRef} className={className} aria-hidden="true" />;
}
