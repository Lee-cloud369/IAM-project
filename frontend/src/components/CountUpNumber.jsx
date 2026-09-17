import React, { useState, useEffect } from 'react';

/**
 * Animated Number Counter component
 * Smoothly interpolates from 0 to target value under 350ms with ease-out cubic.
 */
export default function CountUpNumber({ value, duration = 350, prefix = '', suffix = '', className = '' }) {
  const target = typeof value === 'number' ? value : parseInt(String(value).replace(/[^0-9.-]/g, ''), 10) || 0;
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    let startTimestamp = null;
    let animationFrameId;

    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const elapsed = timestamp - startTimestamp;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic formula
      const easeOut = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(easeOut * target);

      setDisplayValue(current);

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(step);
      }
    };

    animationFrameId = requestAnimationFrame(step);

    return () => {
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
      }
    };
  }, [target, duration]);

  return (
    <span className={className}>
      {prefix}
      {displayValue.toLocaleString()}
      {suffix}
    </span>
  );
}
