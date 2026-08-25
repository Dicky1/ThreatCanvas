import { useEffect, useState } from 'react';
import { Pause, Play } from 'lucide-react';
import type { AttackTimeline } from '../types/api';
import { StatusBadge } from './common/Primitives';

export default function AttackTimelinePlayer({ timeline }: { timeline: AttackTimeline }) {
  const [activeIndex, setActiveIndex] = useState(0);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    if (!playing || !timeline.events.length) return;
    const timer = window.setInterval(() => {
      setActiveIndex((value) => (value + 1) % timeline.events.length);
    }, 900);
    return () => window.clearInterval(timer);
  }, [playing, timeline.events.length]);

  if (!timeline.events.length) return null;

  return (
    <div className="data-list">
      <div className="action-row">
        <button className="button button-secondary" onClick={() => setPlaying((value) => !value)}>
          {playing ? <Pause size={16} /> : <Play size={16} />}
          {playing ? 'Pause attack' : 'Play attack'}
        </button>
        <StatusBadge tone="info">{timeline.events.length} event(s)</StatusBadge>
      </div>
      <div className="timeline-strip">
        {timeline.events.map((event, index) => (
          <div key={`${event.timestamp}-${event.node_id}`} className={`timeline-event ${index === activeIndex ? 'active' : ''}`}>
            <strong>{event.timestamp}</strong>
            <div>
              <strong>{event.technique} | {event.action_type}</strong>
              <small>{event.tactic} | target {event.target}</small>
            </div>
            <StatusBadge tone={index === activeIndex ? 'good' : 'neutral'}>{event.status}</StatusBadge>
          </div>
        ))}
      </div>
    </div>
  );
}
