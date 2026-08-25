import type { ReactNode } from 'react';
import { AlertCircle, LoaderCircle } from 'lucide-react';

export function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: ReactNode }) {
  return <header className="page-header"><div><p className="eyebrow">{eyebrow || 'ThreatCanvas'}</p><h1>{title}</h1>{description && <p className="page-description">{description}</p>}</div>{action}</header>;
}

export function Panel({ title, description, children, className = '' }: { title?: string; description?: string; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}>{(title || description) && <div className="panel-heading">{title && <h2>{title}</h2>}{description && <p>{description}</p>}</div>}{children}</section>;
}

export function MetricCard({ label, value, detail, tone = 'neutral' }: { label: string; value: string | number; detail?: string; tone?: 'neutral' | 'good' | 'warn' | 'danger' }) {
  return <div className={`metric-card metric-${tone}`}><span>{label}</span><strong>{value}</strong>{detail && <small>{detail}</small>}</div>;
}

export function StatusBadge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'good' | 'warn' | 'danger' | 'info' }) {
  return <span className={`status-badge status-${tone}`}>{children}</span>;
}

export function LoadingState({ label = 'Loading analysis' }: { label?: string }) {
  return <div className="state-box"><LoaderCircle className="spin" size={20} /><span>{label}</span></div>;
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return <div className="state-box state-error"><AlertCircle size={20} /><span>{message}</span>{onRetry && <button className="button button-quiet" onClick={onRetry}>Retry</button>}</div>;
}

export function EmptyState({ title, description }: { title: string; description: string }) {
  return <div className="state-box state-empty"><strong>{title}</strong><span>{description}</span></div>;
}
