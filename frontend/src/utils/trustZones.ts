import type { CIRNode } from '../types/api';

export const TRUST_ZONE_ORDER = ['Internet', 'Endpoint', 'Internal Network', 'Crown Jewels'] as const;

export function inferTrustZone(node: CIRNode | undefined): typeof TRUST_ZONE_ORDER[number] {
  const text = `${node?.target ?? ''} ${node?.action_type ?? ''} ${node?.tactic ?? ''}`.toLowerCase();
  if (/(database|domain controller|payment|production|backup|identity|admin)/.test(text)) {
    return 'Crown Jewels';
  }
  if (/(server|internal|smb|lateral|network|external)/.test(text)) {
    return 'Internal Network';
  }
  if (/(workstation|computer|user|endpoint|powershell|execution|defense evasion)/.test(text)) {
    return 'Endpoint';
  }
  return 'Internet';
}

export function groupPathByTrustZone(nodes: Array<CIRNode | undefined>) {
  return TRUST_ZONE_ORDER.map((zone) => ({
    zone,
    nodes: nodes.filter((node) => inferTrustZone(node) === zone),
  }));
}
