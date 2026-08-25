import { useMemo, useState } from 'react';
import { Background, Controls, ReactFlow } from 'reactflow';
import 'reactflow/dist/style.css';
import { Database, Filter, Link2, Search } from 'lucide-react';
import { EmptyState, MetricCard, StatusBadge } from './common/Primitives';
import type { CIRGraph, CIRNode, CIRSpecification } from '../types/api';

type KnowledgeEntity = {
  id: string;
  entity_type: string;
  name: string;
  description?: string;
  provenance?: string;
  confidence?: number;
  attributes?: Record<string, unknown>;
  stix_id?: string;
  stix_type?: string;
  related_steps: CIRNode[];
};

type KnowledgeRelationship = {
  id: string;
  source: string;
  target: string;
  relationship: string;
  provenance?: string;
  confidence?: number;
};

const ENTITY_COLORS: Record<string, { background: string; border: string; color: string }> = {
  threat_actor: { background: '#2a171d', border: '#7a4050', color: '#ffd5de' },
  intrusion_set: { background: '#2a171d', border: '#7a4050', color: '#ffd5de' },
  malware: { background: '#2b1d13', border: '#895a2f', color: '#ffd9b0' },
  technique: { background: '#13283a', border: '#41799f', color: '#d8f0ff' },
  tactic: { background: '#201a3d', border: '#6555ad', color: '#e2dcff' },
  asset: { background: '#10281f', border: '#32735a', color: '#d3f7e6' },
  identity: { background: '#172333', border: '#46688f', color: '#d9eaff' },
  vulnerability: { background: '#331d17', border: '#8a4e3d', color: '#ffd8ce' },
  observable: { background: '#18252c', border: '#4f7585', color: '#dff4fb' },
  evidence: { background: '#222417', border: '#747a43', color: '#f1f5c6' },
  detection_rule: { background: '#172b38', border: '#5894b1', color: '#dff3fb' },
  defensive_control: { background: '#10271f', border: '#3d8568', color: '#cdf8e5' },
  trust_zone: { background: '#1f2430', border: '#59687f', color: '#dbe6f5' },
};

const titleCase = (value: string) => value.replaceAll('_', ' ').replace(/\b\w/g, (char) => char.toUpperCase());
const asString = (value: unknown) => (typeof value === 'string' ? value : undefined);
const asNumber = (value: unknown) => (typeof value === 'number' ? value : undefined);

function entitySearchText(entity: KnowledgeEntity) {
  return `${entity.id} ${entity.name} ${entity.entity_type} ${entity.description ?? ''} ${entity.stix_id ?? ''}`.toLowerCase();
}

function relationshipEndpoint(relationship: Record<string, unknown>, key: 'source' | 'target') {
  return asString(relationship[key]) ?? asString(relationship[key === 'source' ? 'from' : 'to']) ?? '';
}

function buildKnowledgeModel(specification: CIRSpecification, attackGraph: CIRGraph) {
  const entities = new Map<string, KnowledgeEntity>();
  const relationships = new Map<string, KnowledgeRelationship>();

  const addEntity = (entity: Partial<KnowledgeEntity> & { id: string; entity_type: string; name: string }) => {
    const existing = entities.get(entity.id);
    const relatedSteps = [...(existing?.related_steps ?? []), ...(entity.related_steps ?? [])];
    const uniqueRelatedSteps = Array.from(new Map(relatedSteps.map((step) => [step.step_id, step])).values());
    entities.set(entity.id, {
      ...existing,
      ...entity,
      attributes: { ...(existing?.attributes ?? {}), ...(entity.attributes ?? {}) },
      related_steps: uniqueRelatedSteps,
    });
  };

  const addRelationship = (relationship: KnowledgeRelationship) => {
    if (!relationship.source || !relationship.target || relationship.source === relationship.target) return;
    relationships.set(relationship.id, relationship);
  };

  for (const rawEntity of specification.entities ?? []) {
    const id = asString(rawEntity.id);
    const entityType = asString(rawEntity.entity_type);
    if (!id || !entityType) continue;
    addEntity({
      id,
      entity_type: entityType,
      name: asString(rawEntity.name) ?? titleCase(entityType),
      description: asString(rawEntity.description),
      provenance: asString(rawEntity.provenance),
      confidence: asNumber(rawEntity.confidence),
      attributes: typeof rawEntity.attributes === 'object' && rawEntity.attributes ? rawEntity.attributes as Record<string, unknown> : {},
      stix_id: asString(rawEntity.stix_id),
      stix_type: asString(rawEntity.stix_type),
      related_steps: attackGraph.nodes.filter((node) => node.entity_refs?.includes(id)),
    });
  }

  for (const node of attackGraph.nodes) {
    const techniqueId = `technique:${node.technique}`;
    const tacticId = `tactic:${node.tactic}`;
    const assetId = `asset:${node.target}`;

    addEntity({
      id: techniqueId,
      entity_type: 'technique',
      name: node.technique_name || node.technique,
      description: node.action_type,
      confidence: node.confidence ?? undefined,
      attributes: { technique_id: node.technique, attack_version: node.attack_version, data_sources: node.attack_data_sources },
      related_steps: [node],
    });
    addEntity({
      id: tacticId,
      entity_type: 'tactic',
      name: node.tactic_name || node.tactic,
      attributes: { tactic_id: node.tactic },
      related_steps: [node],
    });
    addEntity({
      id: assetId,
      entity_type: 'asset',
      name: node.target,
      attributes: { source: 'attack_graph_target' },
      related_steps: [node],
    });

    if (node.actor) {
      const actorId = `actor:${node.actor}`;
      addEntity({ id: actorId, entity_type: 'threat_actor', name: node.actor, related_steps: [node] });
      addRelationship({ id: `${actorId}-${techniqueId}-USES`, source: actorId, target: techniqueId, relationship: 'USES', confidence: node.confidence ?? undefined });
    }

    addRelationship({ id: `${tacticId}-${techniqueId}-CONNECTED_TO`, source: tacticId, target: techniqueId, relationship: 'CONNECTED_TO', confidence: node.confidence ?? undefined });
    addRelationship({ id: `${techniqueId}-${assetId}-TARGETS`, source: techniqueId, target: assetId, relationship: 'TARGETS', confidence: node.confidence ?? undefined });

    for (const evidence of node.evidence ?? []) {
      const evidenceText = asString(evidence.description) ?? asString(evidence.evidence_text) ?? asString(evidence.source) ?? asString(evidence.type);
      if (!evidenceText) continue;
      const evidenceId = `evidence:${node.step_id}:${evidenceText.slice(0, 32)}`;
      addEntity({
        id: evidenceId,
        entity_type: 'evidence',
        name: evidenceText,
        description: asString(evidence.description) ?? asString(evidence.evidence_text),
        provenance: asString(evidence.provenance) ?? asString(evidence.source),
        confidence: evidence.confidence,
        attributes: { type: evidence.type, telemetry_source: evidence.telemetry_source, validation_state: evidence.validation_state },
        related_steps: [node],
      });
      addRelationship({ id: `${evidenceId}-${techniqueId}-PRODUCES`, source: evidenceId, target: techniqueId, relationship: 'PRODUCES', confidence: evidence.confidence });
    }
  }

  for (const rawRelationship of specification.relationships ?? []) {
    const source = relationshipEndpoint(rawRelationship, 'source');
    const target = relationshipEndpoint(rawRelationship, 'target');
    const relationship = asString(rawRelationship.relationship);
    if (!source || !target || !relationship) continue;
    addRelationship({
      id: asString(rawRelationship.stix_id) ?? `${source}-${target}-${relationship}`,
      source,
      target,
      relationship,
      provenance: asString(rawRelationship.provenance),
      confidence: asNumber(rawRelationship.confidence),
    });
  }

  return { entities: Array.from(entities.values()), relationships: Array.from(relationships.values()) };
}

export default function KnowledgeGraphExplorer({ specification, attackGraph }: { specification: CIRSpecification; attackGraph: CIRGraph }) {
  const [query, setQuery] = useState('');
  const [entityType, setEntityType] = useState('ALL');
  const [relationshipType, setRelationshipType] = useState('ALL');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const model = useMemo(() => buildKnowledgeModel(specification, attackGraph), [specification, attackGraph]);
  const entityTypes = useMemo(() => ['ALL', ...Array.from(new Set(model.entities.map((entity) => entity.entity_type))).sort()], [model.entities]);
  const relationshipTypes = useMemo(() => ['ALL', ...Array.from(new Set(model.relationships.map((relationship) => relationship.relationship))).sort()], [model.relationships]);

  const filtered = useMemo(() => {
    const search = query.trim().toLowerCase();
    const entities = model.entities.filter((entity) => (entityType === 'ALL' || entity.entity_type === entityType) && (!search || entitySearchText(entity).includes(search)));
    const ids = new Set(entities.map((entity) => entity.id));
    const relationships = model.relationships.filter((relationship) => (relationshipType === 'ALL' || relationship.relationship === relationshipType) && ids.has(relationship.source) && ids.has(relationship.target));
    return { entities, relationships, ids };
  }, [entityType, model.entities, model.relationships, query, relationshipType]);

  const selected = model.entities.find((entity) => entity.id === selectedId) ?? filtered.entities[0];
  const visibleRelationships = filtered.relationships.filter((relationship) => !selected || relationship.source === selected.id || relationship.target === selected.id);

  const graphNodes = filtered.entities.map((entity, index) => {
    const color = ENTITY_COLORS[entity.entity_type] ?? { background: '#172632', border: '#426176', color: '#dff3fb' };
    return {
      id: entity.id,
      data: { label: entity.name },
      position: { x: (index % 4) * 250, y: Math.floor(index / 4) * 155 },
      style: { ...color, border: `${selected?.id === entity.id ? 2 : 1}px solid ${color.border}`, borderRadius: 6, fontSize: 12, width: 190 },
    };
  });

  const graphEdges = filtered.relationships.map((relationship) => ({
    id: relationship.id,
    source: relationship.source,
    target: relationship.target,
    label: relationship.relationship,
    animated: relationship.relationship === 'USES' || relationship.relationship === 'EXPLOITS',
    style: { stroke: '#6f8794' },
    labelStyle: { fill: '#dce7ec', fontSize: 10 },
  }));

  if (!model.entities.length) {
    return <EmptyState title="No knowledge entities available" description="Analyze or import a CIR v2 scenario with entities, relationships, techniques, assets, or evidence." />;
  }

  return (
    <div className="knowledge-explorer">
      <div className="metric-grid">
        <MetricCard label="Entities" value={model.entities.length} detail={`${entityTypes.length - 1} entity types`} />
        <MetricCard label="Relationships" value={model.relationships.length} detail={`${relationshipTypes.length - 1} relationship types`} />
        <MetricCard label="ATT&CK Techniques" value={model.entities.filter((entity) => entity.entity_type === 'technique').length} tone="good" />
        <MetricCard label="Evidence Items" value={model.entities.filter((entity) => entity.entity_type === 'evidence').length} />
      </div>

      <div className="knowledge-toolbar">
        <label>
          <Search size={15} />
          <span className="sr-only">Search knowledge graph</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search actor, CVE, technique, asset, detection, evidence" />
        </label>
        <label>
          <Filter size={15} />
          <span className="sr-only">Entity type</span>
          <select value={entityType} onChange={(event) => setEntityType(event.target.value)}>
            {entityTypes.map((type) => <option key={type} value={type}>{type === 'ALL' ? 'All entity types' : titleCase(type)}</option>)}
          </select>
        </label>
        <label>
          <Link2 size={15} />
          <span className="sr-only">Relationship type</span>
          <select value={relationshipType} onChange={(event) => setRelationshipType(event.target.value)}>
            {relationshipTypes.map((type) => <option key={type} value={type}>{type === 'ALL' ? 'All relationships' : type}</option>)}
          </select>
        </label>
      </div>

      <div className="knowledge-layout">
        <aside className="knowledge-catalog" aria-label="Knowledge entity catalog">
          <div className="knowledge-section-title"><Database size={15} /> Entity Catalog</div>
          <div className="knowledge-entity-list">
            {filtered.entities.map((entity) => (
              <button key={entity.id} className={selected?.id === entity.id ? 'active' : ''} onClick={() => setSelectedId(entity.id)}>
                <span>{entity.name}</span>
                <small>{titleCase(entity.entity_type)}</small>
              </button>
            ))}
          </div>
        </aside>

        <div className="knowledge-map" aria-label="Typed relationship map">
          <ReactFlow nodes={graphNodes} edges={graphEdges} onNodeClick={(_, node) => setSelectedId(node.id)} fitView>
            <Background />
            <Controls />
          </ReactFlow>
        </div>

        <aside className="knowledge-inspector" aria-label="Knowledge entity inspector">
          {selected ? (
            <>
              <div className="knowledge-inspector-head">
                <StatusBadge tone="info">{titleCase(selected.entity_type)}</StatusBadge>
                <h2>{selected.name}</h2>
                <p className="mono">{selected.id}</p>
              </div>
              <dl>
                {selected.stix_id && <><dt>STIX ID</dt><dd className="mono">{selected.stix_id}</dd></>}
                {selected.stix_type && <><dt>STIX Type</dt><dd>{selected.stix_type}</dd></>}
                {selected.confidence !== undefined && <><dt>Confidence</dt><dd>{Math.round(selected.confidence * 100)}%</dd></>}
                {selected.provenance && <><dt>Provenance</dt><dd>{selected.provenance}</dd></>}
                {selected.description && <><dt>Description</dt><dd>{selected.description}</dd></>}
              </dl>
              <div className="knowledge-section-title">Related Attack Steps</div>
              <div className="knowledge-related">
                {selected.related_steps.length ? selected.related_steps.map((step) => <span key={step.step_id}>{step.action_type || step.technique}</span>) : <small>No direct scenario step reference.</small>}
              </div>
              {Object.keys(selected.attributes ?? {}).length > 0 && (
                <pre className="knowledge-attributes">{JSON.stringify(selected.attributes, null, 2)}</pre>
              )}
            </>
          ) : <EmptyState title="Select an entity" description="Pick an entity to inspect metadata, provenance, and related attack steps." />}
        </aside>
      </div>

      <div className="knowledge-relationships">
        <div className="knowledge-section-title">Typed Relationships</div>
        <div className="data-list">
          {visibleRelationships.length ? visibleRelationships.map((relationship) => {
            const source = model.entities.find((entity) => entity.id === relationship.source);
            const target = model.entities.find((entity) => entity.id === relationship.target);
            return (
              <div className="data-row" key={relationship.id}>
                <div>
                  <strong>{`${source?.name ?? relationship.source} -> ${target?.name ?? relationship.target}`}</strong>
                  <small>{source ? titleCase(source.entity_type) : 'Unknown'} to {target ? titleCase(target.entity_type) : 'Unknown'}</small>
                </div>
                <StatusBadge>{relationship.relationship}</StatusBadge>
              </div>
            );
          }) : <EmptyState title="No relationships in the current filter" description="Broaden the entity or relationship filters to see connected knowledge." />}
        </div>
      </div>
    </div>
  );
}
