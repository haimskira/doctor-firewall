import { Link } from 'react-router-dom';

import type {
  AffectedRule,
  DynamicPreview,
  PreviewObject,
  PreviewRule,
  RecommendationKind,
  RecommendationPreview,
  PreviewFieldName,
  RuleRecTag,
} from '../api/types';
import { useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';
import { Ltr } from './common';
import { MapChange } from './mapParts';

type TagGroup = 'remove' | 'split' | 'merge' | 'tighten' | 'rename' | 'object' | 'inspect';

const TAG_GROUPS = new Map<RecommendationKind, TagGroup>([
  ['remove_shadowed_rule', 'remove'],
  ['remove_dead_rule', 'remove'],
  ['remove_unused_object', 'remove'],
  ['split_rule', 'split'],
  ['split_group', 'split'],
  ['merge_rules', 'merge'],
  ['merge_groups', 'merge'],
  ['merge_duplicate_objects', 'merge'],
  ['tighten_source', 'tighten'],
  ['tighten_ports', 'tighten'],
  ['rename_role', 'rename'],
  ['rename_convention', 'rename'],
  ['literal_to_object', 'object'],
  ['add_inspection', 'inspect'],
  ['add_file_policy', 'inspect'],
  ['ssl_exempt_core', 'inspect'],
  ['ssl_decrypt_inbound', 'inspect'],
  ['fastpath_candidate', 'inspect'],
  ['remove_redundant_reference', 'remove'],
  ['remove_redundant_member', 'remove'],
  ['remove_disabled_rule', 'remove'],
  ['compact_group', 'merge'],
  ['use_dynamic_object', 'object'],
]);

export function tagGroup(kind: RecommendationKind): TagGroup {
  return TAG_GROUPS.get(kind) ?? 'object';
}

/** The summary tag a rule carries in the policy editor (type + deploy cost). */
export function RecTag({ tag, snapshotId }: { tag: RuleRecTag; snapshotId: number }) {
  const { t } = useI18n();
  const group = tagGroup(tag.kind);
  const title = t('rec.tagTitle', {
    kind: t(`rec.kind.${tag.kind}`),
    cost: tag.deploy_cost,
    status: t(`rec.state.${tag.status}`),
  });
  return (
    <Link
      className={`rec-tag tag-${group}${tag.status === 'accepted' ? ' accepted' : ''}`}
      to={`/recommendations?snapshot=${String(snapshotId)}&rec=${String(tag.id)}`}
      title={title}
      aria-label={title}
    >
      {t(`rec.tag.${group}`)}
      <span className="cost">{tag.deploy_cost}</span>
    </Link>
  );
}

/** Signed number with a real minus sign, e.g. "−120" / "+15". */
export function signed(value: number): string {
  if (value > 0) return `+${value.toLocaleString()}`;
  if (value < 0) return `−${Math.abs(value).toLocaleString()}`;
  return '0';
}

const FIELD_ORDER: readonly PreviewFieldName[] = [
  'src_zone',
  'src_net',
  'src_sgt',
  'src_dyn',
  'user',
  'dst_zone',
  'dst_net',
  'dst_sgt',
  'dst_dyn',
  'src_port',
  'dst_port',
  'app',
  'url',
  'vlan',
  'ips_policy',
  'file_policy',
];

/** Fields always shown on a rule card: empty means "any", and that must be visible. */
const CORE_FIELDS: ReadonlySet<PreviewFieldName> = new Set<PreviewFieldName>([
  'src_zone',
  'src_net',
  'dst_zone',
  'dst_net',
  'dst_port',
]);

/** Other conditions on the same side: with one of them, an empty network field is not "any". */
const SIDE_CONDITIONS = new Map<PreviewFieldName, PreviewFieldName[]>([
  ['src_net', ['src_dyn', 'src_sgt', 'user']],
  ['dst_net', ['dst_dyn', 'dst_sgt']],
]);

/** How a value is drawn: removed (red, struck), added / changed (green), the object that
 * already holds a removed one (green, outlined), or unchanged. */
type Mark = 'del' | 'add' | 'keep' | undefined;
type Classify = (field: string, value: string) => Mark;

function fieldValues(rule: PreviewRule, field: PreviewFieldName): string[] {
  return new Map(Object.entries(rule.fields)).get(field) ?? [];
}

function fieldChange(rule: PreviewRule, field: PreviewFieldName | 'name' | 'action'): { added: string[]; removed: string[] } | undefined {
  return new Map(Object.entries(rule.changes ?? {})).get(field);
}

function Chip({ value, mark }: { value: string; mark: Mark }) {
  const { t } = useI18n();
  if (mark === 'del') {
    return (
      <del className="chip diff-del" title={t('rec.mark.del')}>
        <Ltr>{value}</Ltr>
      </del>
    );
  }
  if (mark === 'add') {
    return (
      <ins className="chip diff-add" title={t('rec.mark.add')}>
        <Ltr>{value}</Ltr>
      </ins>
    );
  }
  return (
    <span className={mark === 'keep' ? 'chip diff-keep' : 'chip'} title={mark === 'keep' ? t('rec.mark.keep') : undefined}>
      <Ltr>{value}</Ltr>
    </span>
  );
}

function FieldValues({
  rule,
  field,
  inline,
  classify,
}: {
  rule: PreviewRule;
  field: PreviewFieldName;
  inline: boolean;
  classify?: Classify | undefined;
}) {
  const { t } = useI18n();
  const values = fieldValues(rule, field);
  const change = inline ? fieldChange(rule, field) : undefined;
  const added = new Set(change?.added ?? []);
  const removed = change?.removed ?? [];
  const others = SIDE_CONDITIONS.get(field) ?? [];
  const elsewhere = others.some((f) => fieldValues(rule, f).length > 0);
  return (
    <span className="chips-inline">
      {values.length === 0 && removed.length === 0 && !elsewhere && <span className="chip any">{t('rules.any')}</span>}
      {values.map((v) => (
        <Chip key={v} value={v} mark={added.has(v) ? 'add' : classify?.(field, v)} />
      ))}
      {removed.map((v) => (
        <Chip key={`-${v}`} value={v} mark="del" />
      ))}
    </span>
  );
}

function RuleCard({ rule, inline, classify }: { rule: PreviewRule; inline: boolean; classify?: Classify | undefined }) {
  const { t } = useI18n();
  const status = rule.status ?? 'unchanged';
  const fields = FIELD_ORDER.filter(
    (f) => CORE_FIELDS.has(f) || fieldValues(rule, f).length > 0 || (inline && fieldChange(rule, f) !== undefined),
  );
  const rename = inline ? fieldChange(rule, 'name') : undefined;
  const actionChange = inline ? fieldChange(rule, 'action') : undefined;
  return (
    <div className={`rule-card status-${status}`}>
      <div className="rule-card-head">
        <span className="muted">{rule.index === null ? '+' : `#${String(rule.index)}`}</span>
        <strong>
          {rename !== undefined ? (
            <>
              <del className="diff-del">
                <Ltr>{rename.removed[0] ?? ''}</Ltr>
              </del>{' '}
              <ins className="diff-add">
                <Ltr>{rule.name}</Ltr>
              </ins>
            </>
          ) : (
            <Ltr>{rule.name}</Ltr>
          )}
        </strong>
        {actionChange !== undefined ? (
          <span className="badge">
            <del className="diff-del">
              <Ltr>{actionChange.removed[0] ?? ''}</Ltr>
            </del>{' '}
            <ins className="diff-add">
              <Ltr>{rule.action}</Ltr>
            </ins>
          </span>
        ) : (
          <span className="badge">
            <Ltr>{rule.action}</Ltr>
          </span>
        )}
        {status !== 'unchanged' && <span className={`badge status-${status}`}>{t(`rec.status.${status}`)}</span>}
      </div>
      <dl className="rule-card-fields">
        {fields.map((f) => (
          <div key={f}>
            <dt className="muted small">{t(`field.${f}`)}</dt>
            <dd>
              <FieldValues rule={rule} field={f} inline={inline} classify={classify} />
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function ObjectCard({ obj, classify }: { obj: PreviewObject; classify?: Classify | undefined }) {
  const { t } = useI18n();
  return (
    <div className={`rule-card status-${obj.status}`}>
      <div className="rule-card-head">
        <strong>
          <Ltr>{obj.name}</Ltr>
        </strong>
        <span className="badge">
          <Ltr>{obj.tier ?? obj.kind}</Ltr>
        </span>
        {obj.status !== 'unchanged' && <span className={`badge status-${obj.status}`}>{t(`rec.status.${obj.status}`)}</span>}
      </div>
      {obj.value !== undefined && obj.value !== null && (
        <div>
          <Ltr>{obj.value}</Ltr>
        </div>
      )}
      {obj.members !== undefined && obj.members.length > 0 && (
        <div className="small">
          <span className="muted">{t('rec.members')}: </span>
          <span className="chips-inline">
            {obj.members.map((m) => (
              <Chip key={m} value={m} mark={classify?.('members', m)} />
            ))}
          </span>
        </div>
      )}
      {obj.references !== undefined && <div className="muted small">{t('rec.references', { count: obj.references })}</div>}
    </div>
  );
}

// ---- before / after colouring ------------------------------------------------------------

interface Valued {
  id: string | null;
  status?: string;
}

/** The other side's values of one field for a card: the same rule / object when it lives on,
 * otherwise everything the other side keeps (a merged rule's values live on in the survivor). */
function counterpart<T extends Valued>(item: T, other: T[], values: (x: T, field: string) => string[]): (field: string) => Set<string> {
  const same = item.id === null ? undefined : other.find((o) => o.id === item.id && o.status !== 'removed');
  if (same !== undefined) return (field) => new Set(values(same, field));
  const alive = other.filter((o) => o.status !== 'removed');
  return (field) => new Set(alive.flatMap((o) => values(o, field)));
}

/** Objects that already hold a removed one ("already inside AAA": AAA), per field. */
function keptNames(preview: RecommendationPreview): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const r of preview.redundant ?? []) {
    const field = r.field ?? 'members';
    const set = out.get(field) ?? new Set<string>();
    set.add(r.kept);
    out.set(field, set);
  }
  return out;
}

function classifier(side: 'before' | 'after', lookup: (field: string) => Set<string>, kept: Map<string, Set<string>>): Classify {
  return (field, value) => {
    if (kept.get(field)?.has(value) === true) return 'keep';
    if (lookup(field).has(value)) return undefined;
    return side === 'before' ? 'del' : 'add';
  };
}

const ruleValues = (r: PreviewRule, field: string): string[] => fieldValues(r, field as PreviewFieldName);
const objectValues = (o: PreviewObject, field: string): string[] => (field === 'members' ? (o.members ?? []) : []);

function MarkLegend() {
  const { t } = useI18n();
  return (
    <p className="muted small mark-legend">
      <del className="chip diff-del">{t('rec.mark.del')}</del>
      <ins className="chip diff-add">{t('rec.mark.add')}</ins>
      <span className="chip diff-keep">{t('rec.mark.keep')}</span>
    </p>
  );
}

function AffectedRules({ rules, total, snapshotId }: { rules: AffectedRule[]; total: number; snapshotId: number }) {
  const { t } = useI18n();
  return (
    <section>
      <h3>{t('rec.affectedRules', { count: total })}</h3>
      <ul className="plain-list">
        {rules.map((r) => (
          <li key={`${r.policy_id}-${r.id}`}>
            <Link
              to={`/rules?snapshot=${String(snapshotId)}&policy=${encodeURIComponent(r.policy_id)}&q=${encodeURIComponent(r.name)}`}
            >
              #{r.index} <Ltr>{r.name}</Ltr>
            </Link>{' '}
            <span className="muted small">
              <Ltr>{r.policy_name}</Ltr>
            </span>
          </li>
        ))}
      </ul>
      {total > rules.length && <div className="muted small">…</div>}
    </section>
  );
}

/** Inline (changes in place) or split (before | after) preview of one recommendation. */
/** use_dynamic_object: what the address list was cross-checked with, and how close it is. */
function DynamicPanel({ dynamic }: { dynamic: DynamicPreview }) {
  const { t } = useI18n();
  const source =
    dynamic.source.type === 'group'
      ? t('rec.dyn.sourceGroup', { name: dynamic.source.name })
      : t(dynamic.source.side === 'destination' ? 'rec.dyn.sourceRuleDst' : 'rec.dyn.sourceRuleSrc', { name: dynamic.source.name });
  return (
    <div className="card dyn-panel">
      <h3>{t('rec.dyn.title')}</h3>
      <p className="small">
        {source} · {t('rec.dyn.addresses', { count: dynamic.addresses })}
      </p>
      <p className="small">
        <strong>{t(`rec.dyn.match.${dynamic.match}`, { name: dynamic.name, covered: dynamic.covered, total: dynamic.addresses })}</strong>
      </p>
      {!dynamic.create && (
        <p className="muted small">
          {t('rec.dyn.mapped', { count: dynamic.mapped_total })}
          {dynamic.truncated && <> · {t('rec.dyn.truncated', { kept: dynamic.mapped })}</>}
        </p>
      )}
      {dynamic.missing_count > 0 && (
        <div>
          <h4>{t('rec.dyn.missing', { count: dynamic.missing_count })}</h4>
          <span className="chips-inline">
            {dynamic.missing.map((a) => (
              <Chip key={a} value={a} mark="del" />
            ))}
          </span>
        </div>
      )}
      {dynamic.extra_count > 0 && (
        <div>
          <h4>{t('rec.dyn.extra', { count: dynamic.extra_count })}</h4>
          <span className="chips-inline">
            {dynamic.extra.map((a) => (
              <Chip key={a} value={a} mark="add" />
            ))}
          </span>
        </div>
      )}
      {dynamic.create && (
        <div>
          <h4>{t('rec.dyn.sample', { count: dynamic.addresses })}</h4>
          <span className="chips-inline">
            {dynamic.sample.map((a) => (
              <Chip key={a} value={a} mark={undefined} />
            ))}
          </span>
        </div>
      )}
      {dynamic.not_mappable > 0 && <p className="muted small">{t('rec.dyn.notMappable', { count: dynamic.not_mappable })}</p>}
      <p className="muted small">{t('rec.dyn.advisory')}</p>
    </div>
  );
}

export function RecommendationPreviewView({
  preview,
  view,
  snapshotId,
}: {
  preview: RecommendationPreview;
  view: 'inline' | 'split';
  snapshotId: number;
}) {
  const { t } = useI18n();
  const before = preview.before ?? [];
  const after = preview.after ?? [];
  const kept = keptNames(preview);
  const keepOnly: Classify = (field, value) => (kept.get(field)?.has(value) === true ? 'keep' : undefined);
  const label = (key: MessageKey) => <h3>{t(key)}</h3>;
  return (
    <div className="rec-preview">
      {(after.length > 0 || preview.objects !== undefined) && <MarkLegend />}
      {after.length > 0 &&
        (view === 'inline' ? (
          <div className="rule-cards">
            {after.map((r, i) => (
              <RuleCard key={`${r.id ?? 'new'}-${String(i)}`} rule={r} inline classify={keepOnly} />
            ))}
          </div>
        ) : (
          <div className="split-view">
            <div>
              {label('rec.before')}
              <div className="rule-cards">
                {before.map((r, i) => (
                  <RuleCard
                    key={`${r.id ?? 'b'}-${String(i)}`}
                    rule={r}
                    inline={false}
                    classify={classifier('before', counterpart(r, after, ruleValues), kept)}
                  />
                ))}
              </div>
            </div>
            <div>
              {label('rec.after')}
              <div className="rule-cards">
                {after
                  .filter((r) => r.status !== 'removed')
                  .map((r, i) => (
                    <RuleCard
                      key={`${r.id ?? 'a'}-${String(i)}`}
                      rule={r}
                      inline={false}
                      classify={classifier('after', counterpart(r, before, ruleValues), kept)}
                    />
                  ))}
              </div>
            </div>
          </div>
        ))}
      {preview.dynamic !== undefined && <DynamicPanel dynamic={preview.dynamic} />}
      {preview.map !== undefined && <MapChange before={preview.map.before} after={preview.map.after} />}
      {preview.rules !== undefined && preview.rules.length > 0 && (
        <div>
          <h3>{t('rec.tlsRules')}</h3>
          <ul className="plain-list small">
            {preview.rules.map((r) => (
              <li key={`${r.policy}-${r.id}`}>
                <bdi>{r.policy}</bdi> · #{r.index} <Ltr>{r.name}</Ltr>
              </li>
            ))}
          </ul>
        </div>
      )}
      {preview.objects !== undefined && (
        <div className="split-view">
          <div>
            {label('rec.before')}
            <div className="rule-cards">
              {preview.objects.before.map((o) => (
                <ObjectCard
                  key={`b-${o.id ?? o.name}`}
                  obj={o}
                  classify={classifier('before', counterpart(o, preview.objects?.after ?? [], objectValues), kept)}
                />
              ))}
            </div>
          </div>
          <div>
            {label('rec.after')}
            <div className="rule-cards">
              {preview.objects.after.map((o) => (
                <ObjectCard
                  key={`a-${o.id ?? o.name}-${o.status}`}
                  obj={o}
                  classify={classifier('after', counterpart(o, preview.objects?.before ?? [], objectValues), kept)}
                />
              ))}
            </div>
          </div>
        </div>
      )}
      {preview.rename !== undefined && (
        <p className="rename-line">
          <del className="diff-del">
            <Ltr>{preview.rename.from}</Ltr>
          </del>{' '}
          →{' '}
          <ins className="diff-add">
            <Ltr>{preview.rename.to}</Ltr>
          </ins>
        </p>
      )}
      {preview.literal !== undefined && (
        <p>
          {t(preview.literal.create ? 'rec.literalCreate' : 'rec.literalExisting', {
            kind: preview.literal.kind,
            name: preview.literal.object,
            value: preview.literal.value,
          })}
        </p>
      )}
      {preview.hits !== undefined && (
        <p className="muted small">
          {t('rec.hits', { count: preview.hits.hit_count ?? 0, last: preview.hits.last_hit ?? t('common.never') })}
        </p>
      )}
      {preview.affected_groups !== undefined && preview.affected_groups.length > 0 && (
        <p className="small">
          <span className="muted">{t('rec.affectedGroups')}: </span>
          <span className="chips-inline">
            {preview.affected_groups.map((g) => (
              <span key={g} className="chip">
                <Ltr>{g}</Ltr>
              </span>
            ))}
          </span>
        </p>
      )}
      {preview.routes !== undefined && preview.routes > 0 && (
        <p className="muted small">{t('rec.routes', { count: preview.routes })}</p>
      )}
      {preview.affected_rules !== undefined && preview.affected_rules.total > 0 && (
        <AffectedRules rules={preview.affected_rules.sample} total={preview.affected_rules.total} snapshotId={snapshotId} />
      )}
    </div>
  );
}
