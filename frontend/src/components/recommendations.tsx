import { Link } from 'react-router-dom';

import type {
  AffectedRule,
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
  ['ssl_exempt_core', 'inspect'],
  ['ssl_decrypt_inbound', 'inspect'],
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

function fieldValues(rule: PreviewRule, field: PreviewFieldName): string[] {
  return new Map(Object.entries(rule.fields)).get(field) ?? [];
}

function fieldChange(rule: PreviewRule, field: PreviewFieldName | 'name' | 'action'): { added: string[]; removed: string[] } | undefined {
  return new Map(Object.entries(rule.changes ?? {})).get(field);
}

function FieldValues({ rule, field, inline }: { rule: PreviewRule; field: PreviewFieldName; inline: boolean }) {
  const values = fieldValues(rule, field);
  const change = inline ? fieldChange(rule, field) : undefined;
  const added = new Set(change?.added ?? []);
  return (
    <span className="chips-inline">
      {values.map((v) =>
        added.has(v) ? (
          <ins key={v} className="chip diff-add">
            <Ltr>{v}</Ltr>
          </ins>
        ) : (
          <span key={v} className="chip">
            <Ltr>{v}</Ltr>
          </span>
        ),
      )}
      {(change?.removed ?? []).map((v) => (
        <del key={`-${v}`} className="chip diff-del">
          <Ltr>{v}</Ltr>
        </del>
      ))}
    </span>
  );
}

function RuleCard({ rule, inline }: { rule: PreviewRule; inline: boolean }) {
  const { t } = useI18n();
  const status = rule.status ?? 'unchanged';
  const fields = FIELD_ORDER.filter(
    (f) => fieldValues(rule, f).length > 0 || (inline && fieldChange(rule, f) !== undefined),
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
      {fields.length === 0 ? (
        <div className="muted small">{t('rules.any')}</div>
      ) : (
        <dl className="rule-card-fields">
          {fields.map((f) => (
            <div key={f}>
              <dt className="muted small">{t(`field.${f}`)}</dt>
              <dd>
                <FieldValues rule={rule} field={f} inline={inline} />
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function ObjectCard({ obj }: { obj: PreviewObject }) {
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
              <span key={m} className="chip">
                <Ltr>{m}</Ltr>
              </span>
            ))}
          </span>
        </div>
      )}
      {obj.references !== undefined && <div className="muted small">{t('rec.references', { count: obj.references })}</div>}
    </div>
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
  const label = (key: MessageKey) => <h3>{t(key)}</h3>;
  return (
    <div className="rec-preview">
      {after.length > 0 &&
        (view === 'inline' ? (
          <div className="rule-cards">
            {after.map((r, i) => (
              <RuleCard key={`${r.id ?? 'new'}-${String(i)}`} rule={r} inline />
            ))}
          </div>
        ) : (
          <div className="split-view">
            <div>
              {label('rec.before')}
              <div className="rule-cards">
                {before.map((r, i) => (
                  <RuleCard key={`${r.id ?? 'b'}-${String(i)}`} rule={r} inline={false} />
                ))}
              </div>
            </div>
            <div>
              {label('rec.after')}
              <div className="rule-cards">
                {after
                  .filter((r) => r.status !== 'removed')
                  .map((r, i) => (
                    <RuleCard key={`${r.id ?? 'a'}-${String(i)}`} rule={r} inline={false} />
                  ))}
              </div>
            </div>
          </div>
        ))}
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
                <ObjectCard key={`b-${o.id ?? o.name}`} obj={o} />
              ))}
            </div>
          </div>
          <div>
            {label('rec.after')}
            <div className="rule-cards">
              {preview.objects.after.map((o) => (
                <ObjectCard key={`a-${o.id ?? o.name}-${o.status}`} obj={o} />
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
