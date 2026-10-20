import type { ScoreReason } from '../api/types';
import { useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';
import { en } from '../i18n/messages';

function reasonKey(code: string): MessageKey | null {
  const key = `score.reason.${code}`;
  return Object.prototype.hasOwnProperty.call(en, key) ? (key as MessageKey) : null;
}

/** Translate a score deduction; unknown codes fall back to the raw code. */
export function useReasonText(): (reason: ScoreReason) => string {
  const { t } = useI18n();
  return (reason) => {
    const key = reasonKey(reason.code);
    const vars = Object.fromEntries(
      Object.entries(reason).filter(
        (entry): entry is [string, string | number] => typeof entry[1] === 'string' || typeof entry[1] === 'number',
      ),
    );
    return key === null ? reason.code : t(key, vars);
  };
}

export function ScoreBadge({ score }: { score: number | null | undefined }) {
  const { t } = useI18n();
  if (score === null || score === undefined) return <span className="muted small">{t('score.none')}</span>;
  const band = score >= 80 ? 'good' : score >= 50 ? 'warn' : 'bad';
  return <span className={`score score-${band}`}>{score}</span>;
}

export function ReasonList({ reasons }: { reasons: ScoreReason[] }) {
  const { t } = useI18n();
  const text = useReasonText();
  if (reasons.length === 0) return <p className="muted small">{t('score.perfect')}</p>;
  return (
    <ul className="reasons">
      {reasons.map((r, i) => (
        <li key={`${r.code}-${String(i)}`}>
          <span className="points">{r.points > 0 ? `−${String(r.points)}` : '·'}</span> {text(r)}
        </li>
      ))}
    </ul>
  );
}
