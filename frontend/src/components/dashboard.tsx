import { CaretDownIcon, CaretRightIcon, MinusIcon, XIcon } from '@phosphor-icons/react';
import { useState } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { useI18n } from '../i18n/I18nProvider';
import { Ltr } from './common';

export type BarTone = 'blue' | 'green' | 'pink' | 'orange' | 'red' | 'yellow' | 'gray';

export interface BarRow {
  key: string;
  label: ReactNode;
  value: number;
  /** Text shown on the bar (defaults to the value). */
  display?: string;
  tone?: BarTone;
  to?: string;
}

/** Relative "last updated" text from an ISO timestamp. */
export function useRelativeTime(): (iso: string | null) => string {
  const { t, language } = useI18n();
  return (iso) => {
    if (iso === null) return t('common.never');
    const seconds = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
    const fmt = new Intl.RelativeTimeFormat(language === 'he' ? 'he' : 'en', { numeric: 'auto' });
    const units: [Intl.RelativeTimeFormatUnit, number][] = [
      ['day', 86400],
      ['hour', 3600],
      ['minute', 60],
    ];
    for (const [unit, size] of units) {
      if (Math.abs(seconds) >= size) return fmt.format(Math.round(seconds / size), unit);
    }
    return fmt.format(seconds, 'second');
  };
}

/** A dashboard widget as in the FMC: collapsible, minimisable, closable. */
export function Widget({
  title,
  footer,
  onClose,
  wide,
  children,
}: {
  title: string;
  footer?: string;
  onClose?: () => void;
  wide?: boolean;
  children: ReactNode;
}) {
  const { t } = useI18n();
  const [open, setOpen] = useState(true);
  return (
    <section className={`widget${wide === true ? ' wide' : ''}${open ? '' : ' closed'}`} aria-label={title}>
      <header className="widget-head">
        <button
          type="button"
          className="widget-icon"
          aria-expanded={open}
          aria-label={t(open ? 'dash.collapse' : 'dash.expand', { name: title })}
          onClick={() => {
            setOpen(!open);
          }}
        >
          {open ? <CaretDownIcon size={14} aria-hidden="true" /> : <CaretRightIcon size={14} className="flip-rtl" aria-hidden="true" />}
        </button>
        <h2>{title}</h2>
        <button
          type="button"
          className="widget-icon"
          aria-label={t('dash.minimize', { name: title })}
          onClick={() => {
            setOpen(false);
          }}
        >
          <MinusIcon size={14} aria-hidden="true" />
        </button>
        {onClose !== undefined && (
          <button type="button" className="widget-icon" aria-label={t('dash.close', { name: title })} onClick={onClose}>
            <XIcon size={14} aria-hidden="true" />
          </button>
        )}
      </header>
      {open && (
        <>
          <div className="widget-body">{children}</div>
          {footer !== undefined && <footer className="widget-foot">{footer}</footer>}
        </>
      )}
    </section>
  );
}

/** Two-column table with a proportional bar behind each value (FMC "Top …" widgets). */
export function BarTable({
  rows,
  labelHeader,
  valueHeader,
  tone = 'blue',
  empty,
}: {
  rows: BarRow[];
  labelHeader: string;
  valueHeader: string;
  tone?: BarTone;
  empty: string;
}) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  if (rows.length === 0) return <p className="widget-empty">{empty}</p>;
  return (
    <table className="bar-table">
      <thead>
        <tr>
          <th scope="col">{labelHeader}</th>
          <th scope="col" className="num">
            {valueHeader}
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.key}>
            <td>{r.to !== undefined ? <Link to={r.to}>{r.label}</Link> : r.label}</td>
            <td className="num">
              <span className="bar-cell">
                <span
                  className={`bar tone-${r.tone ?? tone}`}
                  style={{ inlineSize: `${String(Math.max(2, Math.round((r.value / max) * 100)))}%` }}
                  aria-hidden="true"
                />
                <Ltr>{r.display ?? r.value.toLocaleString()}</Ltr>
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Large figures (FMC status tiles). */
export function Figures({ items }: { items: { key: string; label: string; value: number | string; to?: string }[] }) {
  return (
    <dl className="figures">
      {items.map((i) => (
        <div key={i.key}>
          <dt>{i.label}</dt>
          <dd>{i.to !== undefined ? <Link to={i.to}>{typeof i.value === 'number' ? i.value.toLocaleString() : i.value}</Link> : typeof i.value === 'number' ? i.value.toLocaleString() : i.value}</dd>
        </div>
      ))}
    </dl>
  );
}
