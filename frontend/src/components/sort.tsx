import { ArrowsDownUpIcon, CaretDownIcon, CaretUpIcon } from '@phosphor-icons/react';
import { useCallback, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';

import { useI18n } from '../i18n/I18nProvider';

/* Sortable table headers. A click on a column sorts by it — numbers start from the largest,
   text from A — and a second click reverses. Tables that hold all their rows sort in the
   browser (useClientSort); paged tables ask the server (useServerSort, kept in the URL as
   ?sort=&order= so a link or reload keeps the order). */

export type SortDir = 'asc' | 'desc';

export interface SortState {
  key: string;
  dir: SortDir;
}

export type SortValue = string | number | boolean | null | undefined;

interface HeaderProps {
  label: string;
  sortKey: string;
  state: SortState | null;
  onSort: (next: SortState) => void;
  numeric?: boolean;
  className?: string | undefined;
}

export function SortTh({ label, sortKey, state, onSort, numeric = false, className }: HeaderProps) {
  const { t } = useI18n();
  const active = state?.key === sortKey;
  const dir = active ? state.dir : null;
  const next: SortState = { key: sortKey, dir: dir === null ? (numeric ? 'desc' : 'asc') : dir === 'asc' ? 'desc' : 'asc' };
  return (
    <th
      className={['sortable', className].filter(Boolean).join(' ')}
      aria-sort={dir === null ? 'none' : dir === 'asc' ? 'ascending' : 'descending'}
    >
      <button
        type="button"
        className="th-sort"
        title={t(next.dir === 'asc' ? 'sort.asc' : 'sort.desc')}
        onClick={() => {
          onSort(next);
        }}
      >
        <span>{label}</span>
        <span className={`sort-icon${active ? ' active' : ''}`} aria-hidden="true">
          {dir === 'asc' ? <CaretUpIcon weight="bold" /> : dir === 'desc' ? <CaretDownIcon weight="bold" /> : <ArrowsDownUpIcon />}
        </span>
      </button>
    </th>
  );
}

function rank(value: SortValue): number {
  return value === null || value === undefined || value === '' ? 1 : 0;
}

/** Sort rows in the browser. ``columns`` maps a sort key to the value of a row. */
export function useClientSort<T>(
  rows: readonly T[],
  columns: Record<string, (row: T) => SortValue>,
  initial: SortState | null = null,
): { rows: T[]; state: SortState | null; onSort: (next: SortState) => void } {
  const { language } = useI18n();
  const [state, setState] = useState<SortState | null>(initial);
  const collator = useMemo(() => new Intl.Collator(language, { numeric: true, sensitivity: 'base' }), [language]);
  const getter = state === null ? undefined : columns[state.key];
  const sorted = useMemo(() => {
    if (state === null || getter === undefined) return [...rows];
    const sign = state.dir === 'asc' ? 1 : -1;
    // Stable: equal values keep their original order. Empty values always go last.
    return rows
      .map((row, index) => ({ row, index, value: getter(row) }))
      .sort((a, b) => {
        const empty = rank(a.value) - rank(b.value);
        if (empty !== 0) return empty;
        const diff =
          typeof a.value === 'number' && typeof b.value === 'number'
            ? a.value - b.value
            : typeof a.value === 'boolean' && typeof b.value === 'boolean'
              ? Number(a.value) - Number(b.value)
              : collator.compare(String(a.value ?? ''), String(b.value ?? ''));
        return diff === 0 ? a.index - b.index : sign * diff;
      })
      .map((x) => x.row);
  }, [rows, state, getter, collator]);
  return { rows: sorted, state, onSort: setState };
}

/** Sort state of a server-paged table, kept in the URL. Only ``allowed`` keys are honoured. */
export function useServerSort(allowed: readonly string[]): {
  state: SortState | null;
  onSort: (next: SortState) => void;
  query: Record<string, string>;
} {
  const [params, setParams] = useSearchParams();
  const key = params.get('sort');
  const order = params.get('order');
  const state: SortState | null =
    key !== null && allowed.includes(key) ? { key, dir: order === 'desc' ? 'desc' : 'asc' } : null;
  const onSort = useCallback(
    (next: SortState) => {
      setParams(
        (prev) => {
          const copy = new URLSearchParams(prev);
          copy.set('sort', next.key);
          copy.set('order', next.dir);
          copy.delete('offset');
          return copy;
        },
        { replace: true },
      );
    },
    [setParams],
  );
  const query: Record<string, string> = state === null ? {} : { sort: state.key, order: state.dir };
  return { state, onSort, query };
}

type HeaderCell = (key: string, label: string, numeric?: boolean, className?: string) => ReactNode;

/** ``<thead>`` + ``<tbody>`` of a table whose rows are all loaded, sorted by header clicks. */
export function SortedTable<T>({
  rows,
  columns,
  initial = null,
  limit,
  head,
  children,
}: {
  rows: readonly T[];
  columns: Record<string, (row: T) => SortValue>;
  initial?: SortState | null;
  /** Show only the first rows — of the sorted whole. */
  limit?: number;
  head: (th: HeaderCell) => ReactNode;
  children: (row: T, index: number) => ReactNode;
}) {
  const sort = useClientSort(rows, columns, initial);
  const th: HeaderCell = (key, label, numeric = false, className) => (
    <SortTh key={key} label={label} sortKey={key} state={sort.state} onSort={sort.onSort} numeric={numeric} className={className} />
  );
  return (
    <>
      <thead>{head(th)}</thead>
      <tbody>{(limit === undefined ? sort.rows : sort.rows.slice(0, limit)).map(children)}</tbody>
    </>
  );
}
