import { useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';

import { api, errorCode } from '../api/client';
import type { ObjectDetail } from '../api/types';
import { useI18n } from '../i18n/I18nProvider';
import { Ltr } from './common';

const DELAY_MS = 300;
const SHOWN = 8;
// Object details per snapshot + id, shared by every chip on the page (one request each).
const cache = new Map<string, Promise<ObjectDetail>>();

function load(snapshotId: number, objectId: string): Promise<ObjectDetail> {
  const key = `${String(snapshotId)}:${objectId}`;
  let pending = cache.get(key);
  if (pending === undefined) {
    pending = api<ObjectDetail>(`/api/snapshots/${String(snapshotId)}/objects/${encodeURIComponent(objectId)}`);
    pending.catch(() => cache.delete(key));
    cache.set(key, pending);
  }
  return pending;
}

/** Test hook: forget cached details. */
export function clearObjectHoverCache(): void {
  cache.clear();
}

/**
 * Hover / focus card for an object reference: its value, its members and the groups it
 * belongs to. Positioned against the viewport so scrolling tables do not clip it.
 */
export function ObjectHover({
  snapshotId,
  objectId,
  children,
}: {
  snapshotId: number;
  objectId: string;
  children: ReactNode;
}) {
  const { t, tError } = useI18n();
  const id = useId();
  const anchor = useRef<HTMLSpanElement>(null);
  const timer = useRef<number | null>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number }>({ top: 0, left: 0 });
  const [detail, setDetail] = useState<ObjectDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    },
    [],
  );

  function show() {
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      const box = anchor.current?.getBoundingClientRect();
      if (box !== undefined) {
        const left = Math.max(8, Math.min(box.left, window.innerWidth - 340));
        const below = box.bottom + 6;
        setPos({ top: below + 240 > window.innerHeight ? Math.max(8, box.top - 246) : below, left });
      }
      setOpen(true);
      load(snapshotId, objectId)
        .then((d) => {
          setDetail(d);
        })
        .catch((err: unknown) => {
          setError(errorCode(err));
        });
    }, DELAY_MS);
  }

  function hide() {
    if (timer.current !== null) window.clearTimeout(timer.current);
    setOpen(false);
  }

  const members = detail?.members ?? [];
  const parents = [...new Map((detail?.member_of ?? []).filter((m) => m.depth === 1).map((m) => [m.group_id, m.group_name])).values()];
  return (
    <span
      ref={anchor}
      className="hover-anchor"
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
      aria-describedby={open ? id : undefined}
    >
      {children}
      {open && (
        <span id={id} role="tooltip" className="object-card" style={{ top: pos.top, left: pos.left }}>
          {error !== null ? (
            <span className="bad">{tError(error)}</span>
          ) : detail === null ? (
            <span className="muted">{t('common.loading')}</span>
          ) : (
            <>
              <span className="object-card-head">
                <strong>
                  <Ltr>{detail.object.name}</Ltr>
                </strong>
                <span className="badge">
                  <Ltr>{detail.object.fmc_type}</Ltr>
                </span>
              </span>
              {detail.object.value !== null && (
                <span className="object-card-row">
                  <span className="muted">{t('hover.value')}</span>
                  <Ltr>{detail.object.value}</Ltr>
                </span>
              )}
              {members.length > 0 && (
                <span className="object-card-row">
                  <span className="muted">{t('hover.members', { count: members.length })}</span>
                  <span className="chips-inline">
                    {members.slice(0, SHOWN).map((m, i) => (
                      <span key={`${m.id ?? m.literal ?? ''}-${String(i)}`} className="chip">
                        <Ltr>{m.literal ?? m.name}</Ltr>
                      </span>
                    ))}
                    {members.length > SHOWN && <span className="muted">+{members.length - SHOWN}</span>}
                  </span>
                </span>
              )}
              <span className="object-card-row">
                <span className="muted">{t('hover.memberOf')}</span>
                {parents.length === 0 ? (
                  <span className="muted">{t('hover.none')}</span>
                ) : (
                  <span className="chips-inline">
                    {parents.slice(0, SHOWN).map((name) => (
                      <span key={name} className="chip">
                        <Ltr>{name}</Ltr>
                      </span>
                    ))}
                    {parents.length > SHOWN && <span className="muted">+{parents.length - SHOWN}</span>}
                  </span>
                )}
              </span>
              <span className="object-card-row muted">{t('hover.usedBy', { count: detail.used_by_total })}</span>
            </>
          )}
        </span>
      )}
    </span>
  );
}
