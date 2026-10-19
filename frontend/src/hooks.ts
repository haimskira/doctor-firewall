import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { api, errorCode } from './api/client';
import type { Snapshot } from './api/types';

export interface Loaded<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

interface Result<T> {
  key: string;
  data: T | null;
  error: string | null;
}

/**
 * GET ``path`` (null = skip) and expose data / error code / reload.
 * State is keyed by request, so nothing is reset synchronously inside an effect;
 * the previous data stays visible while a reload (e.g. polling) is in flight.
 */
export function useApi<T>(path: string | null): Loaded<T> {
  const [result, setResult] = useState<Result<T> | null>(null);
  const [tick, setTick] = useState(0);
  const key = path === null ? null : `${path}#${String(tick)}`;

  useEffect(() => {
    if (path === null || key === null) return;
    let cancelled = false;
    api<T>(path)
      .then((value) => {
        if (!cancelled) setResult({ key, data: value, error: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) setResult({ key, data: null, error: errorCode(err) });
      });
    return () => {
      cancelled = true;
    };
  }, [path, key]);

  const reload = useCallback(() => {
    setTick((n) => n + 1);
  }, []);
  const samePath = result !== null && path !== null && result.key.startsWith(`${path}#`);
  return {
    data: samePath ? result.data : null,
    error: samePath ? result.error : null,
    loading: key !== null && result?.key !== key,
    reload,
  };
}

/** URL query parameter as state (keeps views linkable and back-button friendly). */
export function useQueryParam(name: string): [string | null, (value: string | null) => void] {
  const [params, setParams] = useSearchParams();
  const value = params.get(name);
  const set = useCallback(
    (next: string | null) => {
      setParams(
        (prev) => {
          const copy = new URLSearchParams(prev);
          if (next === null || next === '') copy.delete(name);
          else copy.set(name, next);
          return copy;
        },
        { replace: true },
      );
    },
    [name, setParams],
  );
  return [value, set];
}

/** Completed snapshots, and the selected one (``?snapshot=``; defaults to the newest). */
export function useSnapshotSelection(): {
  snapshots: Snapshot[];
  snapshotId: number | null;
  setSnapshotId: (id: number) => void;
  error: string | null;
} {
  const { data, error } = useApi<Snapshot[]>('/api/snapshots?limit=200');
  const [param, setParam] = useQueryParam('snapshot');
  const complete = (data ?? []).filter((s) => s.status === 'complete');
  const parsed = param !== null && /^\d+$/.test(param) ? Number(param) : null;
  const snapshotId =
    parsed !== null && complete.some((s) => s.id === parsed) ? parsed : (complete[0]?.id ?? null);
  const setSnapshotId = useCallback(
    (id: number) => {
      setParam(String(id));
    },
    [setParam],
  );
  return { snapshots: complete, snapshotId, setSnapshotId, error };
}
