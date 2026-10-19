import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import { ApiError, api, setCsrfToken } from '../api/client';
import type { Language, Me, Permission } from '../api/types';
import { useI18n } from '../i18n/I18nProvider';

type AuthState =
  | { status: 'loading' }
  | { status: 'anonymous' }
  | { status: 'authenticated'; me: Me };

interface AuthValue {
  state: AuthState;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  /** Replace the current identity (after password change / preference update). */
  setMe: (me: Me) => void;
  can: (permission: Permission) => boolean;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: 'loading' });
  const { setLanguage } = useI18n();

  const setMe = useCallback(
    (me: Me) => {
      setCsrfToken(me.csrf_token);
      setLanguage(me.language satisfies Language);
      setState({ status: 'authenticated', me });
    },
    [setLanguage],
  );

  useEffect(() => {
    let cancelled = false;
    api<Me>('/api/auth/me')
      .then((me) => {
        if (!cancelled) setMe(me);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setCsrfToken(null);
        setState({ status: 'anonymous' });
        if (!(error instanceof ApiError) || error.status !== 401) {
          console.error('session check failed');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [setMe]);

  const login = useCallback(
    async (username: string, password: string) => {
      const me = await api<Me>('/api/auth/login', 'POST', { username, password });
      setMe(me);
    },
    [setMe],
  );

  const logout = useCallback(async () => {
    try {
      await api<undefined>('/api/auth/logout', 'POST');
    } finally {
      setCsrfToken(null);
      setState({ status: 'anonymous' });
    }
  }, []);

  const can = useCallback(
    (permission: Permission) =>
      state.status === 'authenticated' &&
      !state.me.must_change_password &&
      state.me.permissions.includes(permission),
    [state],
  );

  const value = useMemo(
    () => ({ state, login, logout, setMe, can }) satisfies AuthValue,
    [state, login, logout, setMe, can],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (ctx === null) {
    throw new Error('useAuth must be used inside <AuthProvider>');
  }
  return ctx;
}

/** Only for components rendered behind the authenticated route guard. */
export function useMe(): Me {
  const { state } = useAuth();
  if (state.status !== 'authenticated') {
    throw new Error('useMe used outside an authenticated route');
  }
  return state.me;
}
