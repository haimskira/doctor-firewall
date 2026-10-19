import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { I18nProvider, interpolate, useI18n } from './I18nProvider';
import { en, he } from './messages';
import type { MessageKey } from './messages';

describe('message catalogs', () => {
  it('have exactly the same keys and no empty strings', () => {
    expect(Object.keys(he).sort()).toEqual(Object.keys(en).sort());
    for (const value of [...Object.values(he), ...Object.values(en)]) {
      expect(value.trim()).not.toBe('');
    }
  });

  it('keep the same placeholders in both languages', () => {
    const placeholders = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort();
    for (const key of Object.keys(en) as MessageKey[]) {
      // Keys come from the typed catalog itself.
      // eslint-disable-next-line security/detect-object-injection
      expect(placeholders(he[key])).toEqual(placeholders(en[key]));
    }
  });
});

describe('interpolate', () => {
  it('replaces known placeholders as plain text', () => {
    expect(interpolate('hi {name}', { name: '<b>x</b>' })).toBe('hi <b>x</b>');
    expect(interpolate('{a} {missing}', { a: 1 })).toBe('1 {missing}');
  });
});

function Probe() {
  const { t, tError, dir, setLanguage, language } = useI18n();
  return (
    <div>
      <span data-testid="dir">{dir}</span>
      <span data-testid="title">{t('nav.home')}</span>
      <span data-testid="err">{tError('forbidden')}</span>
      <span data-testid="unknown">{tError('weird_code')}</span>
      <button
        type="button"
        onClick={() => {
          setLanguage(language === 'he' ? 'en' : 'he');
        }}
      >
        toggle
      </button>
    </div>
  );
}

describe('I18nProvider', () => {
  it('defaults to Hebrew RTL and switches to English LTR', async () => {
    render(
      <I18nProvider>
        <Probe />
      </I18nProvider>,
    );
    expect(screen.getByTestId('dir')).toHaveTextContent('rtl');
    expect(document.documentElement.dir).toBe('rtl');
    expect(document.documentElement.lang).toBe('he');
    expect(screen.getByTestId('title')).toHaveTextContent(he['nav.home']);
    expect(screen.getByTestId('err')).toHaveTextContent(he['error.forbidden']);
    expect(screen.getByTestId('unknown')).toHaveTextContent('weird_code');

    await userEvent.click(screen.getByRole('button', { name: 'toggle' }));
    expect(document.documentElement.dir).toBe('ltr');
    expect(screen.getByTestId('title')).toHaveTextContent('Overview');
  });
});
