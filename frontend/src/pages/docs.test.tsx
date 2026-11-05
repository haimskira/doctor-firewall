import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { I18nProvider } from '../i18n/I18nProvider';
import { DocsPage } from './DocsPage';

function at(path: string) {
  render(
    <I18nProvider>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/docs/:doc" element={<DocsPage />} />
        </Routes>
      </MemoryRouter>
    </I18nProvider>,
  );
}

describe('DocsPage', () => {
  it('renders the doctrine with a table of contents of its sections', async () => {
    at('/docs/doctrine');
    expect(await screen.findByRole('heading', { level: 1, name: /דוקטרינת חוקת פיירוול/ })).toBeInTheDocument();
    const toc = screen.getByRole('navigation');
    expect(await screen.findAllByRole('link')).not.toHaveLength(0);
    expect(toc.textContent).toContain('עקרונות-על');
  });

  it('renders the system logic document with its title', async () => {
    at('/docs/logic');
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 2 }).length).toBeGreaterThan(8);
  });

  it('sends an unknown document to the doctrine', async () => {
    at('/docs/nope');
    expect(await screen.findByRole('heading', { level: 1, name: /דוקטרינת/ })).toBeInTheDocument();
  });
});
