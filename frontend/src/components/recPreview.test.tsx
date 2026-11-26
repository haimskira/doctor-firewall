import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { Me, RecommendationPreview } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { RecommendationPreviewView } from './recommendations';

const ME: Me = {
  id: 1, username: 'adm', display_name: 'Adm', roles: ['admin'], permissions: ['policy:read'], language: 'en',
  auth_provider: 'local', must_change_password: false, theme: 'system', csrf_token: 'csrf-p',
};

function show(preview: RecommendationPreview, view: 'inline' | 'split') {
  mockFetch((req) => (req.url === '/api/auth/me' ? { status: 200, body: ME } : { status: 404 }));
  return render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter>
          <RecommendationPreviewView preview={preview} view={view} snapshotId={7} />
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
}

/** The nearest ancestor of ``el`` matching ``selector``. */
function around(el: HTMLElement | undefined, selector: string): HTMLElement {
  const found = el?.parentElement?.closest(selector);
  if (!(found instanceof HTMLElement)) throw new Error(`no ${selector}`);
  return found;
}

const base = { enabled: true, section: 'Mandatory', category: '', action: 'ALLOW' };

describe('recommendation preview colours', () => {
  it('shows "any" for an empty source / destination of a shadowing rule', async () => {
    const by = { ...base, id: 'r1', index: 1, name: 'ANY_TO_WEB', fields: { dst_port: ['HTTPS'] } };
    const shadowed = { ...base, id: 'r9', index: 9, name: 'HOST_TO_WEB', fields: { src_net: ['H_A'], dst_port: ['HTTPS'] } };
    show({ before: [by, shadowed], after: [by, { ...shadowed, status: 'removed' }] }, 'split');
    const card = around((await screen.findAllByText('ANY_TO_WEB'))[0], '.rule-card');
    // src zone, src net, dst zone, dst net are "any"; the port is not.
    expect(within(card).getAllByText('Any')).toHaveLength(4);
    // The removed rule's values are struck in the "before" column.
    const gone = around(screen.getAllByText('HOST_TO_WEB')[0], '.rule-card');
    expect(within(gone).getByText('H_A').closest('del')).not.toBeNull();
  });

  it('marks the redundant reference red and the group that holds it green', async () => {
    const rule = { ...base, id: 'r2', index: 2, name: 'R2' };
    show(
      {
        before: [{ ...rule, fields: { dst_net: ['GRP_AAA', 'H_X'] } }],
        after: [
          {
            ...rule, fields: { dst_net: ['GRP_AAA'] }, status: 'modified',
            changes: { dst_net: { added: [], removed: ['H_X'] } },
          },
        ],
        redundant: [{ field: 'dst_net', removed: 'H_X', kept: 'GRP_AAA', chain: ['GRP_AAA', 'H_X'] }],
      },
      'inline',
    );
    expect((await screen.findByText('H_X')).closest('del')).not.toBeNull();
    expect(screen.getByText('GRP_AAA').closest('.chip')).toHaveClass('diff-keep');
  });

  it('marks a duplicate group member red before and its container green on both sides', async () => {
    const group = { id: 'g1', name: 'GRP_WEB', kind: 'network_group' };
    show(
      {
        objects: {
          before: [{ ...group, members: ['GRP_DMZ', 'H_WEB1'], status: 'unchanged' }],
          after: [{ ...group, members: ['GRP_DMZ'], status: 'kept' }],
        },
        redundant: [{ removed: 'H_WEB1', kept: 'GRP_DMZ', chain: ['GRP_DMZ', 'H_WEB1'] }],
      },
      'split',
    );
    expect((await screen.findByText('H_WEB1')).closest('del')).not.toBeNull();
    for (const chip of screen.getAllByText('GRP_DMZ')) expect(chip.closest('.chip')).toHaveClass('diff-keep');
  });

  it('marks values a merged rule gains green and keeps the rest plain', async () => {
    const a = { ...base, id: 'a', index: 3, name: 'A', fields: { src_net: ['H_1'], dst_net: ['S'] } };
    const b = { ...base, id: 'b', index: 4, name: 'B', fields: { src_net: ['H_2'], dst_net: ['S'] } };
    show(
      {
        before: [a, b],
        after: [{ ...a, fields: { src_net: ['H_1', 'H_2'], dst_net: ['S'] }, status: 'modified' }, { ...b, status: 'removed' }],
      },
      'split',
    );
    const after = around(await screen.findByText('After'), 'div');
    expect(within(after).getByText('H_2').closest('ins')).not.toBeNull();
    expect(within(after).getByText('H_1').closest('ins')).toBeNull();
    // B's source lives on in A: not struck.
    const before = around(screen.getByText('Before'), 'div');
    expect(within(before).getByText('H_2').closest('del')).toBeNull();
  });
});
