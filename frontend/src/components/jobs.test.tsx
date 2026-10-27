import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { JobRun, JobsList } from '../api/types';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { JobsIndicator, JobsProvider } from './jobs';

const RUNNING: JobRun = {
  id: 7,
  kind: 'collect',
  title: 'LAB-FMC',
  requested_by: 'opt',
  status: 'running',
  progress: 42,
  step: 'collect_policies',
  step_args: { done: 3, total: 5, rules: 1800 },
  error: null,
  snapshot_id: 17,
  batch_id: null,
  changeset_id: null,
  created_at: '2026-10-27T09:00:00Z',
  started_at: '2026-10-27T09:00:01Z',
  updated_at: '2026-10-27T09:00:20Z',
  finished_at: null,
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('JobsProvider / JobsIndicator', () => {
  it('shows running jobs live and tells the user when theirs ends', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let answer: JobsList = { active: 1, rows: [RUNNING] };
    const calls = mockFetch((req) => (req.url.startsWith('/api/jobs') ? { status: 200, body: answer } : { status: 404 }));
    render(
      <I18nProvider initial="en">
        <MemoryRouter>
          <JobsProvider username="opt" enabled>
            <JobsIndicator />
          </JobsProvider>
        </MemoryRouter>
      </I18nProvider>,
    );
    const button = await screen.findByRole('button', { name: '1 jobs running' });
    const user = userEvent.setup({ advanceTimers: (ms) => vi.advanceTimersByTime(ms) });
    await user.click(button);
    const panel = screen.getByRole('dialog', { name: 'Jobs' });
    expect(within(panel).getByText('Pulling policies 3/5 — 1800 rules')).toBeInTheDocument();
    expect(within(panel).getByRole('progressbar', { name: 'Progress' })).toHaveAttribute('aria-valuenow', '42');
    expect(within(panel).getByRole('link', { name: /Pull from FMC/ })).toHaveAttribute('href', '/snapshots');

    // While a job runs the provider asks again every 2 s; the job ends.
    answer = { active: 0, rows: [{ ...RUNNING, status: 'done', progress: 100, step: 'done', step_args: {}, finished_at: '2026-10-27T09:01:00Z' }] };
    const before = calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2100);
    });
    expect(calls.length).toBeGreaterThan(before);
    const notice = await screen.findByRole('status');
    expect(notice).toHaveTextContent('Pull from FMC finished: LAB-FMC');
    expect(within(notice).getByRole('link', { name: 'Open' })).toHaveAttribute('href', '/snapshots');
    expect(screen.getByRole('button', { name: 'Jobs' })).toBeInTheDocument(); // nothing running now

    // Idle: the next look is 15 s away, not 2 s.
    const idle = calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(calls.length).toBe(idle);
  });

  it('does not notify about jobs started by someone else', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let answer: JobsList = { active: 1, rows: [{ ...RUNNING, requested_by: 'someone' }] };
    mockFetch((req) => (req.url.startsWith('/api/jobs') ? { status: 200, body: answer } : { status: 404 }));
    render(
      <I18nProvider initial="en">
        <MemoryRouter>
          <JobsProvider username="opt" enabled>
            <JobsIndicator />
          </JobsProvider>
        </MemoryRouter>
      </I18nProvider>,
    );
    await screen.findByRole('button', { name: '1 jobs running' });
    answer = { active: 0, rows: [{ ...RUNNING, requested_by: 'someone', status: 'failed', error: 'worker_lost', finished_at: '2026-10-27T09:01:00Z' }] };
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2100);
    });
    expect(await screen.findByRole('button', { name: 'Jobs' })).toBeInTheDocument();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });
});
