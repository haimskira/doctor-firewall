import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { JobRun, JobsList } from '../api/types';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { CancelJobButton, JobsIndicator, JobsProvider, WatchAlert, jobLink } from './jobs';

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

  it('shows blocked traffic after a deployment in the top bar', async () => {
    mockFetch((req) => (req.url.startsWith('/api/jobs') ? { status: 200, body: { active: 0, rows: [], alerts: 2 } } : { status: 404 }));
    render(
      <I18nProvider initial="en">
        <MemoryRouter>
          <JobsProvider username="opt" enabled>
            <WatchAlert />
          </JobsProvider>
        </MemoryRouter>
      </I18nProvider>,
    );
    expect(await screen.findByRole('alert')).toHaveTextContent('Blocked traffic after a deployment (2)');
    expect(screen.getByRole('link', { name: /Blocked traffic/ })).toHaveAttribute('href', '/history');
  });

  it('translates job errors instead of showing raw exception text', async () => {
    const failed = (id: number, error: string, kind: JobRun['kind'] = 'batch'): JobRun => ({
      ...RUNNING, id, kind, status: 'failed', error, changeset_id: 3, finished_at: '2026-10-27T09:01:00Z',
    });
    mockFetch((req) =>
      req.url.startsWith('/api/jobs')
        ? {
            status: 200,
            body: {
              active: 0,
              rows: [
                failed(1, 'LookupError: changeset_without_snapshot', 'proof'),
                failed(2, 'write_rejected: rule MIXED: 422'),
                failed(3, 'ValueError: something odd'),
              ],
            },
          }
        : { status: 404 },
    );
    render(
      <I18nProvider initial="en">
        <MemoryRouter>
          <JobsProvider username="someone" enabled>
            <JobsIndicator />
          </JobsProvider>
        </MemoryRouter>
      </I18nProvider>,
    );
    await userEvent.click(await screen.findByRole('button', { name: 'Jobs' }));
    const panel = screen.getByRole('dialog', { name: 'Jobs' });
    expect(within(panel).getByText('This changeset has no snapshot to check against.')).toBeInTheDocument();
    expect(within(panel).getByText('The FMC refused a change: rule MIXED: 422')).toBeInTheDocument();
    expect(within(panel).getByText(/The job failed\./)).toBeInTheDocument();
    expect(within(panel).getByText('something odd')).toBeInTheDocument(); // the code, muted
    expect(within(panel).queryByText(/LookupError/)).not.toBeInTheDocument();
  });

  it('links a revert job to the history', () => {
    expect(jobLink({ ...RUNNING, kind: 'revert', changeset_id: 3 })).toBe('/history');
    expect(jobLink({ ...RUNNING, kind: 'batch', changeset_id: 3 })).toBe('/deploy?changeset=3');
  });
});

describe('CancelJobButton', () => {
  const BATCH: JobRun = { ...RUNNING, id: 9, kind: 'batch', title: 'cs · 1', step: 'batch_write', step_args: {}, can_cancel: true };

  function mount(job: JobRun, answer: { status: number; body?: unknown }) {
    const calls = mockFetch((req) => (req.url.startsWith('/api/jobs/') ? answer : req.url.startsWith('/api/jobs') ? { status: 200, body: { active: 0, rows: [] } } : { status: 404 }));
    render(
      <I18nProvider initial="en">
        <MemoryRouter>
          <JobsProvider username="opt" enabled>
            <CancelJobButton job={job} />
          </JobsProvider>
        </MemoryRouter>
      </I18nProvider>,
    );
    return calls;
  }

  it('is hidden for users who may not cancel and for finished runs', () => {
    mount({ ...BATCH, can_cancel: false }, { status: 200 });
    expect(screen.queryByRole('button', { name: 'Cancel run' })).not.toBeInTheDocument();
  });

  it('asks first, and says a deployment already in progress cannot be stopped', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const calls = mount(BATCH, { status: 200, body: { run_id: 9, result: 'requested', deploy_started: false } });
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel run' }));
    expect(confirm.mock.calls[0]?.[0]).toMatch(/rolled back/);
    expect(confirm.mock.calls[0]?.[0]).toMatch(/cannot be stopped/);
    expect(calls.some((c) => c.method === 'POST' && c.url === '/api/jobs/9/cancel')).toBe(true);
    expect(await screen.findByRole('status')).toHaveTextContent('only if the run has not reached the deployment');
  });

  it('does nothing when the confirmation is declined; shows the error of a finished run', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    const calls = mount(BATCH, { status: 409, body: { detail: 'not_cancellable' } });
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel run' }));
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    confirm.mockReturnValue(true);
    await userEvent.click(screen.getByRole('button', { name: 'Cancel run' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The run has already ended.');
  });
});
