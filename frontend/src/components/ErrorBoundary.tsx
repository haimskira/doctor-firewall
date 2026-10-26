import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

/**
 * Keeps one broken page from blanking the whole application: the shell stays, the page shows
 * a message and a way back. Keyed by the route, so navigating away resets it.
 */
export class ErrorBoundary extends Component<
  { children: ReactNode; message: string; retry: string },
  { failed: boolean }
> {
  override state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    // Diagnostics for the browser console only; nothing leaves the page.
    console.error('page failed to render', error, info.componentStack);
  }

  override render(): ReactNode {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="alert alert-error" role="alert">
        <p>{this.props.message}</p>
        <button
          type="button"
          className="secondary"
          onClick={() => {
            this.setState({ failed: false });
          }}
        >
          {this.props.retry}
        </button>
      </div>
    );
  }
}
