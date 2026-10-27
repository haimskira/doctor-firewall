import '@testing-library/jest-dom/vitest';
import { cleanup, configure } from '@testing-library/react';
import { afterEach } from 'vitest';

// findBy* / waitFor give up after 1 s by default; a loaded CI machine renders slower.
configure({ asyncUtilTimeout: 5000 });

afterEach(() => {
  cleanup();
});
