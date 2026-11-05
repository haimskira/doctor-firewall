import { useEffect, useRef, useState } from 'react';
import type { ComponentType } from 'react';
import { Navigate, useParams } from 'react-router-dom';

import { DoctrineDoc } from '../docs/DoctrineDoc';
import { SystemLogicDoc } from '../docs/SystemLogicDoc';
import { useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';

/** In-app documents (compiled from docs/app/*.html by scripts/doc-to-tsx.py; Hebrew only). */
// ``heading``: the document has no h1 of its own, the page adds its title.
const DOCS = new Map<string, { title: MessageKey; body: ComponentType; heading: boolean }>([
  ['doctrine', { title: 'nav.docDoctrine', body: DoctrineDoc, heading: false }],
  ['logic', { title: 'nav.docLogic', body: SystemLogicDoc, heading: true }],
]);

interface Heading {
  id: string;
  text: string;
}

export function DocsPage() {
  const { t, language } = useI18n();
  const { doc = '' } = useParams();
  const entry = DOCS.get(doc);
  const article = useRef<HTMLElement>(null);
  const [toc, setToc] = useState<Heading[]>([]);

  // Table of contents from the rendered h2s (ids assigned here; the source carries none).
  useEffect(() => {
    const root = article.current;
    if (root === null) return;
    const found = Array.from(root.querySelectorAll('h2')).map((h, i) => {
      h.id = `doc-${doc}-${String(i + 1)}`;
      return { id: h.id, text: h.textContent };
    });
    setToc(found);
  }, [doc]);

  if (entry === undefined) return <Navigate to="/docs/doctrine" replace />;
  const Body = entry.body;
  return (
    <div className="doc-layout">
      <nav className="doc-toc card" aria-label={t(entry.title)} dir="rtl" lang="he">
        <div className="doc-toc-title">{t(entry.title)}</div>
        <ol>
          {toc.map((h) => (
            <li key={h.id}>
              <a
                href={`#${h.id}`}
                onClick={(e) => {
                  e.preventDefault();
                  document.getElementById(h.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }}
              >
                {h.text}
              </a>
            </li>
          ))}
        </ol>
      </nav>
      <article ref={article} className="doc-page card" dir="rtl" lang="he">
        {language !== 'he' && <p className="muted small">{t('docs.hebrewOnly')}</p>}
        {entry.heading && <h1>{t(entry.title)}</h1>}
        <Body />
      </article>
    </div>
  );
}
