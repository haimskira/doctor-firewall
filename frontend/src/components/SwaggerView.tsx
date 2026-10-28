import 'swagger-ui-dist/swagger-ui.css';
import { useEffect, useRef } from 'react';
import SwaggerUIBundle from 'swagger-ui-dist/swagger-ui-es-bundle.js';

import { currentCsrfToken } from '../api/client';

/** Swagger UI over the full API document (bundled: no CDN). Try-it-out runs with the session;
 * writes carry the session's CSRF header, as the UI's own requests do. */
export default function SwaggerView() {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (host.current === null) return;
    SwaggerUIBundle({
      domNode: host.current,
      url: '/api/openapi.json?scope=all',
      deepLinking: false,
      docExpansion: 'list',
      defaultModelsExpandDepth: 0,
      displayRequestDuration: true,
      filter: true,
      requestInterceptor: (request) => {
        const token = currentCsrfToken();
        if (token !== null && request.method !== undefined && request.method.toUpperCase() !== 'GET') {
          request.headers['X-CSRF-Token'] = token;
        }
        request.credentials = 'same-origin';
        return request;
      },
    });
  }, []);
  return <div className="swagger-host" dir="ltr" ref={host} />;
}
