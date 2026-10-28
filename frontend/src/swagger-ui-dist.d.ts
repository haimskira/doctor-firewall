declare module 'swagger-ui-dist/swagger-ui-es-bundle.js' {
  interface SwaggerRequest {
    headers: Record<string, string>;
    credentials?: string;
    method?: string;
  }
  interface SwaggerOptions {
    domNode: HTMLElement;
    url: string;
    deepLinking?: boolean;
    docExpansion?: 'list' | 'full' | 'none';
    defaultModelsExpandDepth?: number;
    displayRequestDuration?: boolean;
    filter?: boolean;
    persistAuthorization?: boolean;
    tryItOutEnabled?: boolean;
    requestInterceptor?: (request: SwaggerRequest) => SwaggerRequest;
  }
  const SwaggerUIBundle: (options: SwaggerOptions) => unknown;
  export default SwaggerUIBundle;
}
