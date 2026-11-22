import { useEffect } from 'react';

const SITE_NAME = 'SPPIO';

function upsertMeta(selector, attributes) {
  let element = document.head.querySelector(selector);
  if (!element) {
    element = document.createElement('meta');
    element.setAttribute('data-sppio-meta', '1');
    document.head.appendChild(element);
  }
  Object.entries(attributes).forEach(([name, value]) => {
    element.setAttribute(name, value);
  });
}

/**
 * Keeps document-level metadata in sync with the public page being rendered.
 * SPA navigation otherwise leaves the previous page title in the tab and in
 * share previews.
 */
export default function usePageMeta({ title, description, path }) {
  useEffect(() => {
    if (title) {
      document.title = title;
      upsertMeta('meta[property="og:title"]', { property: 'og:title', content: title });
      upsertMeta('meta[name="twitter:title"]', { name: 'twitter:title', content: title });
    }

    if (description) {
      upsertMeta('meta[name="description"]', { name: 'description', content: description });
      upsertMeta('meta[property="og:description"]', { property: 'og:description', content: description });
      upsertMeta('meta[name="twitter:description"]', { name: 'twitter:description', content: description });
    }

    upsertMeta('meta[property="og:type"]', { property: 'og:type', content: 'website' });
    upsertMeta('meta[property="og:site_name"]', { property: 'og:site_name', content: SITE_NAME });
    upsertMeta('meta[name="twitter:card"]', { name: 'twitter:card', content: 'summary_large_image' });

    if (path) {
      const canonical = `${window.location.origin}${path}`;
      let link = document.head.querySelector('link[rel="canonical"]');
      if (!link) {
        link = document.createElement('link');
        link.setAttribute('rel', 'canonical');
        link.setAttribute('data-sppio-meta', '1');
        document.head.appendChild(link);
      }
      link.setAttribute('href', canonical);
      upsertMeta('meta[property="og:url"]', { property: 'og:url', content: canonical });
    }
  }, [title, description, path]);
}
