import type { MetadataRoute } from 'next';
import { generateAuthoritativeSitemapList } from '@/lib/seo-canonical-url-governance';

export default function sitemap(): MetadataRoute.Sitemap {
  return generateAuthoritativeSitemapList();
}
