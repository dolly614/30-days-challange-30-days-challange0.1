import type { MetadataRoute } from 'next';
import { generateAuthoritativeRobotsRules } from '@/lib/seo-canonical-url-governance';

export default function robots(): MetadataRoute.Robots {
  return generateAuthoritativeRobotsRules();
}
