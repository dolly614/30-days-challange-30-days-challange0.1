import type { MetadataRoute } from 'next';

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = process.env.APP_URL || 'https://uyanix.in';
  const routes = [
    '',
    '/register',
    '/login',
    '/leaderboard',
    '/dashboard',
    '/teacher',
    '/certificate',
    '/terms',
    '/privacy',
    '/contact',
  ];

  return routes.map((route) => ({
    url: `${baseUrl}${route}`,
    lastModified: new Date(),
    changeFrequency: route === '/leaderboard' ? 'hourly' : 'daily',
    priority: route === '' ? 1.0 : 0.8,
  }));
}
