import type { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    id: '/',
    name: 'Uyanix 30 Days Challenge — Seekho, Compete Karo, Jeeto!',
    short_name: 'Uyanix 30D',
    description:
      "India's biggest 30-day daily learning competition for Class 1–12. FREE registration. Win Laptop, Tablet & Smartphone + certificate.",
    start_url: '/',
    scope: '/',
    display: 'standalone',
    background_color: '#fcfbf9',
    theme_color: '#6d28d9',
    icons: [
      {
        src: '/pwa-192x192.png',
        sizes: '192x192',
        type: 'image/png',
        purpose: 'any',
      },
      {
        src: '/pwa-512x512.png',
        sizes: '512x512',
        type: 'image/png',
        purpose: 'any',
      },
      {
        src: '/pwa-maskable-512x512.png',
        sizes: '512x512',
        type: 'image/png',
        purpose: 'maskable',
      },
    ],
  };
}
