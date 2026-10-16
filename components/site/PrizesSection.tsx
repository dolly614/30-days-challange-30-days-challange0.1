'use client';

import React, { useState } from 'react';
import Image from 'next/image';
import { motion, useReducedMotion } from 'motion/react';

interface PrizeItem {
  place: string;
  title: string;
  subtitle: string;
  gradientClass: string;
  elevateClass: string;
  imageSrc: string;
  imageAlt: string;
  emojiFallback: string;
  priority: boolean;
  accentGlow: string;
}

const PRIZES: PrizeItem[] = [
  {
    place: '1st Place',
    title: 'Laptop',
    subtitle: 'Plus certificate + gift',
    gradientClass: 'bg-gradient-gold',
    elevateClass: 'md:-translate-y-4',
    imageSrc: '/images/prizes/laptop-v2.jpg',
    imageAlt: 'First Prize — Complete modern laptop computer with screen and keyboard visible on clean light background',
    emojiFallback: '💻',
    priority: true,
    accentGlow: 'rgba(245, 158, 11, 0.25)',
  },
  {
    place: '2nd Place',
    title: 'Tablet',
    subtitle: 'Plus certificate + gift',
    gradientClass: 'bg-gradient-silver',
    elevateClass: '',
    imageSrc: '/images/prizes/tablet.jpg',
    imageAlt: 'Second Prize — Realistic Modern Tablet Computer with Clean Edge-to-Edge Display',
    emojiFallback: '📱',
    priority: false,
    accentGlow: 'rgba(148, 163, 184, 0.22)',
  },
  {
    place: '3rd Place',
    title: 'Smartphone',
    subtitle: 'Plus certificate + gift',
    gradientClass: 'bg-gradient-bronze',
    elevateClass: '',
    imageSrc: '/images/prizes/smartphone-pro.jpg',
    imageAlt: 'Third Prize — Realistic Modern Front-Facing Smartphone Product with Clean Display and Edge-to-Edge Screen',
    emojiFallback: '📲',
    priority: false,
    accentGlow: 'rgba(217, 119, 6, 0.22)',
  },
];

function PrizeCard({ prize, index }: { prize: PrizeItem; index: number }) {
  const [hasError, setHasError] = useState(false);
  const [isLoaded, setIsLoaded] = useState(false);
  const shouldReduceMotion = useReducedMotion();

  return (
    <motion.div
      initial={{ opacity: 0, y: shouldReduceMotion ? 0 : 32 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-40px' }}
      transition={{
        duration: 0.55,
        delay: index * 0.16,
        ease: [0.16, 1, 0.3, 1],
      }}
      whileHover={
        shouldReduceMotion
          ? undefined
          : {
              y: -8,
              transition: { duration: 0.25, ease: 'easeOut' },
            }
      }
      className={`group card-interactive rounded-3xl ${prize.gradientClass} p-1 shadow-soft ${prize.elevateClass} relative overflow-hidden`}
    >
      <div className="rounded-[22px] bg-card px-4 py-6 sm:px-6 sm:py-7 text-center transition-colors flex flex-col items-center">
        {/* Product Image Stage */}
        <div className="relative w-full h-44 sm:h-48 overflow-hidden rounded-2xl bg-gradient-to-b from-slate-50/90 to-white dark:from-slate-900/60 dark:to-slate-800/40 border border-border/40 p-3 flex items-center justify-center">
          {/* Subtle Studio Glow */}
          <div
            className="absolute inset-0 pointer-events-none opacity-40 group-hover:opacity-80 transition-opacity duration-500 blur-xl"
            style={{
              background: `radial-gradient(circle at 50% 55%, ${prize.accentGlow} 0%, transparent 70%)`,
            }}
            aria-hidden="true"
          />

          {/* Floating Product Image Container */}
          <motion.div
            animate={
              shouldReduceMotion
                ? undefined
                : {
                    y: [0, -6, 0],
                  }
            }
            transition={{
              duration: 3.8,
              repeat: Infinity,
              ease: 'easeInOut',
              delay: index * 0.35,
            }}
            className="relative w-full h-full flex items-center justify-center"
          >
            {!hasError ? (
              <div className="relative w-full h-full transition-transform duration-300 ease-out group-hover:scale-[1.04]">
                <Image
                  src={prize.imageSrc}
                  alt={prize.imageAlt}
                  fill
                  sizes="(max-width: 640px) 100vw, (max-width: 1024px) 33vw, 360px)"
                  priority={prize.priority}
                  quality={85}
                  className={`object-contain transition-opacity duration-300 ${
                    isLoaded ? 'opacity-100' : 'opacity-0'
                  }`}
                  onLoad={() => setIsLoaded(true)}
                  onError={() => setHasError(true)}
                />
                {!isLoaded && (
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-4xl animate-pulse opacity-40">
                      {prize.emojiFallback}
                    </span>
                  </div>
                )}
              </div>
            ) : (
              /* Graceful Fallback if image fails */
              <div className="flex flex-col items-center justify-center gap-2">
                <span className="text-5xl drop-shadow-sm">
                  {prize.emojiFallback}
                </span>
                <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">
                  {prize.title}
                </span>
              </div>
            )}
          </motion.div>

          {/* Subtle Studio Light Reflection Sheen */}
          <div
            className="absolute inset-0 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-500 overflow-hidden rounded-2xl"
            aria-hidden="true"
          >
            <div className="absolute -inset-full top-0 bg-gradient-to-r from-transparent via-white/15 dark:via-white/5 to-transparent -skew-x-12 group-hover:translate-x-full transition-transform duration-1000 ease-out" />
          </div>
        </div>

        {/* Existing Exact Text Details */}
        <div className="mt-4 text-xs sm:text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          {prize.place}
        </div>
        <h3
          className="mt-1.5 w-full max-w-full text-center font-extrabold text-foreground tracking-tight [font-size:clamp(1.35rem,2.1vw,2.25rem)] leading-tight px-1"
          style={{
            overflowWrap: 'break-word',
            wordBreak: 'normal',
          }}
        >
          {prize.title}
        </h3>
        <div className="mt-2 text-xs text-muted-foreground font-medium">
          {prize.subtitle}
        </div>
      </div>
    </motion.div>
  );
}

export function PrizesSection() {
  return (
    <section className="bg-accent/40 py-20 overflow-hidden">
      <div className="mx-auto max-w-7xl px-4 sm:px-6">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-semibold uppercase tracking-widest text-primary">
            Prizes
          </p>
          <h2 className="mt-2 text-3xl font-bold sm:text-4xl">
            Top 3 winners ko{' '}
            <span className="text-gradient">Laptop, Tablet &amp; Phone</span>
          </h2>
          <p className="mt-3 text-muted-foreground">
            Aur har participant ko special gift + digital certificate guaranteed!
          </p>
        </div>

        <div className="mt-12 grid gap-6 md:grid-cols-3 items-stretch">
          {PRIZES.map((prize, idx) => (
            <PrizeCard key={prize.place} prize={prize} index={idx} />
          ))}
        </div>
      </div>
    </section>
  );
}
