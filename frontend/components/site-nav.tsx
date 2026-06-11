"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, ListChecks, ListFilter, Menu, Radar, Settings, X } from "lucide-react";
import clsx from "clsx";

const NAV_ITEMS = [
  { href: "/", label: "Overview", icon: Radar },
  { href: "/findings", label: "Findings", icon: ListFilter },
  { href: "/scans", label: "Scans", icon: ListChecks },
  { href: "/settings", label: "Settings", icon: Settings }
] as const;

function isActive(pathname: string, href: string) {
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function SiteNav() {
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!menuOpen) return;
    const { overflow } = document.body.style;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = overflow;
    };
  }, [menuOpen]);

  return (
    <header className="glass mb-6 flex items-center justify-between rounded-2xl px-5 py-4">
      <Link href="/" className="flex items-center gap-3" aria-label="DirHunter Security Portal home">
        <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-teal/30 bg-teal-dim">
          <Activity className="h-5 w-5 text-teal" />
        </span>
        <span>
          <span className="block text-sm uppercase tracking-[0.32em] text-muted">DirHunter</span>
          <span className="block text-xl font-semibold text-ink">Security Portal</span>
        </span>
      </Link>

      <nav aria-label="Primary" className="hidden items-center gap-2 md:flex">
        {NAV_ITEMS.map((item) => {
          const active = isActive(pathname, item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              aria-current={active ? "page" : undefined}
              className={clsx(
                "flex items-center gap-2 rounded-xl border px-3 py-2 text-sm transition",
                active
                  ? "border-teal/35 bg-teal-dim text-teal"
                  : "border-transparent text-muted hover:border-line-hard hover:bg-panel-soft hover:text-ink"
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <button
        type="button"
        onClick={() => setMenuOpen(true)}
        aria-label="Open navigation menu"
        aria-expanded={menuOpen}
        aria-controls="mobile-nav"
        className="flex h-11 w-11 items-center justify-center rounded-xl border border-line text-muted transition hover:border-line-hard hover:text-ink md:hidden"
      >
        <Menu className="h-5 w-5" />
      </button>

      {menuOpen ? (
        <div className="fixed inset-0 z-50 md:hidden">
          <div className="absolute inset-0 bg-void/70 backdrop-blur-sm" onClick={() => setMenuOpen(false)} aria-hidden="true" />
          <nav
            id="mobile-nav"
            aria-label="Primary"
            className="absolute inset-y-0 right-0 flex w-72 max-w-[85vw] flex-col gap-2 border-l border-line-hard bg-obsidian p-5 shadow-2xl"
          >
            <div className="mb-4 flex items-center justify-between">
              <span className="text-sm uppercase tracking-[0.32em] text-muted">Menu</span>
              <button
                type="button"
                onClick={() => setMenuOpen(false)}
                aria-label="Close navigation menu"
                className="flex h-10 w-10 items-center justify-center rounded-xl border border-line text-muted transition hover:border-line-hard hover:text-ink"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            {NAV_ITEMS.map((item) => {
              const active = isActive(pathname, item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={clsx(
                    "flex items-center gap-3 rounded-xl border px-4 py-3 text-sm transition",
                    active
                      ? "border-teal/35 bg-teal-dim text-teal"
                      : "border-line text-muted hover:border-line-hard hover:bg-panel-soft hover:text-ink"
                  )}
                >
                  <item.icon className="h-5 w-5" />
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>
      ) : null}
    </header>
  );
}
