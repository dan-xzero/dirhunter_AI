import type { Metadata } from "next";
import { Geist, IBM_Plex_Mono } from "next/font/google";
import { Providers } from "@/components/providers";
import { SiteNav } from "@/components/site-nav";
import "./globals.css";

const sans = Geist({
  subsets: ["latin"],
  variable: "--font-geist-sans",
  display: "swap"
});

const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-geist-mono",
  display: "swap"
});

export const metadata: Metadata = {
  title: "DirHunter Portal",
  description: "Findings, scan validation, and triage for DirHunter AI",
  icons: {
    icon: "/favicon.svg"
  }
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>
        <Providers>
          <a href="#main-content" className="skip-link">
            Skip to content
          </a>
          <div className="min-h-screen px-5 py-5 lg:px-8">
            <SiteNav />
            {children}
          </div>
        </Providers>
      </body>
    </html>
  );
}
