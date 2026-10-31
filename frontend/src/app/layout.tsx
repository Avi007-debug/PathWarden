import type { Metadata } from "next";
import "./globals.css";
import { AppProvider } from "@/lib/context/AppContext";
import { AppShell } from "@/components/layout/AppShell";

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000"),
  title: "PathWarden - Cyber Attack Path Reconstruction & Threat Investigation",
  description:
    "Evidence-driven cyberattack reconstruction, ordered attack paths, explainable detections, and evidence-backed reachability assessments.",
  icons: {
    icon: [
      { url: "/logo.png?v=3", type: "image/png" },
      { url: "/favicon.ico?v=3", sizes: "any" },
    ],
    shortcut: "/logo.png?v=3",
    apple: "/logo.png?v=3",
  },
  openGraph: {
    title: "PathWarden - Cyber Attack Path Reconstruction & Threat Investigation",
    description:
      "Evidence-driven cyberattack reconstruction, ordered attack paths, explainable detections, and evidence-backed reachability assessments.",
    url: "https://pathwarden.internal",
    siteName: "PathWarden",
    images: [
      {
        url: "/logo.png",
        width: 1024,
        height: 1024,
        alt: "PathWarden Neon Shield Network Emblem",
      },
    ],
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "PathWarden - Cyber Attack Path Reconstruction & Threat Investigation",
    description:
      "Evidence-driven cyberattack reconstruction, ordered attack paths, explainable detections, and evidence-backed reachability assessments.",
    images: ["/logo.png"],
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/logo.png?v=3" type="image/png" />
        <link rel="apple-touch-icon" href="/logo.png?v=3" />
      </head>
      <body className="min-h-screen bg-grid-tech flex flex-col font-sans selection:bg-[#00C8FF]/30 selection:text-white">
        <AppProvider>
          <AppShell>{children}</AppShell>
        </AppProvider>
      </body>
    </html>
  );
}
