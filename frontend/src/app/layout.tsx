import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "APK Sentinel — Hybrid Static-Dynamic APK Security Console",
  description:
    "Automated mobile APK reverse engineering and risk scoring powered by apkman static code extraction and aparoid sandbox dynamic tracing.",
  keywords: [
    "apkman",
    "aparoid",
    "APK analysis",
    "malware detection",
    "Android security",
    "reverse engineering",
    "AI risk scoring",
  ],
  verification: {
    google: '-voCn8AtdQ6QlPwfn1gTAN5Zc2Xn_L9pZ6aIMKuSros',
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
