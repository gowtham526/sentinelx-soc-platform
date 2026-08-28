import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'SentinelX SOC Platform',
  description: 'Next-Gen Automated SOC Platform',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-dark text-slate-100 min-h-screen flex">
        {children}
      </body>
    </html>
  )
}
