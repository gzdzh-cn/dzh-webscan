import type { Site } from './api'
export function certificateLabel(site: Site, now = Date.now() / 1000): string {
 const cert = site.state.last
 if (cert.cert_expires) {
  const remaining = cert.cert_expires - now
  return (remaining <= 0 ? '已过期' : Math.ceil(remaining / 86400) + ' 天') + (cert.cert_error ? '（检查失败）' : '')
 }
 if (cert.cert_applicable || site.url.startsWith('https:')) return '未知'
 return cert.time && cert.ok ? '不适用' : '未知'
}
