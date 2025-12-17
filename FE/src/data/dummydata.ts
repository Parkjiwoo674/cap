export const dummyStats = {
  totalPackets: '2,847,392',
  bandwidth: '847.2 MB/s',
  threatsDetected: 23,
  activeConnections: 1547,
}

export const dummyThreatData = [
  {name: 'DDoS 공격', count: 8, color: '#ef4444'},
  {name: '포트 스캔', count: 7, color: '#f59e0b'},
  {name: '악성코드', count: 5, color: '#8b5cf6'},
  {name: '기타', count: 3, color: '#6b7280'},
]

export const dummyProtocolData = [
  {name: 'TCP', value: 2962, color: '#3b82f6', label: 'TCP'},
  {name: 'UDP', value: 1234, color: '#10b981', label: 'UDP'},
  {name: 'ICMP', value: 493, color: '#f59e0b', label: 'ICMP'},
  {name: 'ARP', value: 246, color: '#8b5cf6', label: 'ARP'},
  {name: 'DDoS', value: 9, color: '#ef4444', label: 'DDoS'},
]

export const dummyTrafficData = [
  {time: '23:00', receive: 65, send: 45},
  {time: '22:00', receive: 120, send: 100},
  {time: '21:00', receive: 50, send: 35},
  {time: '20:00', receive: 150, send: 30},
  {time: '19:00', receive: 45, send: 35},
  {time: '18:00', receive: 90, send: 55},
  {time: '17:00', receive: 95, send: 60},
  {time: '16:00', receive: 120, send: 30},
  {time: '15:00', receive: 50, send: 110},
  {time: '14:00', receive: 80, send: 70},
  {time: '13:00', receive: 125, send: 70},
  {time: '12:00', receive: 115, send: 30},
  {time: '11:00', receive: 95, send: 25},
  {time: '10:00', receive: 140, send: 110},
  {time: '09:00', receive: 50, send: 65},
  {time: '08:00', receive: 95, send: 80},
  {time: '07:00', receive: 50, send: 55},
  {time: '06:00', receive: 100, send: 95},
  {time: '05:00', receive: 95, send: 50},
  {time: '04:00', receive: 135, send: 60},
  {time: '03:00', receive: 100, send: 50},
  {time: '02:00', receive: 140, send: 50},
  {time: '01:00', receive: 105, send: 85},
  {time: '00:00', receive: 110, send: 90},
]

export const dummyRecentThreats = [
  {ip: '192.168.1.45', type: 'DDoS 공격', time: '10:23:15', severity: 'high' as const},
  {ip: '10.0.0.128', type: '포트 스캔', time: '10:21:42', severity: 'medium' as const},
  {ip: '172.16.0.89', type: '악성코드', time: '10:19:08', severity: 'high' as const},
  {ip: '192.168.2.103', type: '무차별 대입', time: '10:15:33', severity: 'low' as const},
]
