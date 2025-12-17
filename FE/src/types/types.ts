// 백엔드 API 응답 타입 (NetGuard Security v10.2)

export interface ProtocolStats {
  tcp: number
  udp: number
  icmp: number
  arp: number
  ddos: number
}

export interface ThreatInfo {
  type: string // "DDoS 공격", "포트 스캔"
  ip: string // "192.168.1.100"
  time: string // "HH:MM:SS"
  severity: string // "높음", "중간", "낮음"
}

export interface SystemStats {
  total_packets: number
  avg_bandwidth: number // MB/s
  peak_bandwidth: number // MB/s
  active_threats: number
  active_connections: number
  protocol_stats: ProtocolStats
  threats: ThreatInfo[]
  packet_change_rate: number // %
  threat_change: number
}

// 프론트엔드 UI 타입
export interface ThreatStatus {
  label: string
  color: string
  bgColor: string
  textColor: string
}

export interface ProtocolData {
  name: string
  value: number
  color: string
  label: string
}

export interface ThreatData {
  name: string
  count: number
  color: string
}

export interface TrafficData {
  time: string
  receive: number
  send: number
}

// 더미 데이터 타입 (기존 호환성 유지)
export interface Stats {
  totalPackets: string
  bandwidth: string
  threatsDetected: number
  activeConnections: number
}

export interface RecentThreat {
  ip: string
  type: string
  time: string
  severity: 'high' | 'medium' | 'low'
}
