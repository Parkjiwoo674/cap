import type {SystemStats, ProtocolData, ThreatData} from '../types/types'

/**
 * 숫자 포맷팅 (한국어)
 */
export const formatNumber = (num: number): string => {
  return new Intl.NumberFormat('ko-KR').format(num)
}

/**
 * 백엔드 프로토콜 데이터를 UI 형식으로 변환
 */
export const convertProtocolData = (stats: SystemStats): ProtocolData[] => {
  return [
    {name: 'TCP', value: stats.protocol_stats.tcp, color: '#3b82f6', label: 'TCP'},
    {name: 'UDP', value: stats.protocol_stats.udp, color: '#10b981', label: 'UDP'},
    {name: 'ICMP', value: stats.protocol_stats.icmp, color: '#f59e0b', label: 'ICMP'},
    {name: 'ARP', value: stats.protocol_stats.arp, color: '#8b5cf6', label: 'ARP'},
    {name: 'DDoS', value: stats.protocol_stats.ddos, color: '#ef4444', label: 'DDoS'},
  ]
}

/**
 * 위협 유형별 집계
 */
export const aggregateThreatData = (stats: SystemStats): ThreatData[] => {
  const threatTypeCount = stats.threats.reduce((acc, threat) => {
    acc[threat.type] = (acc[threat.type] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  return [
    {name: 'DDoS 공격', count: threatTypeCount['DDoS 공격'] || 0, color: '#ef4444'},
    {name: '포트 스캔', count: threatTypeCount['포트 스캔'] || 0, color: '#f59e0b'},
    {name: '악성코드', count: threatTypeCount['악성코드'] || 0, color: '#8b5cf6'},
    {name: '기타', count: 0, color: '#6b7280'},
  ]
}

/**
 * 위협 레벨 계산
 */
export const getThreatLevel = (threatCount: number) => {
  if (threatCount === 0) {
    return {label: '안전', color: '#10b981', bgColor: '#065f46', textColor: '#34d399'}
  }
  if (threatCount < 3) {
    return {label: '낮음', color: '#f59e0b', bgColor: '#78350f', textColor: '#fbbf24'}
  }
  if (threatCount < 5) {
    return {label: '주의', color: '#f97316', bgColor: '#7c2d12', textColor: '#fb923c'}
  }
  return {label: '위험', color: '#ef4444', bgColor: '#7f1d1d', textColor: '#f87171'}
}

/**
 * 심각도 스타일 가져오기
 */
export const getSeverityStyle = (severity: string) => {
  const styles = {
    높음: {bg: '#7f1d1d', text: '#fca5a5', border: '#ef4444'},
    중간: {bg: '#78350f', text: '#fcd34d', border: '#f59e0b'},
    낮음: {bg: '#374151', text: '#d1d5db', border: '#6b7280'},
  }
  return styles[severity as keyof typeof styles] || styles['낮음']
}

/**
 * 시간 포맷팅
 */
export const formatTime = (date: Date): string => {
  return date.toLocaleTimeString('ko-KR', {hour: '2-digit', minute: '2-digit'})
}
