import React, { useState, useEffect, useRef, useCallback } from 'react'
import {
  Shield,
  Activity,
  TrendingUp,
  Wifi,
  Search,
  Youtube,
  MessageCircle,
  Gamepad2,
  Cloud,
  ShoppingCart,
  Music,
  Video,
  Globe,
  Phone,
  Download,
} from 'lucide-react'

// 타입 정의
interface ActivityItem {
  type: string
  service: string
  details: string
  domain: string
  time: string
}

interface SystemStats {
  total_packets: number
  tcp_count: number
  udp_count: number
  icmp_count: number
  other_count: number
  avg_bandwidth: number
  peak_bandwidth: number
  threat_change: number

  // 활동 데이터
  activities?: ActivityItem[]
  streaming_services?: Record<string, number>
  social_media?: Record<string, number>
  messaging_apps?: Record<string, number>
  cloud_services?: Record<string, number>
  visited_websites?: Array<{ domain: string; count: number }>
  video_streaming?: Array<{ service: string; time: string }>
  file_downloads?: Array<{ type: string; filename: string; time: string }>
  gaming_activity?: Array<{ game: string; time: string }>
  video_calls?: Array<{ service: string; time: string }>
}

interface TrafficData {
  time: string
  packets: number
}

// 유틸리티 함수
const formatNumber = (num: number): string => {
  if (isNaN(num) || num === undefined || num === null) return '0'
  return new Intl.NumberFormat('ko-KR').format(num)
}

const safeNumber = (num: unknown, defaultValue: number = 0): number => {
  const parsed = Number(num)
  return isNaN(parsed) || parsed === undefined || parsed === null ? defaultValue : parsed
}

// 활동 타입별 아이콘 매핑
const getActivityIcon = (type: string): React.ReactNode => {
  const iconMap: Record<string, React.ReactNode> = {
    'Video Streaming': <Youtube className="w-5 h-5 text-red-400" />,
    'Social Media': <MessageCircle className="w-5 h-5 text-blue-400" />,
    'Messaging': <MessageCircle className="w-5 h-5 text-green-400" />,
    'Gaming': <Gamepad2 className="w-5 h-5 text-purple-400" />,
    'File Download': <Download className="w-5 h-5 text-orange-400" />,
    'Web Search': <Search className="w-5 h-5 text-gray-400" />,
    'Video Call': <Phone className="w-5 h-5 text-blue-400" />,
    'Cloud Service': <Cloud className="w-5 h-5 text-cyan-400" />,
    'Music Streaming': <Music className="w-5 h-5 text-pink-400" />,
    'Online Shopping': <ShoppingCart className="w-5 h-5 text-yellow-400" />,
    'Web Browsing': <Globe className="w-5 h-5 text-gray-400" />,
    'Streaming Service': <Video className="w-5 h-5 text-red-400" />,
  }
  return iconMap[type] || <Activity className="w-5 h-5 text-gray-400" />
}

// 활동 타입별 색상
const getActivityColor = (type: string): string => {
  const colors: Record<string, string> = {
    'Video Streaming': '#ef4444',
    'Social Media': '#3b82f6',
    'Messaging': '#10b981',
    'Gaming': '#8b5cf6',
    'File Download': '#f97316',
    'Web Search': '#6b7280',
    'Video Call': '#06b6d4',
    'Cloud Service': '#06b6d4',
    'Music Streaming': '#ec4899',
    'Online Shopping': '#eab308',
    'Web Browsing': '#6b7280',
    'Streaming Service': '#ef4444',
  }
  return colors[type] || '#6b7280'
}

const Dashboard: React.FC = () => {
  const [currentTime, setCurrentTime] = useState<Date>(new Date())
  const [stats, setStats] = useState<SystemStats | null>(null)
  const [connected, setConnected] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [trafficHistory, setTrafficHistory] = useState<TrafficData[]>([])
  const [selectedCategory, setSelectedCategory] = useState<string>('all')

  const ws = useRef<WebSocket | null>(null)
  const lastPacketCount = useRef<number>(0)

  // 시계
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000)
    return () => clearInterval(timer)
  }, [])

  const connectWebSocket = useCallback(() => {
    try {
      ws.current = new WebSocket('ws://localhost:8000/ws')

      ws.current.onopen = () => {
        setConnected(true)
        setError(null)
        console.log('✅ WebSocket 연결 성공')
      }

      ws.current.onmessage = (event: MessageEvent<string>) => {
        try {
          const data: SystemStats = JSON.parse(event.data)
          setStats(data)

          // 패킷 증가량 기반 트래픽 히스토리
          setTrafficHistory((prev) => {
            const currentPackets = safeNumber(data.total_packets, 0)
            const packetDiff = Math.max(currentPackets - lastPacketCount.current, 0)
            lastPacketCount.current = currentPackets

            const now = new Date()
            const newPoint: TrafficData = {
              time: `${now.getHours().toString().padStart(2, '0')}:${now
                .getMinutes()
                .toString()
                .padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`,
              packets: packetDiff,
            }

            const newHistory = [...prev, newPoint]
            return newHistory.slice(-30)
          })
        } catch (err) {
          console.error('❌ 데이터 파싱 오류:', err)
        }
      }

      ws.current.onerror = () => {
        setError('WebSocket 연결 오류')
      }

      ws.current.onclose = () => {
        setConnected(false)
        setTimeout(connectWebSocket, 5000)
      }
    } catch (err) {
      setError(`WebSocket 연결 실패: ${(err as Error).message}`)
    }
  }, [])

  useEffect(() => {
    connectWebSocket()
    return () => ws.current?.close()
  }, [connectWebSocket])

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-gray-950">
        <div className="max-w-md p-8 border border-red-500 rounded-lg bg-red-900/20">
          <Shield className="w-16 h-16 mx-auto mb-4 text-red-500" />
          <h2 className="mb-2 text-2xl font-bold text-center text-red-400">연결 실패</h2>
          <p className="mb-4 text-center text-gray-300">{error}</p>
          <p className="text-sm text-center text-gray-400">
            백엔드 서버 실행: <code className="px-2 py-1 mt-2 bg-gray-800 rounded">sudo python run.py</code>
          </p>
        </div>
      </div>
    )
  }

  if (!connected || !stats) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-950">
        <div className="text-center">
          <div className="w-16 h-16 mx-auto mb-4 border-t-2 border-b-2 border-blue-500 rounded-full animate-spin"></div>
          <p className="text-gray-400">서버 연결 중...</p>
        </div>
      </div>
    )
  }

  const totalPackets = safeNumber(stats.total_packets, 0)
  const tcpCount = safeNumber(stats.tcp_count, 0)
  const udpCount = safeNumber(stats.udp_count, 0)
  const icmpCount = safeNumber(stats.icmp_count, 0)
  const otherCount = safeNumber(stats.other_count, 0)
  const avgBandwidth = safeNumber(stats.avg_bandwidth, 0)
  const peakBandwidth = safeNumber(stats.peak_bandwidth, 0)

  // 카테고리별 필터링
  const filteredActivities = stats.activities?.filter((activity) => {
    if (selectedCategory === 'all') return true
    return activity.type === selectedCategory
  }) || []

  // 전체 활동 수
  const totalActivities = stats.activities?.length || 0
  const totalWebsites = stats.visited_websites?.length || 0

  // 🆕 프로토콜 데이터 (원형 그래프용)
  const protocolData = [
    { name: 'TCP', value: tcpCount, color: '#3b82f6', percentage: totalPackets > 0 ? (tcpCount / totalPackets * 100).toFixed(1) : '0' },
    { name: 'UDP', value: udpCount, color: '#8b5cf6', percentage: totalPackets > 0 ? (udpCount / totalPackets * 100).toFixed(1) : '0' },
    { name: 'ICMP', value: icmpCount, color: '#10b981', percentage: totalPackets > 0 ? (icmpCount / totalPackets * 100).toFixed(1) : '0' },
    { name: 'OTHER', value: otherCount, color: '#f59e0b', percentage: totalPackets > 0 ? (otherCount / totalPackets * 100).toFixed(1) : '0' },
  ].filter(p => p.value > 0) // 0인 항목 제외

  // 🆕 원형 그래프 각도 계산
  let currentAngle = 0
  const pieSlices = protocolData.map((protocol) => {
    const percentage = totalPackets > 0 ? (protocol.value / totalPackets) : 0
    const angle = percentage * 360
    const startAngle = currentAngle
    const endAngle = currentAngle + angle
    currentAngle = endAngle

    return {
      ...protocol,
      startAngle,
      endAngle,
      percentage: (percentage * 100).toFixed(1),
    }
  })

  // 🆕 SVG Path 생성 함수
  const createArcPath = (startAngle: number, endAngle: number, innerRadius: number, outerRadius: number) => {
    const start = polarToCartesian(100, 100, outerRadius, endAngle)
    const end = polarToCartesian(100, 100, outerRadius, startAngle)
    const innerStart = polarToCartesian(100, 100, innerRadius, endAngle)
    const innerEnd = polarToCartesian(100, 100, innerRadius, startAngle)
    
    const largeArcFlag = endAngle - startAngle <= 180 ? '0' : '1'
    
    return [
      `M ${start.x} ${start.y}`,
      `A ${outerRadius} ${outerRadius} 0 ${largeArcFlag} 0 ${end.x} ${end.y}`,
      `L ${innerEnd.x} ${innerEnd.y}`,
      `A ${innerRadius} ${innerRadius} 0 ${largeArcFlag} 1 ${innerStart.x} ${innerStart.y}`,
      'Z'
    ].join(' ')
  }

  const polarToCartesian = (centerX: number, centerY: number, radius: number, angleInDegrees: number) => {
    const angleInRadians = (angleInDegrees - 90) * Math.PI / 180.0
    return {
      x: centerX + (radius * Math.cos(angleInRadians)),
      y: centerY + (radius * Math.sin(angleInRadians))
    }
  }

  return (
    <div className="min-h-screen text-gray-100 bg-gray-950">
      {/* 헤더 */}
      <div className="px-6 py-3 bg-gray-900 border-b border-gray-800">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div>
              <h1 className="text-xl font-bold text-white">NetGuard Activity Monitor</h1>
              <p className="text-xs text-gray-400">실시간 네트워크 패킷 분석 시스템</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
              <span className="text-xs text-gray-400">{connected ? '연결됨' : '연결 끊김'}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="p-6">
        {/* 상태 바 */}
        <div className="flex items-center justify-between px-6 py-3 mb-6 bg-gray-900 border border-gray-800 rounded-lg">
          <div className="flex items-center gap-8">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-sm text-gray-400">시스템 상태:</span>
              <span className="text-sm font-semibold text-green-400">정상 작동</span>
            </div>
            <div className="text-sm text-gray-400">
              <span className="text-gray-500">마지막 업데이트:</span> {currentTime.toLocaleString('ko-KR')}
            </div>
          </div>
        </div>

        {/* 메트릭 카드 */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          <div className="p-5 border rounded-lg bg-gradient-to-br from-blue-900/50 to-blue-800/30 border-blue-700/50">
            <div className="flex items-center justify-between mb-3">
              <div className="p-2.5 bg-blue-500/20 rounded-lg">
                <Activity className="w-5 h-5 text-blue-400" />
              </div>
              <span className="text-xs font-medium text-blue-300">실시간</span>
            </div>
            <div className="mb-1 text-2xl font-bold text-white">{formatNumber(totalPackets)}</div>
            <div className="text-xs text-blue-200">총 패킷 수</div>
          </div>

          <div className="p-5 border rounded-lg bg-gradient-to-br from-purple-900/50 to-purple-800/30 border-purple-700/50">
            <div className="flex items-center justify-between mb-3">
              <div className="p-2.5 bg-purple-500/20 rounded-lg">
                <Wifi className="w-5 h-5 text-purple-400" />
              </div>
              <TrendingUp className="w-4 h-4 text-green-400" />
            </div>
            <div className="mb-1 text-2xl font-bold text-white">{avgBandwidth.toFixed(2)} MB/s</div>
            <div className="text-xs text-purple-200">평균 대역폭</div>
            <div className="flex items-center gap-1 mt-2 text-xs text-purple-300">
              Peak: {peakBandwidth.toFixed(2)} MB/s
            </div>
          </div>

          <div className="p-5 border rounded-lg bg-gradient-to-br from-green-900/50 to-green-800/30 border-green-700/50">
            <div className="flex items-center justify-between mb-3">
              <div className="p-2.5 bg-green-500/20 rounded-lg">
                <Activity className="w-5 h-5 text-green-400" />
              </div>
              <span className="text-xs font-medium text-green-300">활동</span>
            </div>
            <div className="mb-1 text-2xl font-bold text-white">{totalActivities}</div>
            <div className="text-xs text-green-200">감지된 활동</div>
          </div>

          <div className="p-5 border rounded-lg bg-gradient-to-br from-orange-900/50 to-orange-800/30 border-orange-700/50">
            <div className="flex items-center justify-between mb-3">
              <div className="p-2.5 bg-orange-500/20 rounded-lg">
                <Globe className="w-5 h-5 text-orange-400" />
              </div>
              <span className="text-xs font-medium text-orange-300">웹</span>
            </div>
            <div className="mb-1 text-2xl font-bold text-white">{totalWebsites}</div>
            <div className="text-xs text-orange-200">방문 사이트</div>
          </div>
        </div>

        {/* 메인 컨텐츠 */}
        <div className="grid grid-cols-3 gap-6 mb-6">
          {/* 🆕 프로토콜 분포 (원형 그래프) */}
          <div className="p-6 bg-gray-900 border border-gray-800 rounded-lg">
            <div className="mb-4">
              <h3 className="text-lg font-semibold text-white">
                  프로토콜 분포 <span className="ml-2 text-xs text-green-400">● LIVE</span>
              </h3>
              <p className="mt-1 text-xs text-gray-500">총 {formatNumber(totalPackets)} 패킷</p>
            </div>

            {totalPackets > 0 ? (
              <div className="flex items-center justify-between">
                {/* 원형 그래프 */}
                <div className="relative">
                  <svg width="200" height="200" viewBox="0 0 200 200">
                    <defs>
                      {pieSlices.map((_slice, idx) => (
                        <filter key={`glow-${idx}`} id={`glow-${idx}`}>
                          <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                          <feMerge>
                            <feMergeNode in="coloredBlur"/>
                            <feMergeNode in="SourceGraphic"/>
                          </feMerge>
                        </filter>
                      ))}
                    </defs>

                    {/* 그래프 조각 */}
                    {pieSlices.map((slice, idx) => (
                      <g key={idx}>
                        <path
                          d={createArcPath(slice.startAngle, slice.endAngle, 50, 90)}
                          fill={slice.color}
                          opacity="0.9"
                          filter={`url(#glow-${idx})`}
                          className="transition-all duration-300 hover:opacity-100"
                        />
                      </g>
                    ))}

                    {/* 중앙 원 */}
                    <circle cx="100" cy="100" r="48" fill="#111827" />
                    
                    {/* 중앙 텍스트 */}
                    <text x="100" y="95" textAnchor="middle" fontSize="12" fill="#9ca3af">
                      Total
                    </text>
                    <text x="100" y="112" textAnchor="middle" fontSize="16" fill="#fff" fontWeight="bold">
                      {formatNumber(totalPackets)}
                    </text>
                  </svg>
                </div>

                {/* 범례 */}
                <div className="space-y-3">
                  {pieSlices.map((slice, idx) => (
                    <div key={idx} className="flex items-center gap-3">
                      <div
                        className="w-4 h-4 rounded"
                        style={{ backgroundColor: slice.color }}
                      ></div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between gap-4">
                          <span className="text-sm font-medium text-gray-300">{slice.name}</span>
                          <span className="text-xs text-gray-500">{slice.percentage}%</span>
                        </div>
                        <div className="text-xs font-bold" style={{ color: slice.color }}>
                          {formatNumber(slice.value)} packets
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-center text-gray-500">
                <Activity className="w-12 h-12 mb-3 opacity-50" />
                <p className="text-sm">패킷 수집 중...</p>
                <p className="mt-1 text-xs text-gray-600">네트워크 활동을 시작하면 표시됩니다</p>
              </div>
            )}
          </div>

          {/* 최근 활동 */}
          <div className="col-span-2 p-6 bg-gray-900 border border-gray-800 rounded-lg">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-white">
                    실시간 활동 로그 <span className="ml-2 text-xs text-green-400">● LIVE</span>
                </h3>
                <p className="mt-1 text-xs text-gray-500">총 {totalActivities}개 활동 감지됨</p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setSelectedCategory('all')}
                  className={`px-3 py-1 text-xs rounded ${
                    selectedCategory === 'all' ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400'
                  }`}>
                  전체
                </button>
                <button
                  onClick={() => setSelectedCategory('Video Streaming')}
                  className={`px-3 py-1 text-xs rounded ${
                    selectedCategory === 'Video Streaming' ? 'bg-red-600 text-white' : 'bg-gray-800 text-gray-400'
                  }`}>
                  스트리밍
                </button>
                <button
                  onClick={() => setSelectedCategory('Social Media')}
                  className={`px-3 py-1 text-xs rounded ${
                    selectedCategory === 'Social Media' ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400'
                  }`}>
                  소셜
                </button>
              </div>
            </div>

            <div className="space-y-2 overflow-y-auto max-h-96 scrollbar-thin">
              {filteredActivities.length > 0 ? (
                filteredActivities.slice().reverse().map((activity, idx) => (
                  <div
                    key={idx}
                    className="p-4 transition-all border-l-4 rounded-lg bg-gray-800/50 hover:bg-gray-800"
                    style={{ borderColor: getActivityColor(activity.type) }}>
                    <div className="flex items-start gap-3">
                      <div className="mt-1">{getActivityIcon(activity.type)}</div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-semibold text-white">{activity.service}</span>
                          <span className="text-xs text-gray-500">{activity.time}</span>
                        </div>
                        <div className="text-sm text-gray-400">{activity.details}</div>
                        {activity.domain && (
                          <div className="mt-1 font-mono text-xs text-gray-600">{activity.domain}</div>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-12 text-center text-gray-500">
                  <Activity className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">활동이 감지되지 않았습니다</p>
                  <p className="mt-1 text-xs text-gray-600">네트워크 활동을 시작하면 자동으로 표시됩니다</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* 서비스 통계 */}
        <div className="grid grid-cols-4 gap-6 mb-6">
          {/* 스트리밍 */}
          {stats.streaming_services && Object.keys(stats.streaming_services).length > 0 && (
            <div className="p-5 bg-gray-900 border border-gray-800 rounded-lg">
              <div className="flex items-center gap-2 mb-4">
                <Youtube className="w-5 h-5 text-red-400" />
                <h3 className="font-semibold text-white">스트리밍</h3>
              </div>
              <div className="space-y-2">
                {Object.entries(stats.streaming_services).map(([service, count]) => (
                  <div key={service} className="flex items-center justify-between p-2 rounded bg-gray-800/50">
                    <span className="text-sm text-gray-300">{service}</span>
                    <span className="text-sm font-bold text-red-400">{count}회</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 소셜 미디어 */}
          {stats.social_media && Object.keys(stats.social_media).length > 0 && (
            <div className="p-5 bg-gray-900 border border-gray-800 rounded-lg">
              <div className="flex items-center gap-2 mb-4">
                <MessageCircle className="w-5 h-5 text-blue-400" />
                <h3 className="font-semibold text-white">소셜 미디어</h3>
              </div>
              <div className="space-y-2">
                {Object.entries(stats.social_media).map(([service, count]) => (
                  <div key={service} className="flex items-center justify-between p-2 rounded bg-gray-800/50">
                    <span className="text-sm text-gray-300">{service}</span>
                    <span className="text-sm font-bold text-blue-400">{count}회</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 메신저 */}
          {stats.messaging_apps && Object.keys(stats.messaging_apps).length > 0 && (
            <div className="p-5 bg-gray-900 border border-gray-800 rounded-lg">
              <div className="flex items-center gap-2 mb-4">
                <MessageCircle className="w-5 h-5 text-green-400" />
                <h3 className="font-semibold text-white">메신저</h3>
              </div>
              <div className="space-y-2">
                {Object.entries(stats.messaging_apps).map(([service, count]) => (
                  <div key={service} className="flex items-center justify-between p-2 rounded bg-gray-800/50">
                    <span className="text-sm text-gray-300">{service}</span>
                    <span className="text-sm font-bold text-green-400">{count}회</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 게임 */}
          {stats.gaming_activity && stats.gaming_activity.length > 0 && (
            <div className="p-5 bg-gray-900 border border-gray-800 rounded-lg">
              <div className="flex items-center gap-2 mb-4">
                <Gamepad2 className="w-5 h-5 text-purple-400" />
                <h3 className="font-semibold text-white">게임</h3>
              </div>
              <div className="space-y-2">
                {stats.gaming_activity.map((game, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 rounded bg-gray-800/50">
                    <span className="text-sm text-gray-300">{game.game}</span>
                    <span className="text-xs text-gray-500">{game.time}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* 방문한 웹사이트 */}
        {stats.visited_websites && stats.visited_websites.length > 0 && (
          <div className="p-6 mb-6 bg-gray-900 border border-gray-800 rounded-lg">
            <div className="mb-4">
              <h3 className="text-lg font-semibold text-white">🌐 방문한 웹사이트</h3>
              <p className="mt-1 text-xs text-gray-500">패킷 분석을 통해 감지된 도메인</p>
            </div>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-5">
              {stats.visited_websites.map((site, idx) => (
                <div key={idx} className="p-3 transition-all border rounded-lg bg-gray-800/50 border-gray-700/50 hover:border-blue-500/50">
                  <div className="flex items-center justify-between mb-1">
                    <Globe className="w-4 h-4 text-blue-400" />
                    <span className="text-xs font-bold text-blue-400">{site.count}회</span>
                  </div>
                  <div className="text-xs text-gray-300 truncate" title={site.domain}>
                    {site.domain}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 패킷 유입량 그래프 */}
        <div className="p-6 bg-gray-900 border border-gray-800 rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-lg font-semibold text-white"> 실시간 패킷 유입량</h3>
              <p className="mt-1 text-xs text-gray-500">
                초당 패킷 증가량 | {trafficHistory.length}/30 포인트
              </p>
            </div>
          </div>

          <div className="relative p-4 border rounded-lg h-80 bg-gradient-to-b from-gray-950 to-gray-900 border-gray-800/50">
            {trafficHistory.length >= 2 ? (
              <svg width="100%" height="100%" viewBox="0 0 1200 320" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="gradient" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.6" />
                    <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.05" />
                  </linearGradient>
                </defs>

                {/* 패킷 영역 */}
                <path
                  d={`
                    M 60 255
                    ${trafficHistory
                      .map((d, i) => {
                        const x = 60 + (i * 1120) / Math.max(trafficHistory.length - 1, 1)
                        const maxPackets = Math.max(...trafficHistory.map((d) => d.packets), 1)
                        const y = Math.max(30, 255 - (d.packets / maxPackets) * 225)
                        return `L ${x} ${y}`
                      })
                      .join(' ')}
                    L 1180 255 Z
                  `}
                  fill="url(#gradient)"
                />

                {/* 패킷 라인 */}
                <polyline
                  points={trafficHistory
                    .map((d, i) => {
                      const x = 60 + (i * 1120) / Math.max(trafficHistory.length - 1, 1)
                      const maxPackets = Math.max(...trafficHistory.map((d) => d.packets), 1)
                      const y = Math.max(30, 255 - (d.packets / maxPackets) * 225)
                      return `${x},${y}`
                    })
                    .join(' ')}
                  fill="none"
                  stroke="#3b82f6"
                  strokeWidth="3"
                />
              </svg>
            ) : (
              <div className="flex flex-col items-center justify-center h-full">
                <div className="w-12 h-12 mb-4 border-t-2 border-blue-500 rounded-full animate-spin"></div>
                <p className="text-gray-400">데이터 수집 중...</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard