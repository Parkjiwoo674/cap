import type {SystemStats} from '../types/types'

const API_BASE_URL = 'http://localhost:8000'

/**
 * REST API: 현재 시스템 통계 조회
 */
export const fetchStats = async (): Promise<SystemStats> => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/stats`)
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }
    return await response.json()
  } catch (error) {
    console.error('Failed to fetch stats:', error)
    throw error
  }
}

/**
 * WebSocket 연결 생성
 */
export const createWebSocket = (
  onMessage: (data: SystemStats) => void,
  onError?: (error: Event) => void,
  onClose?: () => void
): WebSocket => {
  const ws = new WebSocket(`ws://localhost:8000/ws`)

  ws.onmessage = event => {
    const data = JSON.parse(event.data) as SystemStats
    onMessage(data)
  }

  if (onError) {
    ws.onerror = onError
  }

  if (onClose) {
    ws.onclose = onClose
  }

  return ws
}

/**
 * 서버 상태 확인
 */
export const checkServerHealth = async (): Promise<boolean> => {
  try {
    const response = await fetch(`${API_BASE_URL}/`)
    return response.ok
  } catch {
    return false
  }
}
