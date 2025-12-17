from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import asyncio
from datetime import datetime
from collections import defaultdict, Counter
import threading
import time
import re

app = FastAPI()

# ========== 설정 가능한 값들 ==========
CONFIG = {
    "MAX_PACKET_LOGS": 50,
    "MAX_USER_ACTIVITIES": 100,
    "BANDWIDTH_WINDOW": 5,
    "ACTIVITY_DUPLICATE_THRESHOLD": 3,
    "MAX_ACTIVE_CONNECTIONS": 1000,
    "CONNECTION_TIMEOUT": 300,
    "WEBSOCKET_UPDATE_INTERVAL": 1,
    "PACKET_LOGS_DISPLAY": 30,
    "ACTIVITIES_DISPLAY": 20,
    "TOP_SERVICES_COUNT": 5,
    "TOP_WEBSITES_COUNT": 10,
    "RECENT_EVENTS_COUNT": 5,
    "UNUSUAL_PORT_THRESHOLD": 100,
    "BANDWIDTH_SPIKE_THRESHOLD": 10,
    "SUSPICIOUS_COUNTRIES": ["CN", "RU", "KP"],
    "ALERT_COOLDOWN": 60,
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 전역 변수
total_packets = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0
bandwidth_history = []
peak_bandwidth = 0
last_total_packets = 0
last_update_time = time.time()

# 실시간 패킷 유입량 추적 (시계열 데이터)
packet_timeline = []  # [(timestamp, packet_count, suspicious_count, bandwidth)]
MAX_TIMELINE_POINTS = 60  # 최근 60초 데이터 유지

recent_packets = []
user_activities = []
visited_websites = Counter()
streaming_services = Counter()
social_media_usage = Counter()
messaging_apps = Counter()
file_downloads = []
video_streaming = []
gaming_activity = []
video_calls = []
cloud_services = Counter()
active_connections = set()

recent_dns_queries = {}
recent_service_access = {}
DNS_CACHE_TIMEOUT = 60
SERVICE_CACHE_TIMEOUT = 60

# 보안 경고 시스템
security_alerts = []
recent_alerts = {}
suspicious_ips = set()
suspicious_ports_detected = {}  # {port: {"count": N, "last_seen": timestamp, "ips": set()}}
suspicious_packets = []  # 의심스러운 패킷 로그
port_usage = defaultdict(list)
unknown_processes = set()

MALICIOUS_PATTERNS = [
    r'.*-miner\..*',
    r'.*\.tk$',
    r'.*\.ga$',
    r'.*\.ml$',
    r'.*\.cf$',
    r'.*torrent.*',
    r'.*crack.*',
    r'.*keygen.*',
]

SUSPICIOUS_PORTS = {
    1337: "해커 포트 (Leet)",
    31337: "백오리피스 (Back Orifice)",
    4444: "원격 제어 백도어",
    5555: "안드로이드 디버그 백도어",
    6666: "IRC 봇넷",
    6667: "IRC 봇넷",
    8080: "HTTP 프록시",
    8888: "대체 웹 서버",
    9999: "트로이 목마",
}

SERVICE_PATTERNS = {
    'YouTube': [r'youtube\.com', r'googlevideo\.com', r'ytimg\.com'],
    'Netflix': [r'netflix\.com', r'nflxvideo\.net'],
    'Twitch': [r'twitch\.tv', r'ttvnw\.net'],
    'Facebook': [r'facebook\.com', r'fbcdn\.net'],
    'Instagram': [r'instagram\.com', r'cdninstagram\.com'],
    'Twitter/X': [r'twitter\.com', r'x\.com', r'twimg\.com'],
    'TikTok': [r'tiktok\.com', r'tiktokcdn\.com'],
    'Discord': [r'discord\.com', r'discord\.gg'],
    'KakaoTalk': [r'kakao\.com', r'kakaocdn\.net'],
    'Zoom': [r'zoom\.us', r'zoom\.com'],
    'Steam': [r'steampowered\.com'],
    'League of Legends': [r'riotgames\.com'],
    'Google Drive': [r'drive\.google\.com'],
    'GitHub': [r'github\.com'],
    'Google': [r'^google\.com', r'^www\.google\.'],
    'Naver': [r'naver\.com'],
    'Spotify': [r'spotify\.com'],
}

class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"✅ 클라이언트 연결 (총 {len(self.active_connections)}개)")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"❌ 연결 해제 (남은 {len(self.active_connections)}개)")

    async def broadcast(self, message: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

def detect_service(domain):
    for service, patterns in SERVICE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return service
    return None

def add_security_alert(alert_type, severity, message, details=""):
    current_time = datetime.now()
    alert_key = f"{alert_type}:{message}"
    
    if alert_key in recent_alerts:
        time_diff = current_time.timestamp() - recent_alerts[alert_key]
        if time_diff < CONFIG["ALERT_COOLDOWN"]:
            return
    
    recent_alerts[alert_key] = current_time.timestamp()
    
    alert = {
        "type": alert_type,
        "severity": severity,
        "message": message,
        "details": details,
        "time": current_time.strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp": current_time.timestamp()
    }
    
    security_alerts.append(alert)
    
    if len(security_alerts) > 100:
        security_alerts[:] = security_alerts[-100:]
    
    print(f"🚨 [{severity.upper()}] {alert_type}: {message}")

def check_malicious_domain(domain):
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, domain, re.IGNORECASE):
            return True
    return False

def check_suspicious_port(port):
    return port in SUSPICIOUS_PORTS

def get_port_description(port):
    """포트 설명 가져오기"""
    return SUSPICIOUS_PORTS.get(port, "알 수 없는 포트")

def record_suspicious_port(port, ip):
    """의심스러운 포트 기록"""
    current_time = time.time()
    
    if port not in suspicious_ports_detected:
        suspicious_ports_detected[port] = {
            "count": 0,
            "first_seen": current_time,
            "last_seen": current_time,
            "ips": set(),
            "description": get_port_description(port)
        }
    
    suspicious_ports_detected[port]["count"] += 1
    suspicious_ports_detected[port]["last_seen"] = current_time
    suspicious_ports_detected[port]["ips"].add(ip)
    
    # 오래된 기록 정리 (30분 이상)
    old_ports = [
        p for p, data in suspicious_ports_detected.items()
        if current_time - data["last_seen"] > 1800
    ]
    for p in old_ports:
        del suspicious_ports_detected[p]

def record_suspicious_packet(packet_info):
    """의심스러운 패킷 기록"""
    suspicious_packets.append(packet_info)
    
    # 최대 100개만 유지
    if len(suspicious_packets) > 100:
        suspicious_packets.pop(0)

def analyze_port_usage():
    current_time = time.time()
    
    for port, timestamps in port_usage.items():
        recent = [t for t in timestamps if current_time - t <= 60]
        
        if len(recent) > CONFIG["UNUSUAL_PORT_THRESHOLD"]:
            add_security_alert(
                "Port Scanning",
                "high",
                f"비정상적인 포트 활동 감지: {port}번 포트",
                f"{len(recent)}개 패킷/분"
            )
    
    for port in list(port_usage.keys()):
        port_usage[port] = [t for t in port_usage[port] if current_time - t <= 300]
        if not port_usage[port]:
            del port_usage[port]

def add_activity(activity_type, service, details="", domain=""):
    current_time = datetime.now()
    
    recent = [
        a for a in user_activities[-10:]
        if a['type'] == activity_type and 
           a['service'] == service and
           (current_time.timestamp() - a['timestamp']) < CONFIG["ACTIVITY_DUPLICATE_THRESHOLD"]
    ]
    
    if not recent:
        activity = {
            "type": activity_type,
            "service": service,
            "details": details,
            "domain": domain,
            "time": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": current_time.timestamp()
        }
        
        user_activities.append(activity)
        
        if len(user_activities) > CONFIG["MAX_USER_ACTIVITIES"]:
            user_activities[:] = user_activities[-CONFIG["MAX_USER_ACTIVITIES"]:]
        
        print(f"📝 {activity_type}: {service} - {details}")

def packet_callback(packet):
    global total_packets, tcp_count, udp_count, icmp_count, other_count
    global bandwidth_history, peak_bandwidth
    global visited_websites, streaming_services, social_media_usage
    global messaging_apps, cloud_services, recent_packets, active_connections
    global recent_dns_queries, recent_service_access, suspicious_ips
    global suspicious_ports_detected
    
    total_packets += 1
    current_time = time.time()
    
    packet_info = {
        "protocol": "OTHER",
        "src_ip": "Unknown",
        "dst_ip": "Unknown",
        "size": len(packet) if hasattr(packet, '__len__') else 0,
        "time": datetime.now().strftime("%H:%M:%S"),
        "timestamp": current_time
    }
    
    is_suspicious = False
    
    if packet.haslayer(TCP):
        tcp_count += 1
        packet_info["protocol"] = "TCP"
        if packet.haslayer(IP):
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
            
            if check_suspicious_port(packet[TCP].dport):
                is_suspicious = True
                packet_info["threat_type"] = "suspicious_port"
                packet_info["threat_desc"] = get_port_description(packet[TCP].dport)
                record_suspicious_port(packet[TCP].dport, packet[IP].dst)
                record_suspicious_packet(packet_info.copy())
                add_security_alert(
                    "Suspicious Port",
                    "high",
                    f"의심스러운 포트 사용: {packet[TCP].dport} ({get_port_description(packet[TCP].dport)})",
                    f"{packet[IP].dst}:{packet[TCP].dport}"
                )
            
            port_usage[packet[TCP].dport].append(current_time)
    
    elif packet.haslayer(UDP):
        udp_count += 1
        packet_info["protocol"] = "UDP"
        if packet.haslayer(IP):
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport
            
            if check_suspicious_port(packet[UDP].dport):
                is_suspicious = True
                packet_info["threat_type"] = "suspicious_port"
                packet_info["threat_desc"] = get_port_description(packet[UDP].dport)
                record_suspicious_port(packet[UDP].dport, packet[IP].dst)
                record_suspicious_packet(packet_info.copy())
                add_security_alert(
                    "Suspicious Port",
                    "high",
                    f"의심스러운 포트 사용: {packet[UDP].dport} ({get_port_description(packet[UDP].dport)})",
                    f"{packet[IP].dst}:{packet[UDP].dport}"
                )
            
            port_usage[packet[UDP].dport].append(current_time)
    
    elif packet.haslayer('ICMP'):
        icmp_count += 1
        packet_info["protocol"] = "ICMP"
        if packet.haslayer(IP):
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
    
    else:
        other_count += 1
    
    packet_info["suspicious"] = is_suspicious
    
    recent_packets.append(packet_info)
    if len(recent_packets) > CONFIG["MAX_PACKET_LOGS"]:
        recent_packets.pop(0)
    
    packet_size = len(packet) if hasattr(packet, '__len__') else 0
    bandwidth_history.append((current_time, packet_size))
    bandwidth_history = [
        (t, s) for t, s in bandwidth_history 
        if current_time - t <= CONFIG["BANDWIDTH_WINDOW"]
    ]
    
    if bandwidth_history:
        total_bytes = sum(size for _, size in bandwidth_history)
        bytes_per_sec = total_bytes / CONFIG["BANDWIDTH_WINDOW"]
        mbps = bytes_per_sec / (1024 * 1024)
        
        if mbps > CONFIG["BANDWIDTH_SPIKE_THRESHOLD"]:
            add_security_alert(
                "Bandwidth Spike",
                "medium",
                f"대역폭 급증 감지: {mbps:.2f} MB/s",
                "대용량 데이터 전송 중"
            )
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        active_connections.add(f"{src_ip}:{dst_ip}")
        
        if len(active_connections) > CONFIG["MAX_ACTIVE_CONNECTIONS"]:
            active_connections.clear()
    
    if total_packets % 100 == 0:
        analyze_port_usage()
    
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            query = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
            
            if any(skip in query for skip in ['in-addr.arpa', 'local', '_', 'ip6', 'wpad']):
                return
            
            if check_malicious_domain(query):
                add_security_alert(
                    "Malicious Domain",
                    "critical",
                    f"악성 도메인 접속 시도: {query}",
                    "잠재적 위협 도메인 감지"
                )
                suspicious_ips.add(query)
                
                # 악성 도메인 패킷도 기록
                malicious_packet = {
                    "protocol": "DNS",
                    "src_ip": packet[IP].src if packet.haslayer(IP) else "Unknown",
                    "dst_ip": packet[IP].dst if packet.haslayer(IP) else "Unknown",
                    "domain": query,
                    "size": len(packet) if hasattr(packet, '__len__') else 0,
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "timestamp": current_time,
                    "suspicious": True,
                    "threat_type": "malicious_domain",
                    "threat_desc": "악성 도메인"
                }
                record_suspicious_packet(malicious_packet)
            
            service = detect_service(query)
            
            if service:
                if service in recent_service_access:
                    time_diff = current_time - recent_service_access[service]
                    if time_diff < SERVICE_CACHE_TIMEOUT:
                        return
                
                recent_service_access[service] = current_time
                
                if len(recent_service_access) > 100:
                    old_services = [
                        s for s, t in recent_service_access.items()
                        if current_time - t > SERVICE_CACHE_TIMEOUT * 2
                    ]
                    for s in old_services:
                        del recent_service_access[s]
                
                visited_websites[query] += 1
                
                if service in ['YouTube', 'Netflix', 'Twitch']:
                    streaming_services[service] += 1
                    add_activity("Video Streaming", service, "접속", query)
                
                elif service in ['Facebook', 'Instagram', 'Twitter/X', 'TikTok']:
                    social_media_usage[service] += 1
                    add_activity("Social Media", service, "사용 중", query)
                
                elif service in ['Discord', 'KakaoTalk']:
                    messaging_apps[service] += 1
                    add_activity("Messaging", service, "메시지", query)
                
                elif service == 'Zoom':
                    add_activity("Video Call", service, "회의 중", query)
                    video_calls.append({"service": service, "time": datetime.now().strftime("%H:%M:%S")})
                
                elif service in ['Steam', 'League of Legends']:
                    add_activity("Gaming", service, "플레이 중", query)
                    gaming_activity.append({"game": service, "time": datetime.now().strftime("%H:%M:%S")})
                
                elif service in ['Google Drive', 'GitHub']:
                    cloud_services[service] += 1
                    add_activity("Cloud Service", service, "파일 접근", query)
                
                elif service == 'Spotify':
                    add_activity("Music Streaming", service, "음악 재생", query)
                
                else:
                    add_activity("Web Browsing", service, "방문", query)
            
            else:
                if query in recent_dns_queries:
                    time_diff = current_time - recent_dns_queries[query]
                    if time_diff < DNS_CACHE_TIMEOUT:
                        return
                
                recent_dns_queries[query] = current_time
                
                if len(recent_dns_queries) > 500:
                    old_queries = [
                        q for q, t in recent_dns_queries.items()
                        if current_time - t > DNS_CACHE_TIMEOUT * 2
                    ]
                    for q in old_queries:
                        del recent_dns_queries[q]
                
                visited_websites[query] += 1
                
                if not any(known in query for known in ['.google.', '.microsoft.', '.apple.', '.amazon.']):
                    add_security_alert(
                        "Unknown Domain",
                        "low",
                        f"알 수 없는 도메인 접속: {query}",
                        "확인되지 않은 사이트"
                    )
                
                add_activity("Web Browsing", query, "웹사이트 방문", query)
        
        except Exception:
            pass
    
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        try:
            payload = packet[Raw].load
            payload_str = payload.decode('utf-8', errors='ignore')
            
            if payload_str.startswith(('GET ', 'POST ')):
                host_match = re.search(r'Host: ([^\r\n]+)', payload_str)
                if host_match:
                    domain = host_match.group(1).strip()
                    
                    if 'googlevideo' in domain or 'youtube' in domain:
                        if 'videoplayback' in payload_str:
                            add_activity("Video Streaming", "YouTube", "동영상 시청 중", domain)
                            video_streaming.append({"service": "YouTube", "time": datetime.now().strftime("%H:%M:%S")})
        
        except Exception:
            pass

def start_sniffing():
    print("🚀 패킷 스니핑 시작...")
    print("📊 실제 네트워크 데이터만 수집합니다")
    print("=" * 60)
    
    try:
        # 네트워크 인터페이스 확인
        from scapy.all import get_if_list, conf
        interfaces = get_if_list()
        print(f"✅ 사용 가능한 네트워크 인터페이스: {len(interfaces)}개")
        print(f"📡 현재 인터페이스: {conf.iface}")
        print("=" * 60)
        
        sniff(prn=packet_callback, store=False)
    except PermissionError:
        print("=" * 60)
        print("❌ 권한 오류: 관리자 권한으로 실행하세요")
        print("   Windows: 관리자 권한으로 CMD 실행")
        print("   Linux/Mac: sudo python run.py")
        print("=" * 60)
    except OSError as e:
        print("=" * 60)
        print("❌ 네트워크 인터페이스 오류")
        print(f"   오류 내용: {e}")
        print("   해결 방법:")
        print("   1. Npcap 설치: https://npcap.com/#download")
        print("   2. 'WinPcap API-compatible Mode' 체크하고 설치")
        print("   3. 컴퓨터 재부팅")
        print("=" * 60)
    except ImportError as e:
        print("=" * 60)
        print("❌ Scapy 설치 오류")
        print(f"   오류 내용: {e}")
        print("   해결 방법: pip install scapy")
        print("=" * 60)
    except Exception as e:
        print("=" * 60)
        print(f"❌ 예상치 못한 오류: {e}")
        print(f"   오류 타입: {type(e).__name__}")
        print("=" * 60)
        import traceback
        traceback.print_exc()

sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
sniffing_thread.start()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    global last_total_packets, last_update_time, peak_bandwidth
    
    try:
        while True:
            try:
                current_time = time.time()
                time_diff = current_time - last_update_time
                
                if bandwidth_history and time_diff > 0:
                    total_bytes = sum(size for _, size in bandwidth_history)
                    bytes_per_sec = total_bytes / CONFIG["BANDWIDTH_WINDOW"] if len(bandwidth_history) > 0 else 0
                    avg_bandwidth = bytes_per_sec / (1024 * 1024)
                    if avg_bandwidth > peak_bandwidth:
                        peak_bandwidth = avg_bandwidth
                else:
                    avg_bandwidth = 0
                
                packet_diff = total_packets - last_total_packets
                packet_change_rate = (packet_diff / last_total_packets * 100) if last_total_packets > 0 else 0
                last_total_packets = total_packets
                last_update_time = current_time
                
                stats = {
                    "total_packets": total_packets,
                    "tcp_count": tcp_count,
                    "udp_count": udp_count,
                    "icmp_count": icmp_count,
                    "other_count": other_count,
                    "avg_bandwidth": round(avg_bandwidth, 2),
                    "peak_bandwidth": round(peak_bandwidth, 2),
                    "active_connections": len(active_connections),
                    "threat_change": packet_diff,
                    "packet_change_rate": round(packet_change_rate, 2),
                    
                    # 패킷 로그
                    "packet_logs": recent_packets[-CONFIG["PACKET_LOGS_DISPLAY"]:],
                    "suspicious_packet_logs": suspicious_packets[-30:],  # 의심스러운 패킷 30개
                    
                    # 활동 데이터
                    "activities": user_activities[-CONFIG["ACTIVITIES_DISPLAY"]:],
                    "streaming_services": dict(streaming_services.most_common(CONFIG["TOP_SERVICES_COUNT"])),
                    "social_media": dict(social_media_usage.most_common(CONFIG["TOP_SERVICES_COUNT"])),
                    "messaging_apps": dict(messaging_apps.most_common(CONFIG["TOP_SERVICES_COUNT"])),
                    "cloud_services": dict(cloud_services.most_common(CONFIG["TOP_SERVICES_COUNT"])),
                    "visited_websites": [
                        {"domain": domain, "count": count}
                        for domain, count in visited_websites.most_common(CONFIG["TOP_WEBSITES_COUNT"])
                    ],
                    "video_streaming": video_streaming[-CONFIG["RECENT_EVENTS_COUNT"]:],
                    "file_downloads": file_downloads[-CONFIG["RECENT_EVENTS_COUNT"]:],
                    "gaming_activity": gaming_activity[-CONFIG["RECENT_EVENTS_COUNT"]:],
                    "video_calls": video_calls[-CONFIG["RECENT_EVENTS_COUNT"]:],
                    
                    # 보안 데이터
                    "security_alerts": security_alerts[-20:],
                    "suspicious_ips": list(suspicious_ips)[-10:],
                    "suspicious_ports": [
                        {
                            "port": port,
                            "description": data["description"],
                            "count": data["count"],
                            "ips": list(data["ips"]),
                            "first_seen": datetime.fromtimestamp(data["first_seen"]).strftime("%H:%M:%S"),
                            "last_seen": datetime.fromtimestamp(data["last_seen"]).strftime("%H:%M:%S")
                        }
                        for port, data in sorted(
                            suspicious_ports_detected.items(),
                            key=lambda x: x[1]["count"],
                            reverse=True
                        )[:10]
                    ],
                    "alert_summary": {
                        "critical": len([a for a in security_alerts if a["severity"] == "critical"]),
                        "high": len([a for a in security_alerts if a["severity"] == "high"]),
                        "medium": len([a for a in security_alerts if a["severity"] == "medium"]),
                        "low": len([a for a in security_alerts if a["severity"] == "low"]),
                    },
                    
                    # 통계 데이터 (원형 그래프용 - 명확하게 개선)
                    "threat_stats": {
                        # 전체 패킷 분류
                        "normal_packets": total_packets - len(suspicious_packets),
                        "suspicious_packets": len(suspicious_packets),
                        "total_packets": total_packets,
                        "suspicious_percentage": round((len(suspicious_packets) / total_packets * 100) if total_packets > 0 else 0, 2),
                        
                        # 프로토콜별 분류 (더 명확)
                        "protocol_distribution": {
                            "TCP": tcp_count,
                            "UDP": udp_count,
                            "ICMP": icmp_count,
                            "기타": other_count
                        },
                        
                        # 위협 유형별 분류
                        "threat_types": {
                            "suspicious_ports": len([p for p in suspicious_packets if p.get("threat_type") == "suspicious_port"]),
                            "malicious_domains": len([p for p in suspicious_packets if p.get("threat_type") == "malicious_domain"]),
                            "bandwidth_spikes": len([a for a in security_alerts if a.get("type") == "Bandwidth Spike"]),
                            "port_scanning": len([a for a in security_alerts if a.get("type") == "Port Scanning"]),
                        },
                        
                        # 심각도별 분류
                        "severity_distribution": {
                            "critical": len([a for a in security_alerts if a["severity"] == "critical"]),
                            "high": len([a for a in security_alerts if a["severity"] == "high"]),
                            "medium": len([a for a in security_alerts if a["severity"] == "medium"]),
                            "low": len([a for a in security_alerts if a["severity"] == "low"]),
                            "safe": total_packets - len(suspicious_packets)
                        },
                        
                        # 포트별 통계
                        "port_statistics": {
                            "unique_suspicious_ports": len(suspicious_ports_detected),
                            "total_suspicious_connections": sum(data["count"] for data in suspicious_ports_detected.values()),
                            "most_dangerous_port": max(suspicious_ports_detected.items(), key=lambda x: x[1]["count"])[0] if suspicious_ports_detected else None
                        },
                        
                        # 시간대별 위협 트렌드
                        "recent_threat_trend": len([a for a in security_alerts[-10:] if (time.time() - a["timestamp"]) < 300])  # 최근 5분
                    }
                }
                
                await manager.broadcast(stats)
                await asyncio.sleep(CONFIG["WEBSOCKET_UPDATE_INTERVAL"])
            
            except asyncio.CancelledError:
                print("⚠️ WebSocket 취소됨")
                break
            except Exception as e:
                print(f"❌ 오류: {e}")
                break
    
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        pass
    finally:
        manager.disconnect(websocket)

@app.get("/")
async def root():
    return {
        "status": "running",
        "total_packets": total_packets,
        "total_activities": len(user_activities),
        "recent_packets": len(recent_packets),
        "security_alerts": len(security_alerts),
        "suspicious_packets": len(suspicious_packets),
        "message": "실제 네트워크 데이터만 추적 중"
    }

@app.get("/timeline")
async def get_packet_timeline():
    """실시간 패킷 타임라인 전용 엔드포인트"""
    return {
        "timeline": packet_timeline[-120:],  # 최근 2분
        "summary": {
            "avg_pps": round(sum(p["packets_per_second"] for p in packet_timeline) / len(packet_timeline) if packet_timeline else 0, 1),
            "max_pps": max([p["packets_per_second"] for p in packet_timeline]) if packet_timeline else 0,
            "avg_bandwidth": round(sum(p["bandwidth_mbps"] for p in packet_timeline) / len(packet_timeline) if packet_timeline else 0, 3),
            "peak_bandwidth": max([p["bandwidth_mbps"] for p in packet_timeline]) if packet_timeline else 0,
            "total_suspicious": sum(p["suspicious_packets"] for p in packet_timeline),
            "threat_periods": len([p for p in packet_timeline if p["threat_level"] in ["high", "critical"]])
        }
    }

@app.get("/stats")
async def get_statistics():
    """통계 데이터 전용 엔드포인트 (그래프용)"""
    return {
        # 패킷 안전도 분포
        "safety_distribution": {
            "safe": {
                "count": total_packets - len(suspicious_packets),
                "percentage": round((total_packets - len(suspicious_packets)) / total_packets * 100 if total_packets > 0 else 0, 2),
                "color": "#10b981",
                "label": "안전"
            },
            "suspicious": {
                "count": len(suspicious_packets),
                "percentage": round(len(suspicious_packets) / total_packets * 100 if total_packets > 0 else 0, 2),
                "color": "#f59e0b",
                "label": "의심"
            }
        },
        
        # 프로토콜 분포
        "protocol_distribution": [
            {"name": "TCP", "value": tcp_count, "color": "#3b82f6"},
            {"name": "UDP", "value": udp_count, "color": "#8b5cf6"},
            {"name": "ICMP", "value": icmp_count, "color": "#ec4899"},
            {"name": "기타", "value": other_count, "color": "#6b7280"}
        ],
        
        # 위협 심각도 분포
        "severity_distribution": [
            {
                "name": "안전", 
                "value": total_packets - len(suspicious_packets), 
                "color": "#10b981",
                "icon": "✅"
            },
            {
                "name": "낮음", 
                "value": len([a for a in security_alerts if a["severity"] == "low"]), 
                "color": "#fbbf24",
                "icon": "⚠️"
            },
            {
                "name": "중간", 
                "value": len([a for a in security_alerts if a["severity"] == "medium"]), 
                "color": "#f59e0b",
                "icon": "🔶"
            },
            {
                "name": "높음", 
                "value": len([a for a in security_alerts if a["severity"] == "high"]), 
                "color": "#ef4444",
                "icon": "🔴"
            },
            {
                "name": "치명적", 
                "value": len([a for a in security_alerts if a["severity"] == "critical"]), 
                "color": "#dc2626",
                "icon": "🚨"
            }
        ],
        
        # 위협 유형별 분포
        "threat_types": [
            {
                "name": "의심 포트",
                "value": len([p for p in suspicious_packets if p.get("threat_type") == "suspicious_port"]),
                "color": "#ef4444",
                "description": "백도어, 해킹 시도"
            },
            {
                "name": "악성 도메인",
                "value": len([p for p in suspicious_packets if p.get("threat_type") == "malicious_domain"]),
                "color": "#dc2626",
                "description": "멀웨어, 피싱"
            },
            {
                "name": "대역폭 급증",
                "value": len([a for a in security_alerts if a.get("type") == "Bandwidth Spike"]),
                "color": "#f59e0b",
                "description": "데이터 유출 가능성"
            },
            {
                "name": "포트 스캔",
                "value": len([a for a in security_alerts if a.get("type") == "Port Scanning"]),
                "color": "#f97316",
                "description": "공격 준비 단계"
            }
        ],
        
        # 상위 의심 포트 (막대 그래프용)
        "top_suspicious_ports": [
            {
                "port": port,
                "name": f"{port}번 ({data['description']})",
                "count": data["count"],
                "description": data["description"],
                "color": "#ef4444" if data["count"] > 10 else "#f59e0b"
            }
            for port, data in sorted(
                suspicious_ports_detected.items(),
                key=lambda x: x[1]["count"],
                reverse=True
            )[:5]
        ],
        
        # 트래픽 추세 (라인 그래프용)
        "traffic_trend": {
            "normal": total_packets - len(suspicious_packets),
            "suspicious": len(suspicious_packets),
            "trend": "increasing" if len(suspicious_packets) > 10 else "stable"
        },
        
        # 요약 통계
        "summary": {
            "total_packets": total_packets,
            "total_threats": len(security_alerts),
            "threat_rate": round(len(suspicious_packets) / total_packets * 100 if total_packets > 0 else 0, 2),
            "security_score": round(100 - (len(suspicious_packets) / total_packets * 100) if total_packets > 0 else 100, 1),
            "status": "critical" if len(suspicious_packets) > total_packets * 0.1 else "warning" if len(suspicious_packets) > total_packets * 0.05 else "safe"
        }
    }

@app.get("/alerts")
async def get_alerts():
    return {
        "alerts": security_alerts[-50:],
        "summary": {
            "total": len(security_alerts),
            "critical": len([a for a in security_alerts if a["severity"] == "critical"]),
            "high": len([a for a in security_alerts if a["severity"] == "high"]),
            "medium": len([a for a in security_alerts if a["severity"] == "medium"]),
            "low": len([a for a in security_alerts if a["severity"] == "low"]),
        },
        "suspicious_ips": list(suspicious_ips),
        "suspicious_ports": [
            {
                "port": port,
                "description": data["description"],
                "count": data["count"],
                "ips": list(data["ips"]),
                "first_seen": datetime.fromtimestamp(data["first_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": datetime.fromtimestamp(data["last_seen"]).strftime("%Y-%m-%d %H:%M:%S")
            }
            for port, data in suspicious_ports_detected.items()
        ]
    }

@app.get("/ports")
async def get_suspicious_ports():
    """의심스러운 포트 상세 정보"""
    return {
        "suspicious_ports": [
            {
                "port": port,
                "description": data["description"],
                "count": data["count"],
                "ips": list(data["ips"]),
                "first_seen": datetime.fromtimestamp(data["first_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": datetime.fromtimestamp(data["last_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
                "duration": round((data["last_seen"] - data["first_seen"]) / 60, 2)  # 분 단위
            }
            for port, data in sorted(
                suspicious_ports_detected.items(),
                key=lambda x: x[1]["count"],
                reverse=True
            )
        ],
        "total_suspicious_ports": len(suspicious_ports_detected)
    }

@app.get("/suspicious")
async def get_suspicious_packets():
    """의심스러운 패킷 전용 엔드포인트"""
    return {
        "suspicious_packets": suspicious_packets[-50:],
        "total_suspicious": len(suspicious_packets),
        "threat_breakdown": {
            "suspicious_ports": len([p for p in suspicious_packets if p.get("threat_type") == "suspicious_port"]),
            "malicious_domains": len([p for p in suspicious_packets if p.get("threat_type") == "malicious_domain"]),
        }
    }

@app.get("/config")
async def get_config():
    return CONFIG

@app.post("/config")
async def update_config(new_config: dict):
    CONFIG.update(new_config)
    return {"status": "updated", "config": CONFIG}

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🛡️  NetGuard Real-Time Packet Monitor")
    print("=" * 60)
    print("📡 서버: http://localhost:8000")
    print("🔌 WebSocket: ws://localhost:8000/ws")
    print("=" * 60)
    print("⚠️  관리자 권한 필요:")
    print("   Windows: 관리자 권한으로 CMD 실행")
    print("   Linux/Mac: sudo python run.py")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")