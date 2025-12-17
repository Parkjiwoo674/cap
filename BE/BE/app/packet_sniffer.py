from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Packet
from typing import Dict, List, Set
from datetime import datetime
from collections import defaultdict
import threading
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProtocolStats:
    def __init__(self):
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.arp = 0
        self.ddos = 0


class ThreatInfo:
    def __init__(self, type: str, ip: str, time: str, severity: str):
        self.type = type
        self.ip = ip
        self.time = time
        self.severity = severity


class PacketSniffer:
    def __init__(self):
        self.is_running = False
        self.packet_count = 0
        self.protocol_stats = ProtocolStats()
        self.bandwidth_data = []
        self.connection_count = 0
        self.threats = []
        
        # IP별 패킷 수 추적 (DDoS 탐지용)
        self.ip_counter: Dict[str, int] = defaultdict(int)
        
        # 포트 스캔 탐지용 (IP별 접근한 포트 집합)
        self.port_scan_detector: Dict[str, Set[int]] = defaultdict(set)
        
        self.prev_packet_count = 0
        self.prev_threat_count = 0

    def start_sniffing(self, interface=None):
        """실제 패킷 캡처 시작"""
        if self.is_running:
            logger.warning("Packet sniffer is already running")
            return
        
        self.is_running = True
        
        def capture_packets():
            try:
                logger.info(f"Starting packet capture on interface: {interface or 'default'}")
                
                sniff(
                    iface=interface,
                    prn=self.packet_callback,
                    store=False,  # 메모리 절약
                    stop_filter=lambda x: not self.is_running
                )
            except PermissionError:
                logger.error("Permission denied! Run with sudo/administrator privileges")
                self.is_running = False
            except Exception as e:
                logger.error(f"Error during packet capture: {e}")
                self.is_running = False
        
        # 별도 스레드에서 실행
        capture_thread = threading.Thread(target=capture_packets, daemon=True)
        capture_thread.start()
        logger.info("Packet sniffer thread started")

    def packet_callback(self, packet: Packet):
        """캡처된 패킷 처리"""
        try:
            self.packet_count += 1
            
            # IP 레이어가 있는 패킷만 처리
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_len = len(packet)
                
                # 대역폭 계산 (Mbps)
                bandwidth_mbps = (packet_len * 8) / (1024 * 1024)
                self.bandwidth_data.append(bandwidth_mbps)
                
                # 최근 100개만 유지
                if len(self.bandwidth_data) > 100:
                    self.bandwidth_data = self.bandwidth_data[-100:]
                
                # IP별 패킷 수 추적
                self.ip_counter[src_ip] += 1
                
                # DDoS 공격 탐지 (단일 IP에서 100개 이상)
                if self.ip_counter[src_ip] == 100:  # 정확히 100일 때만 (중복 방지)
                    self._add_threat("DDoS 공격", src_ip, "높음")
                    self.protocol_stats.ddos += 1
                    logger.warning(f"DDoS attack detected from {src_ip}")
                
                # 프로토콜 분류
                if TCP in packet:
                    self.protocol_stats.tcp += 1
                    
                    # 포트 스캔 탐지
                    dst_port = packet[TCP].dport
                    self.port_scan_detector[src_ip].add(dst_port)
                    
                    if len(self.port_scan_detector[src_ip]) == 20:  # 정확히 20일 때만
                        self._add_threat("포트 스캔", src_ip, "중간")
                        logger.warning(f"Port scan detected from {src_ip}")
                
                elif UDP in packet:
                    self.protocol_stats.udp += 1
                
                elif ICMP in packet:
                    self.protocol_stats.icmp += 1
            
            # ARP 패킷
            elif ARP in packet:
                self.protocol_stats.arp += 1
            
            # 고유 IP 수 계산 (활성 연결)
            self.connection_count = len(self.ip_counter)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _add_threat(self, threat_type: str, ip: str, severity: str):
        """위협 로그 추가"""
        current_time = datetime.now().strftime("%H:%M:%S")
        
        # 중복 방지: 최근 5개에 동일 IP+타입 있으면 무시
        if not any(t.ip == ip and t.type == threat_type for t in self.threats[-5:]):
            threat = ThreatInfo(
                type=threat_type,
                ip=ip,
                time=current_time,
                severity=severity
            )
            self.threats.append(threat)
            
            # 최근 20개만 유지
            if len(self.threats) > 20:
                self.threats = self.threats[-20:]

    def get_stats(self) -> dict:
        """현재 통계 반환"""
        # 평균 대역폭
        avg_bandwidth = sum(self.bandwidth_data) / len(self.bandwidth_data) if self.bandwidth_data else 0.0
        
        # 최대 대역폭
        peak_bandwidth = max(self.bandwidth_data) if self.bandwidth_data else 0.0
        
        # 활성 위협 (심각도 "높음"만)
        active_threats = sum(1 for t in self.threats if t.severity == "높음")
        
        # 패킷 증가율 계산
        packet_change = self.packet_count - self.prev_packet_count
        packet_change_rate = (packet_change / self.prev_packet_count * 100) if self.prev_packet_count > 0 else 0
        self.prev_packet_count = self.packet_count
        
        # 위협 변화량
        current_threat_count = len(self.threats)
        threat_change = current_threat_count - self.prev_threat_count
        self.prev_threat_count = current_threat_count
        
        return {
            "total_packets": self.packet_count,
            "avg_bandwidth": round(avg_bandwidth, 2),
            "peak_bandwidth": round(peak_bandwidth, 2),
            "active_threats": active_threats,
            "active_connections": self.connection_count,
            "protocol_stats": {
                "tcp": self.protocol_stats.tcp,
                "udp": self.protocol_stats.udp,
                "icmp": self.protocol_stats.icmp,
                "arp": self.protocol_stats.arp,
                "ddos": self.protocol_stats.ddos
            },
            "threats": [
                {
                    "type": t.type,
                    "ip": t.ip,
                    "time": t.time,
                    "severity": t.severity
                }
                for t in self.threats[-10:]  # 최근 10개만 반환
            ],
            "packet_change_rate": round(packet_change_rate, 2),
            "threat_change": threat_change
        }

    def stop_sniffing(self):
        """패킷 캡처 중지"""
        logger.info("Stopping packet sniffer...")
        self.is_running = False

    def reset_stats(self):
        """통계 초기화"""
        self.packet_count = 0
        self.protocol_stats = ProtocolStats()
        self.bandwidth_data = []
        self.ip_counter.clear()
        self.port_scan_detector.clear()
        self.threats = []
        self.connection_count = 0
        logger.info("Statistics reset")