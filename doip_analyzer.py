from pathlib import Path
import streamlit as st
import pandas as pd
from io import StringIO

st.set_page_config(layout="wide", page_title="Automotive Diagnostic Communication Analyzer")
st.title("Automotive Diagnostic Communication Analyzer")

# Define protocol layer colors (add this near the top of your file)
PROTOCOL_COLORS = {
    "ethernet": "#FF9966",  # Orange
    "ipv4": "#66B2FF",      # Blue
    "ipv6": "#66CCFF",      # Light Blue
    "tcp": "#99CC66",       # Green
    "doip": "#FF66B2",      # Pink
    "uds": "#CC99FF"        # Purple
}


def create_colored_hex_view(data, eth_type=None, ip_protocol=None, tcp_payload_start=None, doip_payload_start=None):
    # Calculate boundaries
    ethernet_end = 28  # 14 bytes * 2 hex chars per byte
    
    # Create HTML with spans for different colors
    html = "<pre style='font-family: monospace; white-space: pre-wrap; font-size: 14px; background-color: transparent;'>"
    
    # Always process Ethernet header with proper styling
    html += f"<span style='background-color: {PROTOCOL_COLORS['ethernet']}; color: white; padding: 2px; margin: 1px;'>"
    for i in range(0, min(ethernet_end, len(data)), 2):
        html += data[i:i+2] + " "
    html += "</span> "
    
    # Process IP/ARP header
    if eth_type == '0800':  # IPv4
        # For IPv4, header length is in the second byte of header
        try:
            ip_header_len = int(data[ethernet_end + 1], 16) * 8  # IHL value * 8 hex chars
        except:
            ip_header_len = 40  # Default to minimum IPv4 header length
            
        ip_end = ethernet_end + ip_header_len
        
        # Color IPv4 header properly
        html += f"<span style='background-color: {PROTOCOL_COLORS['ipv4']}; color: white; padding: 2px; margin: 1px;'>"
        for i in range(ethernet_end, min(ip_end, len(data)), 2):
            html += data[i:i+2] + " "
        html += "</span> "
        
        # Process TCP or UDP header if present
        if len(data) > ip_end:
            # Extract protocol number from IPv4 header
            try:
                protocol_num = int(data[ethernet_end + 18:ethernet_end + 20], 16)
            except:
                protocol_num = 0

            if protocol_num == 6:  # TCP
                # TCP 헤더 길이 계산 수정
                tcp_header_len = 20  # 기본값은 20바이트
                
                if len(data) >= ip_end + 24:
                    try:
                        # 수정: 데이터 오프셋은 TCP 헤더의 12번째 바이트 위치 (상위 4비트)
                        offset_byte = int(data[ip_end + 24:ip_end + 26], 16)
                        data_offset = (offset_byte >> 4)
                        tcp_header_len = data_offset * 4  # 32비트 워드 단위 -> 바이트
                        tcp_header_len_hex = tcp_header_len * 2  # 바이트 -> 16진수 문자 개수
                    except:
                        tcp_header_len_hex = 40  # 기본값 20바이트 = 40 hex chars
                else:
                    tcp_header_len_hex = 40
                
                # TCP 헤더 컬러링
                html += f"<span style='background-color: {PROTOCOL_COLORS['tcp']}; color: white; padding: 2px; margin: 1px;'>"
                for i in range(ip_end, min(ip_end + tcp_header_len_hex, len(data)), 2):
                    html += data[i:i+2] + " "
                html += "</span> "
                
                # TCP 페이로드 컬러링 부분 수정
                if len(data) > ip_end + tcp_header_len_hex:
                    # DoIP detection
                    doip_detected = False
                    try:
                        tcp_payload_start = ip_end + tcp_header_len_hex
                        src_port = int(data[ip_end:ip_end+4], 16)
                        dst_port = int(data[ip_end+4:ip_end+8], 16)
                        
                        # 더 정확한 TCP 플래그 확인 방법
                        flags_byte = int(data[ip_end + 26:ip_end + 28], 16)
                        has_syn = (flags_byte & 0x02) != 0
                        has_fin = (flags_byte & 0x01) != 0
                        has_rst = (flags_byte & 0x04) != 0
                        has_psh = (flags_byte & 0x08) != 0
                        has_ack = (flags_byte & 0x10) != 0

                        # 제어 패킷: SYN, FIN, RST가 있거나 ACK만 있고 PSH가 없는 경우
                        is_control_packet = has_syn or has_fin or has_rst or (has_ack and not has_psh)
                        
                        # 제어 패킷인 경우 페이로드를 회색으로 표시
                        if is_control_packet:
                            html += f"<span style='background-color: #DDDDDD; color: black; padding: 2px; margin: 1px;'>"
                            for i in range(tcp_payload_start, len(data), 2):
                                html += data[i:i+2] + " "
                            html += "</span> "
                            return html
                            
                        if (src_port == 13400 or dst_port == 13400) and len(data) > tcp_payload_start + 16:
                            # 기존 DoIP 처리 코드
                            # DoIP detection logic
                            protocol_version = int(data[tcp_payload_start:tcp_payload_start+2], 16)
                            inverse_version = int(data[tcp_payload_start+2:tcp_payload_start+4], 16)
                            
                            if protocol_version + inverse_version == 0xFF:
                                doip_detected = True
                                # DoIP header
                                doip_header_len = 16
                                html += f"<span style='background-color: {PROTOCOL_COLORS['doip']}; color: white; padding: 2px; margin: 1px;'>"
                                for i in range(tcp_payload_start, min(tcp_payload_start + doip_header_len, len(data)), 2):
                                    html += data[i:i+2] + " "
                                html += "</span> "
                                
                                # UDS payload
                                if len(data) > tcp_payload_start + doip_header_len:
                                    html += f"<span style='background-color: {PROTOCOL_COLORS['uds']}; color: white; padding: 2px; margin: 1px;'>"
                                    for i in range(tcp_payload_start + doip_header_len, len(data), 2):
                                        html += data[i:i+2] + " "
                                    html += "</span> "
                    except:
                        pass
                    
                    # If no DoIP detected, just color as UDS payload
                    if not doip_detected:
                        html += f"<span style='background-color: {PROTOCOL_COLORS['uds']}; color: white; padding: 2px; margin: 1px;'>"
                        for i in range(ip_end + tcp_header_len_hex, len(data), 2):
                            html += data[i:i+2] + " "
                        html += "</span> "


            elif protocol_num == 17:  # UDP
                # UDP header is 8 bytes (16 hex chars)
                udp_header_len = 16
                html += f"<span style='background-color: {PROTOCOL_COLORS['tcp']}; color: white; padding: 2px; margin: 1px;'>"
                for i in range(ip_end, min(ip_end + udp_header_len, len(data)), 2):
                    html += data[i:i+2] + " "
                html += "</span> "


                # UDP payload - check for DoIP
                doip_detected = False
                if len(data) > ip_end + udp_header_len:
                    try:
                        src_port = int(data[ip_end:ip_end+4], 16)
                        dst_port = int(data[ip_end+4:ip_end+8], 16)
                        
                        if src_port == 13400 or dst_port == 13400:
                            udp_payload_start = ip_end + udp_header_len
                            # Check for valid DoIP header
                            if len(data) > udp_payload_start + 16:
                                protocol_version = int(data[udp_payload_start:udp_payload_start+2], 16)
                                inverse_version = int(data[udp_payload_start+2:udp_payload_start+4], 16)
                                payload_type = int(data[udp_payload_start+4:udp_payload_start+8], 16)
                                
                                if protocol_version + inverse_version == 0xFF:
                                    doip_detected = True
                                    # DoIP header
                                    doip_header_len = 16
                                    html += f"<span style='background-color: {PROTOCOL_COLORS['doip']}; color: white; padding: 2px; margin: 1px;'>"
                                    for i in range(udp_payload_start, min(udp_payload_start + doip_header_len, len(data)), 2):
                                        html += data[i:i+2] + " "
                                    html += "</span> "
                                    
                                    # 페이로드 컬러링 - Vehicle Identification Request는 회색으로 표시
                                    if payload_type in [0x0001, 0x0002, 0x0003, 0x0007]:
                                        html += f"<span style='background-color: #DDDDDD; color: black; padding: 2px; margin: 1px;'>"
                                        for i in range(udp_payload_start + doip_header_len, len(data), 2):
                                            html += data[i:i+2] + " "
                                        html += "</span> "
                                    else:
                                        # UDS payload
                                        if len(data) > udp_payload_start + doip_header_len:
                                            html += f"<span style='background-color: {PROTOCOL_COLORS['uds']}; color: white; padding: 2px; margin: 1px;'>"
                                            for i in range(udp_payload_start + doip_header_len, len(data), 2):
                                                html += data[i:i+2] + " "
                                            html += "</span> "
                    except:
                        pass


                
                # If no DoIP detected, color as generic payload
                if not doip_detected and len(data) > ip_end + udp_header_len:
                    html += f"<span style='background-color: #DDDDDD; color: black; padding: 2px; margin: 1px;'>"
                    for i in range(ip_end + udp_header_len, len(data), 2):
                        html += data[i:i+2] + " "
                    html += "</span> "
                    
            else:
                # Other protocols - color the rest generically
                html += f"<span style='background-color: #DDDDDD; color: black; padding: 2px; margin: 1px;'>"
                for i in range(ip_end, len(data), 2):
                    html += data[i:i+2] + " "
                html += "</span> "
    
    elif eth_type == '86DD':  # IPv6
        ipv6_header_len = 80  # 40 bytes * 2 hex chars
        ipv6_end = ethernet_end + ipv6_header_len
        
        # Color IPv6 header
        html += f"<span style='background-color: {PROTOCOL_COLORS['ipv6']}; color: white; padding: 2px; margin: 1px;'>"
        for i in range(ethernet_end, min(ipv6_end, len(data)), 2):
            html += data[i:i+2] + " "
        html += "</span> "
        
        # Process next layer if present
        if len(data) > ipv6_end:
            # Extract next header type
            try:
                next_header = int(data[ethernet_end + 12:ethernet_end + 14], 16)
            except:
                next_header = 0
                
            if next_header == 6:  # TCP
                # TCP header (20+ bytes)
                tcp_header_len = 40  # Default to 20 bytes
                
                # Color TCP header
                html += f"<span style='background-color: {PROTOCOL_COLORS['tcp']}; color: white; padding: 2px; margin: 1px;'>"
                for i in range(ipv6_end, min(ipv6_end + tcp_header_len, len(data)), 2):
                    html += data[i:i+2] + " "
                html += "</span> "
                
                # Check for DoIP in payload
                doip_detected = False
                tcp_payload_start = ipv6_end + tcp_header_len
                if len(data) > tcp_payload_start:
                    try:
                        # Extract ports from TCP header
                        src_port = int(data[ipv6_end:ipv6_end+4], 16)
                        dst_port = int(data[ipv6_end+4:ipv6_end+8], 16)
                        
                        if (src_port == 13400 or dst_port == 13400) and len(data) > tcp_payload_start + 16:
                            protocol_version = int(data[tcp_payload_start:tcp_payload_start+2], 16)
                            inverse_version = int(data[tcp_payload_start+2:tcp_payload_start+4], 16)
                            
                            if protocol_version + inverse_version == 0xFF:
                                doip_detected = True
                                # DoIP header
                                doip_header_len = 16
                                html += f"<span style='background-color: {PROTOCOL_COLORS['doip']}; color: white; padding: 2px; margin: 1px;'>"
                                for i in range(tcp_payload_start, min(tcp_payload_start + doip_header_len, len(data)), 2):
                                    html += data[i:i+2] + " "
                                html += "</span> "
                                
                                # UDS payload
                                if len(data) > tcp_payload_start + doip_header_len:
                                    html += f"<span style='background-color: {PROTOCOL_COLORS['uds']}; color: white; padding: 2px; margin: 1px;'>"
                                    for i in range(tcp_payload_start + doip_header_len, len(data), 2):
                                        html += data[i:i+2] + " "
                                    html += "</span> "
                    except:
                        pass
                
                # If no DoIP detected, color as generic payload
                if not doip_detected and len(data) > tcp_payload_start:
                    html += f"<span style='background-color: #DDDDDD; color: black; padding: 2px; margin: 1px;'>"
                    for i in range(tcp_payload_start, len(data), 2):
                        html += data[i:i+2] + " "
                    html += "</span> "
                
            elif next_header == 17:  # UDP
                # UDP header (8 bytes = 16 hex chars)
                udp_header_len = 16
                udp_end = ipv6_end + udp_header_len
                
                # Color UDP header
                html += f"<span style='background-color: {PROTOCOL_COLORS['tcp']}; color: white; padding: 2px; margin: 1px;'>"
                for i in range(ipv6_end, min(udp_end, len(data)), 2):
                    html += data[i:i+2] + " "
                html += "</span> "
                
                # Check for DoIP in payload
                doip_detected = False
                if len(data) > udp_end:
                    try:
                        src_port = int(data[ipv6_end:ipv6_end+4], 16)
                        dst_port = int(data[ipv6_end+4:ipv6_end+8], 16)
                        
                        if src_port == 13400 or dst_port == 13400:
                            # Check for valid DoIP header
                            if len(data) > udp_end + 16:
                                protocol_version = int(data[udp_end:udp_end+2], 16)
                                inverse_version = int(data[udp_end+2:udp_end+4], 16)
                                
                                if protocol_version + inverse_version == 0xFF:
                                    doip_detected = True
                                    # DoIP header
                                    doip_header_len = 16
                                    html += f"<span style='background-color: {PROTOCOL_COLORS['doip']}; color: white; padding: 2px; margin: 1px;'>"
                                    for i in range(udp_end, min(udp_end + doip_header_len, len(data)), 2):
                                        html += data[i:i+2] + " "
                                    html += "</span> "
                                    
                                    # UDS payload
                                    if len(data) > udp_end + doip_header_len:
                                        html += f"<span style='background-color: {PROTOCOL_COLORS['uds']}; color: white; padding: 2px; margin: 1px;'>"
                                        for i in range(udp_end + doip_header_len, len(data), 2):
                                            html += data[i:i+2] + " "
                                        html += "</span> "
                    except:
                        pass
                
                # If no DoIP detected, color as generic payload
                if not doip_detected and len(data) > udp_end:
                    html += f"<span style='background-color: #DDDDDD; color: black; padding: 2px; margin: 1px;'>"
                    for i in range(udp_end, len(data), 2):
                        html += data[i:i+2] + " "
                    html += "</span> "
            else:
                # Other next headers
                html += f"<span style='background-color: #DDDDDD; color: black; padding: 2px; margin: 1px;'>"
                for i in range(ipv6_end, len(data), 2):
                    html += data[i:i+2] + " "
                html += "</span> "
    
    elif eth_type == '0806':  # ARP
        # ARP is typically 28 bytes (56 hex chars)
        arp_end = ethernet_end + 56
        
        html += f"<span style='background-color: {PROTOCOL_COLORS['ipv4']}; color: white; padding: 2px; margin: 1px;'>"
        for i in range(ethernet_end, min(arp_end, len(data)), 2):
            html += data[i:i+2] + " "
        html += "</span> "
        
        # Any trailing data after ARP
        if len(data) > arp_end:
            html += f"<span style='background-color: #DDDDDD; color: black; padding: 2px; margin: 1px;'>"
            for i in range(arp_end, len(data), 2):
                html += data[i:i+2] + " "
            html += "</span> "
            
    else:  # Unknown EtherType
        html += f"<span style='background-color: #DDDDDD; color: black; padding: 2px; margin: 1px;'>"
        for i in range(ethernet_end, len(data), 2):
            html += data[i:i+2] + " "
        html += "</span> "
    
    html += "</pre>"
    return html

def create_protocol_columns():
    """Create and return the UI columns with proper styling"""
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown(f"<h3 style='background-color: {PROTOCOL_COLORS['ethernet']}; padding: 10px;'>Ethernet</h3>", unsafe_allow_html=True)
        eth_placeholder = st.empty()
    
    with col2:
        # Create a placeholder for the IP header that will be set dynamically
        ip_header_placeholder = st.empty()
        ip_content_placeholder = st.empty()  
    
    with col3:
        st.markdown(f"<h3 style='background-color: {PROTOCOL_COLORS['tcp']}; padding: 10px;'>TCP/UDP</h3>", unsafe_allow_html=True)
        tcp_placeholder = st.empty()
    
    with col4:
        # 여기서 UDS에서 DoIP로 이름 변경
        st.markdown(f"<h3 style='background-color: {PROTOCOL_COLORS['doip']}; padding: 10px;'>DoIP</h3>", unsafe_allow_html=True)
        doip_placeholder = st.empty()  # uds_placeholder를 doip_placeholder로 이름 변경해도 됨
    
    with col5:
        # 여기서 Service에서 UDS로 이름 변경
        st.markdown(f"<h3 style='background-color: {PROTOCOL_COLORS['uds']}; padding: 10px;'>UDS</h3>", unsafe_allow_html=True)
        uds_placeholder = st.empty() 
    
    # 반환 값은 변경 전과 동일하게 유지하여 기존 코드와의 호환성 보존
    return col1, col2, col3, col4, col5, ip_header_placeholder, ip_content_placeholder, tcp_placeholder, doip_placeholder, uds_placeholder


def create_colored_hex_visualization(data, ethernet_packet):
    """Create the colored hex visualization based on packet type"""
    if not ethernet_packet:
        return f"<pre>{data}</pre>"
    
    eth_type = ethernet_packet["ethernet"]["eth_type"]
    
    # 항상 create_colored_hex_view 함수 사용
    ip_protocol = None
    tcp_payload_start = None
    doip_payload_start = None
    
    # Detect packet types and boundaries
    if eth_type == '0800':  # IPv4
        ip_protocol, tcp_payload_start, doip_payload_start = detect_ipv4_protocol_layers(ethernet_packet)
    elif eth_type == '86DD':  # IPv6
        ip_protocol, tcp_payload_start, doip_payload_start = detect_ipv6_protocol_layers(ethernet_packet)
    
    # Generate the colored hex view
    return create_colored_hex_view(data, eth_type, ip_protocol, tcp_payload_start, doip_payload_start)


def fixed_ipv6_coloring(data):
    """Special function to properly color IPv6 packets"""
    ethernet_end = 28  # Ethernet header size in hex chars
    ipv6_header_len = 80  # IPv6 header size in hex chars
    ipv6_end = ethernet_end + ipv6_header_len
    
    html = "<pre style='font-family: monospace; white-space: pre-wrap; font-size: 14px; background-color: transparent;'>"
    
    # Color the Ethernet header
    html += f"<span style='background-color: {PROTOCOL_COLORS['ethernet']}; color: white; padding: 2px; margin: 1px;'>"
    for i in range(0, min(ethernet_end, len(data)), 2):
        html += data[i:i+2] + " "
    html += "</span> "
    
    if len(data) > ethernet_end:
        # Color the IPv6 header
        html += f"<span style='background-color: {PROTOCOL_COLORS['ipv6']}; color: white; padding: 2px; margin: 1px;'>"
        for i in range(ethernet_end, min(ipv6_end, len(data)), 2):
            html += data[i:i+2] + " "
        html += "</span> "
        
        if len(data) > ipv6_end:
            # Get the Next Header field (IPv6)
            next_header = int(data[ethernet_end + 12:ethernet_end + 14], 16)
            
            if next_header == 17:  # UDP
                # UDP header (8 bytes = 16 hex chars)
                udp_header_len = 16
                udp_end = ipv6_end + udp_header_len
                
                # Color UDP header
                html += f"<span style='background-color: {PROTOCOL_COLORS['tcp']}; color: white; padding: 2px; margin: 1px;'>"
                for i in range(ipv6_end, min(udp_end, len(data)), 2):
                    html += data[i:i+2] + " "
                html += "</span> "
                
                # Color UDP payload
                if len(data) > udp_end:
                    html += f"<span style='background-color: {PROTOCOL_COLORS['uds']}; color: white; padding: 2px; margin: 1px;'>"
                    for i in range(udp_end, len(data), 2):
                        html += data[i:i+2] + " "
                    html += "</span>"
            elif next_header == 6:  # TCP
                # TCP header (20 bytes = 40 hex chars, but can vary)
                tcp_header_len = 40  # Approximate
                tcp_end = ipv6_end + tcp_header_len
                
                # Color TCP header
                html += f"<span style='background-color: {PROTOCOL_COLORS['tcp']}; color: white; padding: 2px; margin: 1px;'>"
                for i in range(ipv6_end, min(tcp_end, len(data)), 2):
                    html += data[i:i+2] + " "
                html += "</span> "
                
                # Color TCP payload
                if len(data) > tcp_end:
                    html += f"<span style='background-color: {PROTOCOL_COLORS['uds']}; color: white; padding: 2px; margin: 1px;'>"
                    for i in range(tcp_end, len(data), 2):
                        html += data[i:i+2] + " "
                    html += "</span>"
            else:
                # Other protocols
                html += f"<span style='background-color: {PROTOCOL_COLORS['tcp']}; color: white; padding: 2px; margin: 1px;'>"
                for i in range(ipv6_end, len(data), 2):
                    html += data[i:i+2] + " "
                html += "</span>"
    
    html += "</pre>"
    return html


def detect_ipv4_protocol_layers(ethernet_packet):
    """Helper function to detect protocols in an IPv4 packet for visualization"""
    ip_protocol = None
    tcp_payload_start = None
    doip_payload_start = None
    
    ip_packet = parse_ip_packet(ethernet_packet["payload"])
    if ip_packet:
        ip_info = ip_packet["ip"]
        ip_protocol = ip_info["protocol"]
        
        # Calculate IP header length in hex chars
        ip_header_len = ip_info['ihl'] * 4 * 2
        
        # TCP payload starts after the ethernet header (14 bytes = 28 hex chars) + IP header length
        tcp_payload_start = 28 + ip_header_len
        
        if "TCP" in ip_protocol:
            tcp_packet = parse_tcp_packet(ip_packet["payload"])
            if tcp_packet:
                # Get TCP header length
                tcp_header_len = tcp_packet["tcp"]["data_offset"] * 4 * 2
                
                # DoIP payload starts after TCP header
                if tcp_packet["tcp"]['src_port'] == 13400 or tcp_packet["tcp"]['dest_port'] == 13400:
                    # Check if payload is a valid DoIP message
                    payload = tcp_packet["payload"]
                    if len(payload) >= 16:
                        try:
                            protocol_version = int(payload[0:2], 16)
                            inverse_protocol_version = int(payload[2:4], 16)
                            
                            # Basic validation - protocol version + inverse should be 0xFF
                            if protocol_version + inverse_protocol_version == 0xFF:
                                # DoIP payload starts after TCP header
                                doip_payload_start = tcp_payload_start + tcp_header_len
                        except:
                            pass
        elif "UDP" in ip_protocol:
            # UDP header is fixed at 8 bytes (16 hex chars)
            udp_header_len = 16
            doip_start = tcp_payload_start + udp_header_len
            
            # Check for DoIP in UDP
            if len(ip_packet["payload"]) >= 16:
                try:
                    src_port = int(ip_packet["payload"][0:4], 16)
                    dst_port = int(ip_packet["payload"][4:8], 16)
                    
                    if src_port == 13400 or dst_port == 13400:
                        udp_payload = ip_packet["payload"][16:]
                        if len(udp_payload) >= 16:
                            protocol_version = int(udp_payload[0:2], 16)
                            inverse_version = int(udp_payload[2:4], 16)
                            
                            if protocol_version + inverse_version == 0xFF:
                                doip_payload_start = doip_start
                except:
                    pass
    
    return ip_protocol, tcp_payload_start, doip_payload_start


def detect_ipv6_protocol_layers(ethernet_packet):
    """Helper function to detect protocols in an IPv6 packet for visualization"""
    ip_protocol = None
    tcp_payload_start = None
    doip_payload_start = None
    
    ipv6_packet = parse_ipv6_packet(ethernet_packet["payload"])
    if ipv6_packet:
        ipv6_info = ipv6_packet["ipv6"]
        ip_protocol = ipv6_info["next_header"]
        
        # IPv6 header is fixed 40 bytes (80 hex chars)
        ipv6_header_len = 80
        tcp_payload_start = 28 + ipv6_header_len  # Ethernet (28) + IPv6 header (80)
        
        if "TCP" in ip_protocol:
            tcp_packet = parse_tcp_packet(ipv6_packet["payload"])
            if tcp_packet:
                tcp_header_len = tcp_packet["tcp"]["data_offset"] * 4 * 2
                
                if tcp_packet["tcp"]['src_port'] == 13400 or tcp_packet["tcp"]['dest_port'] == 13400:
                    # Check if payload is a valid DoIP message
                    payload = tcp_packet["payload"]
                    if len(payload) >= 16:
                        try:
                            protocol_version = int(payload[0:2], 16)
                            inverse_protocol_version = int(payload[2:4], 16)
                            
                            # Basic validation - protocol version + inverse should be 0xFF
                            if protocol_version + inverse_protocol_version == 0xFF:
                                doip_payload_start = tcp_payload_start + tcp_header_len
                        except:
                            pass
        elif "UDP" in ip_protocol:
            # UDP header is fixed 8 bytes (16 hex chars)
            udp_header_len = 16
            doip_start = tcp_payload_start + udp_header_len
            
            # Check for DoIP in UDP
            if len(ipv6_packet["payload"]) >= 16:
                try:
                    src_port = int(ipv6_packet["payload"][0:4], 16)
                    dst_port = int(ipv6_packet["payload"][4:8], 16)
                    
                    if src_port == 13400 or dst_port == 13400:
                        udp_payload = ipv6_packet["payload"][16:]
                        if len(udp_payload) >= 16:
                            protocol_version = int(udp_payload[0:2], 16)
                            inverse_version = int(udp_payload[2:4], 16)
                            
                            if protocol_version + inverse_version == 0xFF:
                                doip_payload_start = doip_start
                except:
                    pass
    
    return ip_protocol, tcp_payload_start, doip_payload_start


def analyze_packet(data, col1, col2, col3, col4, col5, ip_header_placeholder, ip_content_placeholder, tcp_placeholder, doip_placeholder, uds_placeholder):
    """Main packet analysis logic"""
    # Get placeholder for Ethernet column
    eth_placeholder = col1.empty()
    
    # Parse Ethernet layer
    ethernet_packet = parse_ethernet_packet(data)
    if not ethernet_packet:
        eth_placeholder.text("Could not parse Ethernet packet")
        return
    
    # Display Ethernet information
    eth_type = display_ethernet_info(ethernet_packet, eth_placeholder)
    
    # Process according to EtherType
    if eth_type == '0800':  # IPv4
        # Set IPv4 header
        ip_header_placeholder.markdown(f"<h3 style='background-color: {PROTOCOL_COLORS['ipv4']}; padding: 10px;'>IPv4</h3>", unsafe_allow_html=True)
        process_ipv4_packet(ethernet_packet, ip_content_placeholder, tcp_placeholder, doip_placeholder, uds_placeholder)
    elif eth_type == '86DD':  # IPv6
        # Set IPv6 header
        ip_header_placeholder.markdown(f"<h3 style='background-color: {PROTOCOL_COLORS['ipv6']}; padding: 10px;'>IPv6</h3>", unsafe_allow_html=True)
        process_ipv6_packet(ethernet_packet, ip_content_placeholder, tcp_placeholder, doip_placeholder, uds_placeholder)
    elif eth_type == '0806':  # ARP
        # Set ARP header
        ip_header_placeholder.markdown(f"<h3 style='background-color: {PROTOCOL_COLORS['ipv4']}; padding: 10px;'>ARP</h3>", unsafe_allow_html=True)
        process_arp_packet(ethernet_packet, ip_content_placeholder, tcp_placeholder, doip_placeholder, uds_placeholder, col2)
    else:
        ip_content_placeholder.text(f"Unknown EtherType: 0x{eth_type}")


def process_ipv4_packet(ethernet_packet, ip_placeholder, tcp_placeholder, doip_placeholder, uds_placeholder):
    """Process an IPv4 packet and display protocol information"""
    ip_packet = parse_ip_packet(ethernet_packet["payload"])
    if not ip_packet:
        ip_placeholder.text("Could not parse IPv4 packet")
        return
    
    # Display IPv4 information
    ip_info = display_ipv4_info(ip_packet, ethernet_packet, ip_placeholder)
    
    # Process TCP if present
    if "TCP" in ip_info['protocol']:
        process_tcp_packet(ip_packet["payload"], ip_packet, tcp_placeholder, doip_placeholder, uds_placeholder)
    elif "UDP" in ip_info['protocol']:
        udp_payload = ip_packet["payload"]
        # Parse UDP header
        if len(udp_payload) >= 8:  # UDP header is 8 bytes
            src_port = int(udp_payload[0:4], 16)
            dest_port = int(udp_payload[4:8], 16)
            
            # Display UDP info
            process_udp_packet(udp_payload, tcp_placeholder, doip_placeholder, uds_placeholder)
            
            # Check if this is DoIP (UDP port 13400)
            if src_port == 13400 or dest_port == 13400:
                # UDP payload starts after header (8 bytes = 16 hex chars)
                doip_payload = udp_payload[16:]
                if len(doip_payload) > 0:
                    # 여기를 수정: process_doip_packet 함수 사용
                    process_doip_packet(doip_payload, doip_placeholder, uds_placeholder)


def process_ipv6_packet(ethernet_packet, ip_placeholder, tcp_placeholder, doip_placeholder, uds_placeholder):
    """Process an IPv6 packet and display protocol information"""
    ipv6_packet = parse_ipv6_packet(ethernet_packet["payload"])
    if not ipv6_packet:
        ip_placeholder.text("Could not parse IPv6 packet")
        return
    
    # Display IPv6 information
    ipv6_info = display_ipv6_info(ipv6_packet, ethernet_packet, ip_placeholder)
    
    # Process TCP or UDP if present
    if "TCP" in ipv6_info['next_header']:
        process_tcp_packet(ipv6_packet["payload"], ipv6_packet, tcp_placeholder, doip_placeholder, uds_placeholder)
    elif "UDP" in ipv6_info['next_header']:
        # 여기도 process_udp_packet 후 process_doip_packet을 사용하도록 수정 필요
        process_udp_packet(ipv6_packet["payload"], tcp_placeholder, doip_placeholder, uds_placeholder)
        
        # 추가: DoIP 체크 및 process_doip_packet 호출
        if len(ipv6_packet["payload"]) >= 8:
            src_port = int(ipv6_packet["payload"][0:4], 16)
            dest_port = int(ipv6_packet["payload"][4:8], 16)
            
            if src_port == 13400 or dest_port == 13400:
                doip_payload = ipv6_packet["payload"][16:]
                if len(doip_payload) > 0:
                    process_doip_packet(doip_payload, doip_placeholder, uds_placeholder)


def process_doip_packet(payload, doip_placeholder, uds_placeholder):
    """Process a DoIP packet and display protocol information"""
    doip_info = detect_doip(payload)
    
    # 페이로드 타입 확인
    payload_type = None
    try:
        payload_type_str = doip_info["doip"]["payload_type"]
        if "0x0001" in payload_type_str:
            payload_type = 0x0001  # Vehicle Identification Request
        elif "0x0004" in payload_type_str:
            payload_type = 0x0004  # Vehicle Announcement Response
        elif "0x0006" in payload_type_str:
            payload_type = 0x0006  # Routing Activation Response
        elif "0x8001" in payload_type_str:
            payload_type = 0x8001  # Diagnostic Message
        elif "0x8002" in payload_type_str:
            payload_type = 0x8002  # Diagnostic Message ACK
        elif "0x8003" in payload_type_str:
            payload_type = 0x8003  # Diagnostic Message Negative ACK
    except:
        pass
    
    # Vehicle Announcement Response는 Service 컬럼에만 표시
    if payload_type == 0x0001:
        # DoIP 헤더 및 페이로드 정보
        doip_text = f"""Vehicle Identification Request:

Protocol Version: {doip_info['doip']['protocol_version']}
Payload Type: {doip_info['doip']['payload_type']}
Payload: {payload[16:]}
"""
        doip_placeholder.text(doip_text)
        
        # UDS 컬럼은 비워두기
        uds_placeholder.text("No UDS data in Vehicle Identification Request")

    elif payload_type == 0x0004:
        # DoIP 헤더 및 페이로드 정보를 DoIP 컬럼에 표시
        doip_text = f"""Vehicle Announcement Response:

Protocol Version: {doip_info['doip']['protocol_version']}
Inverse Protocol Version: {doip_info['doip']['inverse_protocol_version']}
Payload Type: {doip_info['doip']['payload_type']}
Payload Length: {doip_info['doip']['payload_length']} bytes
DoIP Header: {payload[:16]}
"""
        doip_placeholder.text(doip_text)
        
        # VIN과 관련 정보를 UDS 컬럼에 표시
        uds_text = f"""Vehicle Announcement Response Details:

VIN (hex): {doip_info['doip']['vin']}
VIN (decoded): {doip_info['doip']['decoded_vin']}
Logical Address: {doip_info['doip']['logical_address']}
EID: {doip_info['doip']['eid']}
GID: {doip_info['doip']['gid']}
"""
        uds_placeholder.text(uds_text)
    else:
        # 다른 타입의 DoIP 메시지는 기존 방식대로 처리
        doip_data = display_doip_info(doip_info, payload, doip_placeholder)
        
        # Check message type
        if "0x8001" in doip_data["payload_type"]:
            # Diagnostic Message - UDS 파싱을 하기 전에 Source/Target Address 정보 표시
            uds_header_text = f"""Diagnostic Message:
Source Address: {doip_data.get('source_address', 'Unknown')}
Target Address: {doip_data.get('target_address', 'Unknown')}

UDS Data:
"""
            # UDS 정보 파싱 및 표시
            uds_data = parse_uds_packet(doip_info["payload"])
            
            # UDS 데이터와 함께 Source/Target Address 정보를 UDS 컬럼에 표시
            uds_payload_formatted = ' '.join([doip_info["payload"][i:i+2] for i in range(0, min(30, len(doip_info["payload"])), 2)])
            if len(doip_info["payload"]) > 30:
                uds_payload_formatted += "..."
            
            uds_full_text = uds_header_text + f"""{uds_payload_formatted}

Service ID: {uds_data['uds']['service_id']}
Service Type: {uds_data['uds']['service_type']}
"""
            
            # Add details if available
            if 'details' in uds_data['uds'] and uds_data['uds']['details']:
                uds_full_text += "\nDetails:"
                for key, value in uds_data['uds']['details'].items():
                    uds_full_text += f"\n- {key}: {value}"
            
            uds_placeholder.text(uds_full_text)

        elif "0x8002" in doip_data["payload_type"]:  # ACK 메시지 처리 추가
            # Diagnostic Message ACK - UDS 컬럼에 Source/Target Address 정보 표시
            uds_text = f"""Diagnostic Message ACK:

Source Address: {doip_data.get('source_address', 'Unknown')}
Target Address: {doip_data.get('target_address', 'Unknown')}
"""
            if 'ack_code' in doip_data:
                uds_text += f"ACK Code: {doip_data['ack_code']}"
                
            uds_placeholder.text(uds_text)
            
        elif "0x8003" in doip_data["payload_type"]:  # NACK 메시지 처리 추가
            # Diagnostic Message NACK - UDS 컬럼에 Source/Target Address 정보 표시
            uds_text = f"""Diagnostic Message NACK:

Source Address: {doip_data.get('source_address', 'Unknown')}
Target Address: {doip_data.get('target_address', 'Unknown')}
"""
            if 'nack_code' in doip_data:
                uds_text += f"NACK Code: {doip_data['nack_code']}"
                
            uds_placeholder.text(uds_text)
            

        elif "0x0006" in doip_data["payload_type"]:
            # Routing Activation Response
            uds_text = f"""Routing Activation Response:

Target Address: {doip_data['target_address']}
Source Address: {doip_data['source_address']}
Response Code: {doip_data['routing_activation_response']}
Response Description: {doip_data['routing_response_description']}
"""
            if 'reserved' in doip_data:
                uds_text += f"Reserved: {doip_data['reserved']}"
                
            uds_placeholder.text(uds_text)
        else:
            # 기타 DoIP 메시지
            uds_placeholder.text("No UDS data in this DoIP message type")


def process_tcp_packet(payload, ip_packet, tcp_placeholder, doip_placeholder, uds_placeholder):
    """Process a TCP packet and display protocol information"""
    tcp_packet = parse_tcp_packet(payload)
    if not tcp_packet:
        tcp_placeholder.text("Could not parse TCP packet")
        return
    
    # Display TCP information
    tcp_info = display_tcp_info(tcp_packet, payload, tcp_placeholder)
    
    # Check for control packets (SYN, ACK, FIN, RST)
    is_control_packet = False
    flags = tcp_info['flag_names'].split(", ")
    if "SYN" in flags or "FIN" in flags or "RST" in flags or ("ACK" in flags and not "PSH" in flags):
        is_control_packet = True
        
        # 추가: TCP 제어 패킷의 페이로드가 있을 경우 TCP 컬럼에 표시
        if len(tcp_packet["payload"]) > 0:
            # 수정: 기존 text_area 대신 새로운 텍스트 구성
            tcp_payload_hex = ' '.join([tcp_packet["payload"][i:i+2] for i in range(0, min(30, len(tcp_packet["payload"])), 2)])
            if len(tcp_packet["payload"]) > 30:
                tcp_payload_hex += "..."
            
            # 전체 TCP 정보를 다시 구성
            tcp_header_len = tcp_info['data_offset'] * 8
            tcp_header_hex = payload[:tcp_header_len]
            tcp_header_formatted = ' '.join([tcp_header_hex[i:i+2] for i in range(0, len(tcp_header_hex), 2)])
            
            updated_tcp_text = f"""TCP Header:
{tcp_header_formatted}

Source Port: {tcp_info['src_port']}
Destination Port: {tcp_info['dest_port']}
Sequence Number: {tcp_info['seq_num']}
Acknowledgment Number: {tcp_info['ack_num']}
Data Offset: {tcp_info['data_offset']} (32-bit words)
Flags: {tcp_info['flag_names']}
Window Size: {tcp_info['window']}

TCP Payload Data:
{tcp_payload_hex}
"""
            tcp_placeholder.text(updated_tcp_text)
            
            # 다른 컬럼은 비워두기
            doip_placeholder.text("No DoIP data (TCP control packet)")
            uds_placeholder.text("No UDS data")
            return
    
    # Check for DoIP protocol (port 13400)
    if tcp_info['src_port'] == 13400 or tcp_info['dest_port'] == 13400:
        # Check if this is likely a TCP control packet (SYN, ACK, etc)
        is_control_packet = False
        flags = tcp_info['flag_names'].split(", ")
        if "SYN" in flags or "FIN" in flags or "RST" in flags:
            is_control_packet = True
            
        # Only try to parse DoIP if this isn't just a control packet
        if len(tcp_packet["payload"]) > 0 and not is_control_packet:
            process_doip_packet(tcp_packet["payload"], doip_placeholder, uds_placeholder)
        else:
            doip_placeholder.text("TCP connection to DoIP port (13400), but no DoIP data present yet")
            uds_placeholder.text("No UDS data available")
    else:
        # Try normal UDS parsing
        if len(tcp_packet["payload"]) > 0:
            process_uds_packet(tcp_packet["payload"], doip_placeholder, uds_placeholder)
        else:
            doip_placeholder.text("No payload data")
            uds_placeholder.text("No data to analyze")


def process_uds_packet(payload, placeholder, is_doip=False):
    """Process a UDS packet and display protocol information"""
    uds_data = parse_uds_packet(payload)
    display_uds_info(uds_data, payload, placeholder)


def process_udp_packet(payload, tcp_placeholder, doip_placeholder=None, uds_placeholder=None):
    """Process a UDP packet and display protocol information"""
    if len(payload) < 8:
        tcp_placeholder.text("Could not parse UDP packet")
        return
        
    try:
        src_port = int(payload[0:4], 16)
        dest_port = int(payload[4:8], 16)
        length = int(payload[8:12], 16)
        checksum = payload[12:16]
        
        udp_header_hex = payload[:16]
        udp_header_formatted = ' '.join([udp_header_hex[i:i+2] for i in range(0, len(udp_header_hex), 2)])
        
        udp_text = f"""UDP Header:
{udp_header_formatted}

Source Port: {src_port}
Destination Port: {dest_port}
Length: {length} bytes
Checksum: 0x{checksum}
"""
        tcp_placeholder.text(udp_text)
        
        # 추가: UDP 페이로드를 UDS 컬럼에 표시
        if doip_placeholder and len(payload) > 16:
            udp_payload = payload[16:]
            payload_formatted = ' '.join([udp_payload[i:i+2] for i in range(0, min(30, len(udp_payload)), 2)])
            if len(udp_payload) > 30:
                payload_formatted += "..."
                
            doip_text = f"""UDP Payload:
{payload_formatted}

Length: {len(udp_payload)//2} bytes
"""
            doip_placeholder.text(doip_text)
            
            # 필요한 경우 uds_placeholder에도 정보 표시
            if uds_placeholder:
                uds_placeholder.text("No diagnostic service information available for this UDP payload")
    except:
        tcp_placeholder.text("Error parsing UDP header")


def process_arp_packet(ethernet_packet, ip_placeholder, tcp_placeholder, doip_placeholder, uds_placeholder, col2):
    """Process an ARP packet and display protocol information"""
    arp_packet = parse_arp_packet(ethernet_packet["payload"])
    if not arp_packet:
        ip_placeholder.text("Could not parse ARP packet")
        return
    
    # Display ARP information
    display_arp_info(arp_packet, ethernet_packet, ip_placeholder)


def parse_arp_packet(payload):
    """Parse ARP packet and return structured information"""
    if not payload or len(payload) < 28:  # Minimum length for ARP (28 bytes = 56 hex chars)
        return None
    
    try:
        # Parse ARP header fields
        hardware_type = int(payload[0:4], 16)
        protocol_type = int(payload[4:8], 16)
        hardware_size = int(payload[8:10], 16)
        protocol_size = int(payload[10:12], 16)
        opcode = int(payload[12:16], 16)
        
        # ARP operation codes
        opcode_map = {
            1: "REQUEST",
            2: "REPLY",
            3: "RARP REQUEST",
            4: "RARP REPLY",
            5: "DRARP REQUEST",
            6: "DRARP REPLY",
            7: "DRARP ERROR",
            8: "InARP REQUEST",
            9: "InARP REPLY"
        }
        
        # Get addresses based on hardware/protocol sizes
        sender_mac_start = 16
        sender_mac_end = sender_mac_start + (hardware_size * 2)
        sender_mac = ':'.join([payload[i:i+2] for i in range(sender_mac_start, sender_mac_end, 2)])
        
        sender_ip_start = sender_mac_end
        sender_ip_end = sender_ip_start + (protocol_size * 2)
        sender_ip = '.'.join([str(int(payload[i:i+2], 16)) for i in range(sender_ip_start, sender_ip_end, 2)])
        
        target_mac_start = sender_ip_end
        target_mac_end = target_mac_start + (hardware_size * 2)
        target_mac = ':'.join([payload[i:i+2] for i in range(target_mac_start, target_mac_end, 2)])
        
        target_ip_start = target_mac_end
        target_ip_end = target_ip_start + (protocol_size * 2)
        target_ip = '.'.join([str(int(payload[i:i+2], 16)) for i in range(target_ip_start, target_ip_end, 2)])
        
        return {
            "arp": {
                "hardware_type": hardware_type,
                "protocol_type": f"0x{protocol_type:04X}",
                "hardware_size": hardware_size,
                "protocol_size": protocol_size,
                "opcode": opcode,
                "operation": opcode_map.get(opcode, "UNKNOWN"),
                "sender_mac": sender_mac,
                "sender_ip": sender_ip,
                "target_mac": target_mac,
                "target_ip": target_ip
            },
            "payload": ""  # ARP has no payload
        }
    except Exception as e:
        return None


def display_arp_info(arp_packet, ethernet_packet, ip_placeholder):
    """Display ARP header information in the UI"""
    arp_info = arp_packet["arp"]
    arp_header_hex = ethernet_packet["payload"][:56]  # Usually 28 bytes for ARP
    arp_header_formatted = ' '.join([arp_header_hex[i:i+2] for i in range(0, len(arp_header_hex), 2)])
    
    # Get protocol type name
    protocol_name = "Unknown"
    if arp_info['protocol_type'] == "0x0800":
        protocol_name = "IPv4"
    
    # Get hardware type name
    hardware_name = "Unknown"
    if arp_info['hardware_type'] == 1:
        hardware_name = "Ethernet"
    
    arp_text = f"""ARP Header:
{arp_header_formatted}

Hardware Type: {arp_info['hardware_type']} ({hardware_name})
Protocol Type: {arp_info['protocol_type']} ({protocol_name})
Hardware Size: {arp_info['hardware_size']} bytes
Protocol Size: {arp_info['protocol_size']} bytes
Operation: {arp_info['opcode']} ({arp_info['operation']})
Sender MAC: {arp_info['sender_mac']}
Sender IP: {arp_info['sender_ip']}
Target MAC: {arp_info['target_mac']}
Target IP: {arp_info['target_ip']}
"""
    ip_placeholder.text(arp_text)
    return arp_info

# Function to parse the packet data
def parse_ethernet_packet(data_str):
    '''
    이더넷 헤더의 구조에 대해 설명해 드리겠습니다.

    이더넷 헤더는 총 14바이트로 구성되며 다음과 같은 필드들을 포함합니다:

    1. **목적지 MAC 주소** (Destination MAC Address)
    - 길이: 6바이트 (48비트)
    - 설명: 이더넷 프레임을 수신할 장치의 물리적 주소입니다. 모든 장치는 이 필드를 확인하여 자신에게 온 프레임인지 판단합니다.

    2. **출발지 MAC 주소** (Source MAC Address)
    - 길이: 6바이트 (48비트)
    - 설명: 이더넷 프레임을 전송한 장치의 물리적 주소로, 수신 장치가 응답할 때 사용합니다.

    3. **타입/길이 필드** (Type/Length Field)
    - 길이: 2바이트 (16비트)
    - 설명: 두 가지 용도로 사용됩니다:
        - 값이 1500보다 크면 상위 계층 프로토콜의 타입을 식별합니다(예: 0x0800은 IPv4, 0x0806은 ARP).
        - 값이 1500 이하면 이더넷 프레임 데이터 부분의 길이를 바이트 단위로 나타냅니다.

    이 헤더 뒤에는 데이터 필드(페이로드)와 프레임 검사 순서(FCS) 필드가 이어집니다. 데이터 필드는 46~1500바이트 길이이며, FCS 필드는 4바이트로 프레임 무결성을 검사하는 CRC-32 체크섬을 포함합니다.
    '''

    # Check if data string is valid
    if not data_str or len(data_str) < 28:  # Minimum length for an Ethernet frame
        return None
    
    # Parse Ethernet header (first 14 bytes / 28 hex chars)
    eth_header = data_str[:28]
    try:
        dest_mac = ':'.join([eth_header[i:i+2] for i in range(0, 12, 2)])
        src_mac = ':'.join([eth_header[12:24][i:i+2] for i in range(0, 12, 2)])
        eth_type = eth_header[24:28]
    except:
        return None
    
    # Rest is payload
    payload = data_str[28:]
    
    return {
        "ethernet": {
            "dest_mac": dest_mac,
            "src_mac": src_mac,
            "eth_type": eth_type
        },
        "payload": payload
    }


def parse_ip_packet(payload):
    """Parse IPv4 packet header and return structured information"""
    if not payload or len(payload) < 40:  # Minimum length for an IPv4 header (20 bytes = 40 hex chars)
        return None
    
    try:
        version_ihl = int(payload[0:2], 16)
        version = version_ihl >> 4
        ihl = version_ihl & 0x0F
        
        tos = int(payload[2:4], 16)
        total_length = int(payload[4:8], 16)
        identification = payload[8:12]
        flags_frag_offset = payload[12:16]
        ttl = int(payload[16:18], 16)
        protocol_num = int(payload[18:20], 16)
        
        # Map protocol number to name
        protocol_name = "Unknown"
        if protocol_num == 1:
            protocol_name = "ICMP"
        elif protocol_num == 6:
            protocol_name = "TCP"
        elif protocol_num == 17:
            protocol_name = "UDP"
        
        header_checksum = payload[20:24]
        src_ip = f"{int(payload[24:26], 16)}.{int(payload[26:28], 16)}.{int(payload[28:30], 16)}.{int(payload[30:32], 16)}"
        dest_ip = f"{int(payload[32:34], 16)}.{int(payload[34:36], 16)}.{int(payload[36:38], 16)}.{int(payload[38:40], 16)}"
        
        # IP header size in bytes * 2 (for hex chars)
        ip_header_size = ihl * 4 * 2
        ip_payload = payload[ip_header_size:]
        
        return {
            "ip": {
                "version": version,
                "ihl": ihl,
                "tos": tos,
                "total_length": total_length,
                "identification": identification,
                "flags_frag_offset": flags_frag_offset,
                "ttl": ttl,
                "protocol": f"{protocol_num} ({protocol_name})",
                "header_checksum": header_checksum,
                "src_ip": src_ip,
                "dest_ip": dest_ip
            },
            "payload": ip_payload
        }
    except:
        return None


def parse_ipv6_packet(payload):
    """Parse IPv6 packet header and return structured information"""
    if not payload or len(payload) < 80:  # Minimum length for an IPv6 header (40 bytes = 80 hex chars)
        return None
    
    try:
        # First byte contains version (4 bits) and part of Traffic Class (4 bits)
        version_tc_high = int(payload[0:2], 16)
        version = version_tc_high >> 4
        tc_high = version_tc_high & 0x0F
        
        # Second byte contains rest of Traffic Class (4 bits) and part of Flow Label (4 bits)
        tc_low_flow_high = int(payload[2:4], 16)
        tc_low = tc_low_flow_high >> 4
        flow_high = tc_low_flow_high & 0x0F
        
        # Traffic Class (combining high and low parts)
        traffic_class = (tc_high << 4) | tc_low
        
        # Flow Label (20 bits total: 4 from second byte + 16 from bytes 3-4)
        flow_label_low = int(payload[4:8], 16)
        flow_label = (flow_high << 16) | flow_label_low
        
        # Payload Length (16 bits)
        payload_length = int(payload[8:12], 16)
        
        # Next Header (8 bits) - Similar to IPv4's protocol field
        next_header = int(payload[12:14], 16)
        
        # Protocol name
        protocol_name = "Unknown"
        if next_header == 1:
            protocol_name = "ICMP"
        elif next_header == 6:
            protocol_name = "TCP"
        elif next_header == 17:
            protocol_name = "UDP"
        elif next_header == 58:
            protocol_name = "ICMPv6"
        
        # Hop Limit (8 bits) - Similar to IPv4's TTL
        hop_limit = int(payload[14:16], 16)
        
        # Source IPv6 address (128 bits = 32 hex chars)
        src_ipv6 = ':'.join([payload[i:i+4] for i in range(16, 48, 4)])
        
        # Destination IPv6 address (128 bits = 32 hex chars)
        dest_ipv6 = ':'.join([payload[i:i+4] for i in range(48, 80, 4)])
        
        # IPv6 payload starts after the header (fixed 40 bytes)
        ipv6_payload = payload[80:]
        
        return {
            "ipv6": {
                "version": version,
                "traffic_class": traffic_class,
                "flow_label": flow_label,
                "payload_length": payload_length,
                "next_header": f"{next_header} ({protocol_name})",
                "hop_limit": hop_limit,
                "src_ipv6": src_ipv6,
                "dest_ipv6": dest_ipv6
            },
            "payload": ipv6_payload
        }
    except:
        return None


def parse_tcp_packet(payload):
    """Parse TCP header and return structured information"""
    if not payload or len(payload) < 40:  # Minimum TCP header (20 bytes = 40 hex chars)
        return None
    
    try:
        src_port = int(payload[0:4], 16)
        dest_port = int(payload[4:8], 16)
        seq_num = int(payload[8:16], 16)
        ack_num = int(payload[16:24], 16)
        
        # Data offset and flags
        data_offset_flags = int(payload[24:28], 16)
        data_offset = (data_offset_flags >> 12) & 0x0F  # Higher 4 bits
        
        # TCP flags
        flags = data_offset_flags & 0x01FF  # Lower 9 bits
        flag_names = []
        if flags & 0x01:
            flag_names.append("FIN")
        if flags & 0x02:
            flag_names.append("SYN")
        if flags & 0x04:
            flag_names.append("RST")
        if flags & 0x08:
            flag_names.append("PSH")
        if flags & 0x10:
            flag_names.append("ACK")
        if flags & 0x20:
            flag_names.append("URG")
        if flags & 0x40:
            flag_names.append("ECE")
        if flags & 0x80:
            flag_names.append("CWR")
        if flags & 0x100:
            flag_names.append("NS")
        
        window = int(payload[28:32], 16)
        checksum = payload[32:36]
        urgent_pointer = payload[36:40]
        
        # Calculate the TCP header size in bytes * 2 (for hex chars)
        tcp_header_size = data_offset * 4 * 2
        tcp_payload = payload[tcp_header_size:]
        
        return {
            "tcp": {
                "src_port": src_port,
                "dest_port": dest_port,
                "seq_num": seq_num,
                "ack_num": ack_num,
                "data_offset": data_offset,
                "flags": flags,
                "flag_names": ", ".join(flag_names),
                "window": window,
                "checksum": checksum,
                "urgent_pointer": urgent_pointer
            },
            "payload": tcp_payload
        }
    except:
        return None


def detect_doip(payload):
    """Detect DoIP protocol and parse header"""
    if len(payload) < 16:  # Minimum 8 bytes for header (16 hex chars)
        return {"doip": {
            "protocol_version": "Unknown",
            "inverse_protocol_version": "Unknown",
            "payload_type": "Unknown",
            "payload_length": 0,
            "note": "Insufficient data for DoIP header"
        }, "payload": payload}
    
    try:
        protocol_version = int(payload[0:2], 16)
        inverse_protocol_version = int(payload[2:4], 16)
        payload_type = int(payload[4:8], 16)
        payload_length = int(payload[8:16], 16)
        
        # Dictionary of DoIP payload types
        payload_types = {
            0x0000: "Generic DoIP Header Negative ACK",
            0x0001: "Vehicle Identification Request",
            0x0002: "Vehicle Identification Request with EID",
            0x0003: "Vehicle Identification Request with VIN",
            0x0004: "Vehicle Announcement Response Message",
            0x0005: "Routing Activation Request",
            0x0006: "Routing Activation Response",
            0x0007: "Alive Check Request",
            0x0008: "Alive Check Response",
            0x4001: "DoIP Entity Status Request",
            0x4002: "DoIP Entity Status Response",
            0x4003: "Diagnostic Power Mode Information Request",
            0x4004: "Diagnostic Power Mode Information Response",
            0x8001: "Diagnostic Message",
            0x8002: "Diagnostic Message ACK",
            0x8003: "Diagnostic Message Negative ACK"
        }
        
        # Create the basic DoIP info dictionary
        doip_info = {
            "protocol_version": f"0x{protocol_version:02X}",
            "inverse_protocol_version": f"0x{inverse_protocol_version:02X}",
            "payload_type": f"0x{payload_type:04X} ({payload_types.get(payload_type, 'Unknown')})",
            "payload_length": payload_length
        }
        
        # Validate if this looks like a proper DoIP header (protocol version + inverse should be 0xFF)
        if protocol_version + inverse_protocol_version != 0xFF:
            return {"doip": {
                "protocol_version": f"0x{protocol_version:02X}",
                "inverse_protocol_version": f"0x{inverse_protocol_version:02X}",
                "payload_type": "Invalid",
                "payload_length": 0,
                "note": "Invalid DoIP header (protocol version validation failed)"
            }, "payload": payload}
        
        # Start of actual DoIP payload after the header (8 bytes)
        doip_payload = payload[16:]
        
        # For Diagnostic Messages, ACKs and NACKs extract source and target addresses
        if payload_type in [0x8001, 0x8002, 0x8003] and len(doip_payload) >= 8:
            source_address = int(doip_payload[0:4], 16)
            target_address = int(doip_payload[4:8], 16)
            doip_info["source_address"] = f"0x{source_address:04X}"
            doip_info["target_address"] = f"0x{target_address:04X}"
            
            # Only for diagnostic messages (0x8001), the UDS data follows after addresses
            if payload_type == 0x8001:
                return {
                    "doip": doip_info,
                    "payload": doip_payload[8:]  # Skip the source and target addresses
                }
            elif payload_type == 0x8002 and len(doip_payload) >= 9:
                # For ACK messages, there's an ACK code after the addresses
                ack_code = int(doip_payload[8:10], 16)
                doip_info["ack_code"] = f"0x{ack_code:02X}"
                return {
                    "doip": doip_info,
                    "payload": ""  # No UDS payload for ACKs
                }
            elif payload_type == 0x8003 and len(doip_payload) >= 9:
                # For NACK messages, there's a NACK code after the addresses
                nack_code = int(doip_payload[8:10], 16)
                doip_info["nack_code"] = f"0x{nack_code:02X}"
                return {
                    "doip": doip_info,
                    "payload": ""  # No UDS payload for NACKs
                }
        
        # Handle Routing Activation Response (0x0006)
        if payload_type == 0x0006 and len(doip_payload) >= 9:
            # First 2 bytes: Target address (logical address of external test equipment)
            target_address = int(doip_payload[0:4], 16)
            
            # Next 2 bytes: Source address (logical address of DoIP entity)
            source_address = int(doip_payload[4:8], 16)
            
            # Response code
            response_code = int(doip_payload[8:10], 16)
            
            # Reserved bytes (should be 0)
            reserved = doip_payload[10:18] if len(doip_payload) >= 18 else ""
            
            # Response code meaning
            response_descriptions = {
                0x00: "Routing activation denied due to unsupported activation type",
                0x01: "Routing activation denied due to missing authentication",
                0x02: "Routing activation denied due to rejected confirmation",
                0x03: "Routing activation denied due to unsupported routing activation",
                0x04: "Routing activation denied because maximum number of sockets reached",
                0x05: "Routing activation denied because maximum number of concurrent TCP_DATA sockets reached",
                0x06: "Routing activation denied due to missing confirmation",
                0x07: "Routing activation denied due to vehicle manufacturer specific reason",
                0x08: "Routing activation denied because vehicle identifies as not ready for remote diagnostic",
                0x09: "Routing activation denied due to unsupported protocol",
                0x0A: "Routing activation denied due to different authentication method expected",
                0x10: "Routing activation successful",
                0x11: "Routing activation successful with TLS connection established",
            }
            
            response_description = response_descriptions.get(response_code, "Unknown response code")
            
            doip_info["target_address"] = f"0x{target_address:04X}"
            doip_info["source_address"] = f"0x{source_address:04X}"
            doip_info["routing_activation_response"] = f"0x{response_code:02X}"
            doip_info["routing_response_description"] = response_description
            if reserved:
                doip_info["reserved"] = reserved
            
            return {
                "doip": doip_info,
                "payload": ""  # No UDS payload for routing activation responses
            }
        
        # Handle Vehicle Announcement Response Message (0x0004)
        if payload_type == 0x0004 and len(doip_payload) >= 32:
            # Extract VIN (17 bytes)
            vin_hex = doip_payload[0:34]
            try:
                vin = bytes.fromhex(vin_hex).decode('ascii')
            except:
                vin = vin_hex
            
            # Extract logical address (2 bytes)
            logical_address = int(doip_payload[34:38], 16)
            
            # Extract EID (6 bytes)
            eid = doip_payload[38:50]
            
            # Extract GID (6 bytes) - or whatever remains
            gid = doip_payload[50:] if len(doip_payload) > 50 else ""
            
            doip_info["vin"] = vin_hex
            doip_info["decoded_vin"] = vin
            doip_info["logical_address"] = f"0x{logical_address:04X}"
            doip_info["eid"] = eid
            doip_info["gid"] = gid
            
            return {
                "doip": doip_info,
                "payload": ""  # No UDS payload for announcement messages
            }
        
        return {
            "doip": doip_info,
            "payload": doip_payload
        }
    except Exception as e:
        return {"doip": {
            "protocol_version": "Unknown",
            "inverse_protocol_version": "Unknown",
            "payload_type": "Unknown",
            "payload_length": 0,
            "error": str(e),
            "note": "TCP port is DoIP (13400) but payload is not valid DoIP data"
        }, "payload": payload}


def parse_uds_packet(payload):
    """Parse UDS diagnostic message"""
    if not payload or len(payload) < 2:  # Need at least service ID
        return {"uds": {"service_id": "Unknown", "service_type": "Unknown"}, "payload": payload}
    
    try:
        service_id = int(payload[0:2], 16)
        
        # Determine service type based on service ID
        service_id_info = {
            0x10: "Diagnostic Session Control",
            0x11: "ECU Reset",
            0x14: "Clear Diagnostic Information",
            0x19: "Read DTC Information",
            0x22: "Read Data By Identifier",
            0x23: "Read Memory By Address",
            0x27: "Security Access",
            0x28: "Communication Control",
            0x2E: "Write Data By Identifier",
            0x2F: "Input Output Control By Identifier",
            0x31: "Routine Control",
            0x34: "Request Download",
            0x35: "Request Upload",
            0x36: "Transfer Data",
            0x37: "Request Transfer Exit",
            0x3D: "Write Memory By Address",
            0x3E: "Tester Present",
            0x50: "Diagnostic Session Control Response",
            0x51: "ECU Reset Response",
            0x54: "Clear Diagnostic Information Response",
            0x59: "Read DTC Information Response",
            0x62: "Read Data By Identifier Response",
            0x63: "Read Memory By Address Response",
            0x67: "Security Access Response",
            0x68: "Communication Control Response",
            0x6E: "Write Data By Identifier Response",
            0x6F: "Input Output Control By Identifier Response",
            0x71: "Routine Control Response",
            0x74: "Request Download Response",
            0x75: "Request Upload Response",
            0x76: "Transfer Data Response",
            0x77: "Request Transfer Exit Response",
            0x7D: "Write Memory By Address Response",
            0x7E: "Tester Present Response",
            0x7F: "Negative Response"
        }
        
        service_type = service_id_info.get(service_id, "Unknown")
        
        # Check if it's a response message
        is_response = False
        if service_id > 0x40 and service_id != 0x7F:
            is_response = True
        
        # Parse additional details based on service ID
        details = {}
        
        # Negative response handling
        if service_id == 0x7F and len(payload) >= 6:
            requested_sid = int(payload[2:4], 16)
            nrc = int(payload[4:6], 16)
            
            # Known negative response codes
            nrc_codes = {
                0x10: "General Reject",
                0x11: "Service Not Supported",
                0x12: "Sub-Function Not Supported",
                0x13: "Invalid Format or Message Length",
                0x14: "Response Too Long",
                0x21: "Busy Repeat Request",
                0x22: "Conditions Not Correct",
                0x24: "Request Sequence Error",
                0x25: "No Response From Sub-net Component",
                0x26: "Failure Prevents Execution Of Requested Action",
                0x31: "Request Out Of Range",
                0x33: "Security Access Denied",
                0x35: "Invalid Key",
                0x36: "Exceed Number Of Attempts",
                0x37: "Required Time Delay Not Expired",
                0x70: "Upload/Download Not Accepted",
                0x71: "Transfer Data Suspended",
                0x72: "General Programming Failure",
                0x73: "Wrong Block Sequence Counter",
                0x78: "Request Correctly Received But Response Is Pending",
                0x7E: "Sub-Function Not Supported In Active Session",
                0x7F: "Service Not Supported In Active Session"
            }
            
            details["Requested Service"] = f"0x{requested_sid:02X} ({service_id_info.get(requested_sid, 'Unknown')})"
            details["Response Code"] = f"0x{nrc:02X} ({nrc_codes.get(nrc, "Unknown")})"
        
        # Session control
        elif service_id == 0x10 or service_id == 0x50:
            if len(payload) >= 4:
                session_type = int(payload[2:4], 16)
                session_types = {
                    0x01: "Default Session",
                    0x02: "Programming Session",
                    0x03: "Extended Diagnostic Session",
                    0x04: "Safety System Diagnostic Session",
                }
                details["Session Type"] = f"0x{session_type:02X} ({session_types.get(session_type, "Unknown")})"
        
        # Read Data By Identifier
        elif service_id == 0x22 or service_id == 0x62:
            if len(payload) >= 6:
                did = int(payload[2:6], 16)
                details["Data Identifier"] = f"0x{did:04X}"
                if service_id == 0x62 and len(payload) >= 8:
                    details["Data"] = payload[6:]
        
        # Write Data By Identifier
        elif service_id == 0x2E or service_id == 0x6E:
            if len(payload) >= 6:
                did = int(payload[2:6], 16)
                details["Data Identifier"] = f"0x{did:04X}"
                if len(payload) > 6:
                    details["Data"] = payload[6:]
        
        # Tester Present
        elif service_id == 0x3E or service_id == 0x7E:
            if len(payload) >= 4:
                sub_function = int(payload[2:4], 16)
                details["Sub-Function"] = f"0x{sub_function:02X}"
        
        return {
            "uds": {
                "service_id": f"0x{service_id:02X}",
                "service_type": service_type,
                "is_response": is_response,
                "details": details
            },
            "payload": payload
        }
    except:
        return {"uds": {"service_id": "Error", "service_type": "Error"}, "payload": payload}


def display_ethernet_info(ethernet_packet, eth_placeholder):
    """Display Ethernet header information in the UI"""
    eth_info = ethernet_packet["ethernet"]
    eth_header_hex = data[:28]
    eth_header_formatted = ' '.join([eth_header_hex[i:i+2] for i in range(0, len(eth_header_hex), 2)])

    eth_type_name = 'Unknown'
    if eth_info['eth_type'] == '0800':
        eth_type_name = 'IPv4'
    elif eth_info['eth_type'] == '86DD':
        eth_type_name = 'IPv6'

    eth_text = f"""Ethernet Header:
{eth_header_formatted}

Destination MAC: {eth_info['dest_mac']}
Source MAC: {eth_info['src_mac']}
EtherType: 0x{eth_info['eth_type']} ({eth_type_name})
"""
    eth_placeholder.text(eth_text)
    return eth_info['eth_type']
    

def display_ipv4_info(ip_packet, ethernet_packet, ip_placeholder):
    """Display IPv4 header information in the UI"""
    ip_info = ip_packet["ip"]
    ip_header_len = ip_info['ihl'] * 8
    ip_header_hex = ethernet_packet["payload"][:ip_header_len]
    ip_header_formatted = ' '.join([ip_header_hex[i:i+2] for i in range(0, len(ip_header_hex), 2)])
    
    ip_text = f"""IP Header:
{ip_header_formatted}

Version: {ip_info['version']}
Header Length: {ip_info['ihl']} (32-bit words)
Type of Service: {ip_info['tos']}
Total Length: {ip_info['total_length']} bytes
Identification: 0x{ip_info['identification']}
Flags Fragment Offset: 0x{ip_info['flags_frag_offset']}
TTL: {ip_info['ttl']}
Protocol: {ip_info['protocol']}
Source IP: {ip_info['src_ip']}
Destination IP: {ip_info['dest_ip']}
"""
    ip_placeholder.text(ip_text)
    return ip_info


def display_ipv6_info(ipv6_packet, ethernet_packet, ip_placeholder):
    """Display IPv6 header information in the UI"""
    ipv6_info = ipv6_packet["ipv6"]
    ipv6_header_hex = ethernet_packet["payload"][:80]
    ipv6_header_formatted = ' '.join([ipv6_header_hex[i:i+2] for i in range(0, len(ipv6_header_hex), 2)])
    
    ip_text = f"""IPv6 Header:
{ipv6_header_formatted}

Version: {ipv6_info['version']}
Traffic Class: 0x{ipv6_info['traffic_class']:02X}
Flow Label: 0x{ipv6_info['flow_label']:05X}
Payload Length: {ipv6_info['payload_length']} bytes
Next Header: {ipv6_info['next_header']}
Hop Limit: {ipv6_info['hop_limit']}
Source IPv6: {ipv6_info['src_ipv6']}
Destination IPv6: {ipv6_info['dest_ipv6']}
"""
    ip_placeholder.text(ip_text)
    return ipv6_info


def display_tcp_info(tcp_packet, ip_packet_payload, tcp_placeholder):
    """Display TCP header information in the UI"""
    tcp_info = tcp_packet["tcp"]
    tcp_header_len = tcp_info['data_offset'] * 8
    tcp_header_hex = ip_packet_payload[:tcp_header_len]
    tcp_header_formatted = ' '.join([tcp_header_hex[i:i+2] for i in range(0, len(tcp_header_hex), 2)])
    
    tcp_text = f"""TCP Header:
{tcp_header_formatted}

Source Port: {tcp_info['src_port']}
Destination Port: {tcp_info['dest_port']}
Sequence Number: {tcp_info['seq_num']}
Acknowledgment Number: {tcp_info['ack_num']}
Data Offset: {tcp_info['data_offset']} (32-bit words)
Flags: {tcp_info['flag_names']}
Window Size: {tcp_info['window']}
"""
    tcp_placeholder.text(tcp_text)
    return tcp_info


def display_doip_info(doip_info, payload, doip_placeholder):
    """Display DoIP information in the UI"""
    doip_data = doip_info["doip"]
    doip_header_hex = payload[:16]
    doip_header_formatted = ' '.join([doip_header_hex[i:i+2] for i in range(0, len(doip_header_hex), 2)])
    
    # 페이로드 타입 확인
    is_diagnostic_message = False
    if 'payload_type' in doip_data and ('0x8001' in doip_data['payload_type'] or 
                                         '0x8002' in doip_data['payload_type'] or 
                                         '0x8003' in doip_data['payload_type']):
        is_diagnostic_message = True
    
    doip_text = f"""DoIP Header:
{doip_header_formatted}

Protocol Version: {doip_data['protocol_version']}
Inverse Protocol Version: {doip_data['inverse_protocol_version']}
Payload Type: {doip_data['payload_type']}
Payload Length: {doip_data['payload_length']} bytes"""

    # Diagnostic Message(0x8001)일 경우 Source/Target Address는 표시하지 않음
    if not is_diagnostic_message:
        # Add additional DoIP fields if they exist
        if 'source_address' in doip_data:
            doip_text += f"\nSource Address: {doip_data['source_address']}"
        if 'target_address' in doip_data:
            doip_text += f"\nTarget Address: {doip_data['target_address']}"
    else:
        doip_text += "\n\nNote: See UDS column for Source/Target Address info"
        
    # 다른 정보는 계속 표시
    if 'ack_code' in doip_data:
        doip_text += f"\nACK Code: {doip_data['ack_code']}"
    if 'nack_code' in doip_data:
        doip_text += f"\nNACK Code: {doip_data['nack_code']}"
    if 'client_address' in doip_data:
        doip_text += f"\nClient Address: {doip_data['client_address']}"
    if 'doip_entity_address' in doip_data:
        doip_text += f"\nDoIP Entity Address: {doip_data['doip_entity_address']}"
    
    # 나머지 정보들은 기존과 같이 표시
    # ...

    doip_placeholder.text(doip_text)
    return doip_data


def display_uds_info(uds_data, payload, uds_placeholder):
    """Display UDS information in the UI"""
    uds_payload_formatted = ' '.join([payload[i:i+2] for i in range(0, min(30, len(payload)), 2)])
    if len(payload) > 30:
        uds_payload_formatted += "..."
    
    uds_text = f"""UDS Data:
{uds_payload_formatted}

Service ID: {uds_data['uds']['service_id']}
Service Type: {uds_data['uds']['service_type']}
"""
    
    # Add details if available
    if 'details' in uds_data['uds'] and uds_data['uds']['details']:
        uds_text += "\nDetails:"
        for key, value in uds_data['uds']['details'].items():
            uds_text += f"\n- {key}: {value}"
    else:
        uds_text += "\nNo detailed information available."
    
    uds_placeholder.text(uds_text)

# Define function to parse CSV content
def parse_csv(content):
    try:
        # Replace the header with a standard format
        lines = content.strip().split('\n')
        if len(lines) > 0:
            df = pd.read_csv(StringIO(content), sep=',')
            return df
    except Exception as e:
        st.error(f"Error parsing CSV: {e}")
        return None

# Extract info from the document
def extract_content_from_document():
    return """ts,type,ch,tx_rx,data,fcs,port,sim
0.257025,ETH,1,Rx,46:333300000002A81374BD389D86DD6000000000103AFFFE800000000000004C705F11449FCF51FF0200000000000000000000000000028500674D000000000101A81374BD389D,FCS:734d6816,Ports:Port6,Sim:0
0.272157,ETH,1,Rx,9d:333300010002A81374BD389D86DD60054E1700671101FE800000000000004C705F11449FCF51FF0200000000000000000000000100020222022300672D4501D30E160008000202BF0001000E000100012A621DD5A81374BD389D0003000C0DA81374000000000000000000270011000F4445534B544F502D4B524E4E5330370010000E0000013700084D53465420352E30000600080011001700180027,FCS:40a51d09,Ports:Port6,Sim:0
0.468434,ETH,1,Rx,52:FFFFFFFFFFFF0200000010010800450000445756000040116654A9FE1301FFFFFFFF34583458003092C202FD0004000000204B4E4D3233303941523130305650323531100102000000100100000000000100,FCS:7d8d192,Ports:Port5,Sim:0
1.065976,ETH,1,Rx,158:FFFFFFFFFFFFA81374BD389D08004500014A4F3200008011EA7100000000FFFFFFFF00440043013689C2010106004A690E8B0300000000000000000000000000000000000000A81374BD389D00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013D0701A81374BD389D32040AE39F280C0F4445534B544F502D4B524E4E5330373C084D53465420352E30370E0103060F1F212B2C2E2F7779F9FCFF,FCS:35b681a9,Ports:Port6,Sim:0
1.468449,ETH,1,Rx,52:FFFFFFFFFFFF020000001001080045000044575D00004011664DA9FE1301FFFFFFFF34583458003092C202FD0004000000204B4E4D3233303941523130305650323531100102000000100100000000000100,FCS:92255390,Ports:Port5,Sim:0"""


# Get the content
# csv_content = extract_content_from_document()
# df = parse_csv(csv_content)
# dir_data = Path('.').absolute()/'asc'
dir_data = Path('.')/'asc'
file_xlsx = dir_data/'obd_ethernet_log.new.xlsx'
df = pd.read_excel(file_xlsx)    
df = df.loc[df['tx_rx'] == 'Rx', :].reset_index(drop=True)

if df is not None:
    # Clean up the data column (remove the length prefix if present)
    def clean_data(data_str):
        if ':' in data_str:
            parts = data_str.split(':', 1)
            return parts[1]
        return data_str
    
    df['data'] = df['data'].apply(clean_data)
    
    # Display the original dataframe
    st.subheader("Original OBD Ethernet Log")
    st.dataframe(df.style.format({'ts': '{:,.4f}'}), height=200, use_container_width=True)
    
    col_packet_data, col_packet_padding  = st.columns([2, 9])
    with col_packet_data:
        # Display Raw Packet Data first
        st.subheader("Raw Packet Data")

        # Allow user to select a row for analysis
        selected_index = st.number_input(
            # "Select a packet to analyze:", 
            "", 
            min_value=df.index.min(), 
            max_value=df.index.max(), 
            value=df.index.min(), 
            step=1
        )

    if selected_index is not None:
        # Get selected row data
        selected_row = df.iloc[selected_index]
        data = selected_row['data']
        
        # Prepare raw data visualization
        ethernet_packet = parse_ethernet_packet(data)
        # colored_hex = create_colored_hex_view(data, ethernet_packet)
        colored_hex = create_colored_hex_visualization(data, ethernet_packet)
        st.markdown(colored_hex, unsafe_allow_html=True)
        
        # Show plain hex data in an expander
        with st.expander("Show plain hex data"):
            formatted_data = ' '.join([data[i:i+2] for i in range(0, len(data), 2)])
            st.text_area("Raw Hex Data", formatted_data, height=100)

        # Set up the protocol analysis UI
        st.subheader("Packet Analysis")
        col1, col2, col3, col4, col5, ip_header, ip_placeholder, tcp_placeholder, doip_placeholder, uds_placeholder = create_protocol_columns()
        
        # Analyze the packet
        analyze_packet(data, col1, col2, col3, col4, col5, ip_header, ip_placeholder, tcp_placeholder, doip_placeholder, uds_placeholder)
else:
    st.error("Failed to parse the OBD Ethernet log data. Please check the format and try again.")

