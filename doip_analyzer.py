from pathlib import Path
import streamlit as st
import pandas as pd
import numpy as np
import re
from io import StringIO

st.set_page_config(layout="wide", page_title="Automotive Diagnostic Communication Analyzer")
st.title("Automotive Diagnostic Communication Analyzer")

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
    if not payload or len(payload) < 40:  # Minimum length for an IP header
        return None
    
    try:
        # Extract IP header fields
        version_ihl = payload[0:2]
        # version = int(version_ihl[0], 16) >> 4
        version = int(version_ihl[0], 16)
        # ihl = int(version_ihl[0], 16) & 0x0F
        ihl = int(version_ihl[1], 16)
        
        # ToS, Total Length, ID, Flags+FragOffset
        tos = payload[2:4]
        total_len = int(payload[4:8], 16)
        id_field = payload[8:12]
        flags_frag = payload[12:16]
        
        # TTL, Protocol, Header Checksum
        ttl = int(payload[16:18], 16)
        protocol = int(payload[18:20], 16)
        header_checksum = payload[20:24]
        
        # Source and Destination IP addresses
        src_ip = '.'.join([str(int(payload[24:26], 16)), 
                          str(int(payload[26:28], 16)), 
                          str(int(payload[28:30], 16)),
                          str(int(payload[30:32], 16))])
        
        dest_ip = '.'.join([str(int(payload[32:34], 16)), 
                           str(int(payload[34:36], 16)), 
                           str(int(payload[36:38], 16)),
                           str(int(payload[38:40], 16))])
        
        # IP header length in bytes
        header_len = ihl * 4
        
        # IP payload starts after the header
        ip_payload = payload[header_len*2:]
        
        protocol_name = "Unknown"
        if protocol == 1:
            protocol_name = "ICMP"
        elif protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        
        return {
            "ip": {
                "version": version,
                "ihl": ihl,
                "tos": tos,
                "total_length": total_len,
                "identification": id_field,
                "flags_frag_offset": flags_frag,
                "ttl": ttl,
                "protocol": f"{protocol} ({protocol_name})",
                "header_checksum": header_checksum,
                "src_ip": src_ip,
                "dest_ip": dest_ip
            },
            "payload": ip_payload
        }
    except:
        return None

def parse_ipv6_packet(payload):
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
        
        # Hop Limit (8 bits) - Similar to IPv4's TTL
        hop_limit = int(payload[14:16], 16)
        
        # Source IPv6 address (128 bits = 32 hex chars)
        src_ipv6 = ':'.join([payload[i:i+4] for i in range(16, 48, 4)])
        
        # Destination IPv6 address (128 bits = 32 hex chars)
        dest_ipv6 = ':'.join([payload[i:i+4] for i in range(48, 80, 4)])
        
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
    if not payload or len(payload) < 40:  # Minimum length for a TCP header (20 bytes)
        return None
    
    try:
        # Extract TCP header fields
        src_port = int(payload[0:4], 16)
        dest_port = int(payload[4:8], 16)
        seq_num = int(payload[8:16], 16)
        ack_num = int(payload[16:24], 16)
        
        # Data offset, reserved, flags
        data_offset_flags = int(payload[24:28], 16)
        data_offset = (data_offset_flags >> 12) & 0xF
        
        # Flags
        flags = data_offset_flags & 0x3F
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        
        # Window size, checksum, urgent pointer
        window = int(payload[28:32], 16)
        checksum = payload[32:36]
        urgent_ptr = payload[36:40]
        
        # TCP header length in bytes
        header_len = data_offset * 4
        
        # TCP payload starts after the header
        tcp_payload = payload[header_len*2:]
        
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
                "urgent_ptr": urgent_ptr
            },
            "payload": tcp_payload
        }
    except:
        return None

def parse_uds_packet(payload):
    if not payload or len(payload) < 2:
        return {"uds": {"service_id": "Unknown", "service_type": "Unknown"}, "payload": payload}
    
    try:
        service_id = int(payload[0:2], 16)
        service_type = "Unknown"
        
        # Common UDS service IDs
        uds_services = {
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
            0x85: "Control DTC Setting"
        }
        
        # Check if response (add 0x40 to request service ID)
        if service_id >= 0x40 and service_id <= 0xBF:
            req_service_id = service_id - 0x40
            if req_service_id in uds_services:
                service_type = f"Response to {uds_services[req_service_id]}(0x{req_service_id:02x})"
            else:
                service_type = f"Response to Unknown Service (0x{req_service_id:02X})"
        else:
            if service_id in uds_services:
                service_type = uds_services[service_id]
        
        # Determine service details based on service ID
        service_details = {}
        remaining_payload = payload[2:]
        
        # Specific service parsing
        if service_id == 0x10:  # Diagnostic Session Control
            if len(remaining_payload) >= 2:
                session_type = int(remaining_payload[0:2], 16)
                session_types = {
                    0x01: "Default Session",
                    0x02: "Programming Session",
                    0x03: "Extended Diagnostic Session",
                    0x04: "Safety System Diagnostic Session",
                    0x05: "OBD Session"
                }
                service_details["session_type"] = session_types.get(session_type, f"Unknown (0x{session_type:02X})")
        
        elif service_id == 0x22:  # Read Data By Identifier
            if len(remaining_payload) >= 4:
                did = int(remaining_payload[0:4], 16)
                service_details["data_identifier"] = f"0x{did:04X}"
                service_details["data_value"] = remaining_payload[4:]
        
        elif service_id == 0x27:  # Security Access
            if len(remaining_payload) >= 2:
                sec_level = int(remaining_payload[0:2], 16)
                service_details["security_level"] = f"Level {sec_level//2}" if sec_level % 2 != 0 else f"Seed for Level {sec_level//2}"
                if sec_level % 2 == 0 and len(remaining_payload) > 2:
                    service_details["key"] = remaining_payload[2:]
                elif sec_level % 2 != 0 and len(remaining_payload) > 2:
                    service_details["seed"] = remaining_payload[2:]
        
        elif service_id == 0x3E:  # Tester Present
            if len(remaining_payload) >= 2:
                subfunction = int(remaining_payload[0:2], 16)
                service_details["subfunction"] = "Zero Subfunction" if subfunction == 0x00 else f"Unknown (0x{subfunction:02X})"
        
        return {
            "uds": {
                "service_id": f"0x{service_id:02X}",
                "service_type": service_type,
                "details": service_details
            },
            # "payload": remaining_payload
            "payload": payload
        }
    except:
        return {
            "uds": {
                "service_id": "Unknown", 
                "service_type": "Unknown", 
            }, 
            "payload": payload
        }



# Helper function to detect DoIP protocol (commonly used in automotive diagnostics)
def detect_doip(tcp_payload):
    # DoIP protocol detection logic can be added here
    if len(tcp_payload) < 16:  # Minimum 8 bytes for header (16 hex chars)
        return {"doip": {"protocol_version": "Unknown", "inverse_protocol_version": "n.a.", "payload_type": "n.a.", "payload_length": "n.a."}, "payload": tcp_payload}
    
    try:
        protocol_version = int(tcp_payload[0:2], 16)
        inverse_protocol_version = int(tcp_payload[2:4], 16)
        payload_type = int(tcp_payload[4:8], 16)
        payload_length = int(tcp_payload[8:16], 16)  # 4 bytes for payload length
        
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
        
        # Start of actual DoIP payload after the header (8 bytes)
        doip_payload = tcp_payload[16:]
        
        # For Diagnostic Messages (0x8001), extract source and target addresses
        if payload_type == 0x8001 and len(doip_payload) >= 4:
            source_address = int(doip_payload[0:4], 16)
            target_address = int(doip_payload[4:8], 16)
            doip_info["source_address"] = f"0x{source_address:04X}"
            doip_info["target_address"] = f"0x{target_address:04X}"
            # UDS data starts after source and target addresses
            return {
                "doip": doip_info,
                "payload": doip_payload[8:]  # Skip the source and target addresses
            }
        
        # For Diagnostic Message ACK (0x8002), extract addresses and response code
        elif payload_type == 0x8002 and len(doip_payload) >= 6:
            source_address = int(doip_payload[0:4], 16)
            target_address = int(doip_payload[4:8], 16)
            ack_code = int(doip_payload[8:10], 16)
            
            ack_codes = {
                0x00: "ACK",
                0x01: "Invalid source address",
                0x02: "Unknown target address",
                0x03: "Diagnostic message too large",
                0x04: "Out of memory",
                0x05: "Target unreachable",
                0x06: "Unknown network",
                0x07: "Transport protocol error"
            }
            
            doip_info["source_address"] = f"0x{source_address:04X}"
            doip_info["target_address"] = f"0x{target_address:04X}"
            doip_info["ack_code"] = f"0x{ack_code:02X} ({ack_codes.get(ack_code, 'Unknown')})"
            
            return {
                "doip": doip_info,
                "payload": doip_payload[10:]  # Skip after the ACK code
            }
        
        # For Diagnostic Message Negative ACK (0x8003), extract addresses and NACK code
        elif payload_type == 0x8003 and len(doip_payload) >= 6:
            source_address = int(doip_payload[0:4], 16)
            target_address = int(doip_payload[4:8], 16)
            nack_code = int(doip_payload[8:10], 16)
            
            nack_codes = {
                0x00: "Reserved",
                0x01: "Invalid source address",
                0x02: "Unknown target address",
                0x03: "Diagnostic message too large",
                0x04: "Out of memory",
                0x05: "Target unreachable",
                0x06: "Unknown network",
                0x07: "Transport protocol error",
                0x10: "Target node not ready",
                0x11: "Unknown test service"
            }
            
            doip_info["source_address"] = f"0x{source_address:04X}"
            doip_info["target_address"] = f"0x{target_address:04X}"
            doip_info["nack_code"] = f"0x{nack_code:02X} ({nack_codes.get(nack_code, 'Unknown')})"
            
            return {
                "doip": doip_info,
                "payload": doip_payload[10:]  # Skip after the NACK code
            }
        
        # For Routing Activation Response (0x0006)
        elif payload_type == 0x0006 and len(doip_payload) >= 6:
            client_logical_address = int(doip_payload[0:4], 16)
            logical_address_of_doip_entity = int(doip_payload[4:8], 16)
            routing_activation_response_code = int(doip_payload[8:10], 16)
            
            response_codes = {
                0x00: "Routing activation accepted",
                0x01: "Routing activation rejected due to unsupported activation type",
                0x02: "Routing activation rejected due to unsupported reserved value",
                0x03: "Routing activation rejected due to missing authentication",
                0x04: "Routing activation rejected due to rejected confirmation",
                0x05: "Routing activation rejected due to unsupported protocol",
                0x06: "Routing activation rejected due to different TCP_DATA port",
                0x07: "Routing activation rejected due to different TCP_DIAG port"
            }
            
            doip_info["client_address"] = f"0x{client_logical_address:04X}"
            doip_info["doip_entity_address"] = f"0x{logical_address_of_doip_entity:04X}"
            doip_info["routing_response_code"] = f"0x{routing_activation_response_code:02X} ({response_codes.get(routing_activation_response_code, 'Unknown')})"
            
            return {
                "doip": doip_info,
                "payload": doip_payload[10:]  # Skip after the response code
            }
        
        return {
            "doip": doip_info,
            "payload": doip_payload
        }
    except Exception as e:
        return {"doip": {"protocol_version": "Unknown", "error": str(e)}, "payload": tcp_payload}

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
1.065976,ETH,1,Rx,158:FFFFFFFFFFFFA81374BD389D08004500014A4F3200008011EA7100000000FFFFFFFF00440043013689C2010106004A690E8B0300000000000000000000000000000000000000A81374BD389D00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013D0701A81374BD389D32040AE39F280C0F4445534B544F502D4B524E4E5330373C084D53465420352E30370E0103060F1F212B2C2E2F7779F9FCFF,FCS:35b681a9,Ports:Port6,Sim:0
1.468449,ETH,1,Rx,52:FFFFFFFFFFFF020000001001080045000044575D00004011664DA9FE1301FFFFFFFF34583458003092C202FD0004000000204B4E4D3233303941523130305650323531100102000000100100000000000100,FCS:92255390,Ports:Port5,Sim:0"""

# Get the content
# csv_content = extract_content_from_document()
# df = parse_csv(csv_content)
dir_data = Path('.').absolute()/'asc'
file_xlsx = dir_data/'obd_ethernet_log.new.xlsx'
df = pd.read_excel(file_xlsx)    

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
    st.dataframe(df, use_container_width=True)
    
    # Allow user to select a row for analysis
    # selected_index = st.selectbox("Select a packet to analyze:", df.index)
    selected_index = st.number_input(
        "Select a packet to analyze:", 
        min_value = df.index.min(), 
        max_value = df.index.max(), 
        value="min", 
        step=1
    )

    # Analyze and display the parsed data
    st.subheader("Packet Analysis")
    
    # Create columns for each protocol layer
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.subheader("Ethernet")
        eth_placeholder = st.empty()
    
    with col2:
        st.subheader("IP")
        ip_placeholder = st.empty()
    
    with col3:
        st.subheader("TCP")
        tcp_placeholder = st.empty()
    
    with col4:
        st.subheader("UDS")
        uds_placeholder = st.empty()
    
    with col5:
        st.subheader("Service")
        service_placeholder = st.empty()
    
    
    if selected_index is not None:
        selected_row = df.iloc[selected_index]
        data = selected_row['data']
        
        # Parse the packet data
        ethernet_packet = parse_ethernet_packet(data)
        
        if ethernet_packet:
            # Display Ethernet information
            eth_info = ethernet_packet["ethernet"]

            eth_type = 'unknown'
            if eth_info['eth_type'] == '0800':
                eth_type = 'IPv4'
            elif eth_info['eth_type'] == '86DD':
                eth_type = 'IPv6'

                # ip_placeholder.text("IPv6 packet detected. IPv6 parsing not implemented in this version.")
                # tcp_placeholder.text("No TCP layer detected.")
                # uds_placeholder.text("No UDS layer detected.")
                # service_placeholder.text("No service information available.")

            eth_text = f"""
            Destination MAC: {eth_info['dest_mac']}
            Source MAC: {eth_info['src_mac']}
            EtherType: 0x{eth_info['eth_type']} ({eth_type})
            """
            eth_placeholder.text(eth_text)
            
            # Parse IP if present
            if eth_info['eth_type'] == '0800':  # IPv4
                ip_packet = parse_ip_packet(ethernet_packet["payload"])
                
                if ip_packet:
                    ip_info = ip_packet["ip"]
                    ip_text = f"""
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
                    
                    # Parse TCP if present
                    if "TCP" in ip_info['protocol']:
                        tcp_packet = parse_tcp_packet(ip_packet["payload"])
                        
                        if tcp_packet:
                            tcp_info = tcp_packet["tcp"]
                            tcp_text = f"""
                            Source Port: {tcp_info['src_port']}
                            Destination Port: {tcp_info['dest_port']}
                            Sequence Number: {tcp_info['seq_num']}
                            Acknowledgment Number: {tcp_info['ack_num']}
                            Data Offset: {tcp_info['data_offset']} (32-bit words)
                            Flags: {tcp_info['flag_names']}
                            Window Size: {tcp_info['window']}
                            """
                            tcp_placeholder.text(tcp_text)
                            
                            # Check for UDS or DoIP protocol
                            payload = tcp_packet["payload"]
                            
                            # Detect if this is DoIP (port 13400 is commonly used for DoIP)
                            if tcp_info['src_port'] == 13400 or tcp_info['dest_port'] == 13400:
                                doip_info = detect_doip(payload)
                                doip_data = doip_info["doip"]
                                
                                # Create complete UDS text with all available DoIP information
                                uds_text = f"Protocol Version: {doip_data['protocol_version']}\n"
                                uds_text += f"Inverse Protocol Version: {doip_data['inverse_protocol_version']}\n" 
                                uds_text += f"Payload Type: {doip_data['payload_type']}\n"
                                uds_text += f"Payload Length: {doip_data['payload_length']} bytes"

                                # Add additional DoIP fields if they exist
                                if 'source_address' in doip_data:
                                    uds_text += f"\nSource Address: {doip_data['source_address']}"
                                if 'target_address' in doip_data:
                                    uds_text += f"\nTarget Address: {doip_data['target_address']}"
                                if 'ack_code' in doip_data:
                                    uds_text += f"\nACK Code: {doip_data['ack_code']}"
                                if 'nack_code' in doip_data:
                                    uds_text += f"\nNACK Code: {doip_data['nack_code']}"
                                if 'client_address' in doip_data:
                                    uds_text += f"\nClient Address: {doip_data['client_address']}"
                                if 'doip_entity_address' in doip_data:
                                    uds_text += f"\nDoIP Entity Address: {doip_data['doip_entity_address']}"
                                if 'routing_response_code' in doip_data:
                                    uds_text += f"\nRouting Response: {doip_data['routing_response_code']}"

                                uds_placeholder.text(uds_text)
                                
                                # Try to parse UDS within DoIP
                                uds_data = parse_uds_packet(doip_info["payload"])
                                
                                service_text = f"""
                                message: {uds_data['payload']}
                                Service ID: {uds_data['uds']['service_id']}
                                Service Type: {uds_data['uds']['service_type']}
                                """
                                
                                # Add details if available
                                if 'details' in uds_data['uds'] and uds_data['uds']['details']:
                                    service_text += "\nDetails:"
                                    for key, value in uds_data['uds']['details'].items():
                                        service_text += f"\n- {key}: {value}"
                                
                                service_placeholder.text(service_text)
                            else:
                                # Try normal UDS parsing
                                uds_data = parse_uds_packet(payload)
                                uds_text = f"""
                                message: {uds_data['payload']}
                                Service ID: {uds_data['uds']['service_id']}
                                Service Type: {uds_data['uds']['service_type']}
                                """
                                uds_placeholder.text(uds_text)
                                
                                # Show service details
                                service_text = "Service Details:"
                                if 'details' in uds_data['uds'] and uds_data['uds']['details']:
                                    for key, value in uds_data['uds']['details'].items():
                                        service_text += f"\n- {key}: {value}"
                                else:
                                    service_text += "\nNo detailed information available."
                                
                                service_placeholder.text(service_text)
                    else:
                        tcp_placeholder.text("No TCP layer detected in this packet.")
                        uds_placeholder.text("No UDS layer detected in this packet.")
                        service_placeholder.text("No service information available.")
                else:
                    ip_placeholder.text("Could not parse IP packet.")
                    tcp_placeholder.text("No TCP layer detected.")
                    uds_placeholder.text("No UDS layer detected.")
                    service_placeholder.text("No service information available.")
            elif eth_info['eth_type'] == '86DD':  # IPv6
                ipv6_packet = parse_ipv6_packet(ethernet_packet["payload"])
                
                if ipv6_packet:
                    ipv6_info = ipv6_packet["ipv6"]
                    ip_text = f"""
                    Version: {ipv6_info['version']}
                    Traffic Class: {ipv6_info['traffic_class']}
                    Flow Label: {ipv6_info['flow_label']}
                    Payload Length: {ipv6_info['payload_length']} bytes
                    Next Header: {ipv6_info['next_header']}
                    Hop Limit: {ipv6_info['hop_limit']}
                    Source IPv6: {ipv6_info['src_ipv6']}
                    Destination IPv6: {ipv6_info['dest_ipv6']}
                    """
                    ip_placeholder.text(ip_text)
                    
                    # Parse TCP if present in IPv6 packet
                    if "TCP" in ipv6_info['next_header']:
                        tcp_packet = parse_tcp_packet(ipv6_packet["payload"])
                        
                        if tcp_packet:
                            tcp_info = tcp_packet["tcp"]
                            tcp_text = f"""
                            Source Port: {tcp_info['src_port']}
                            Destination Port: {tcp_info['dest_port']}
                            Sequence Number: {tcp_info['seq_num']}
                            Acknowledgment Number: {tcp_info['ack_num']}
                            Data Offset: {tcp_info['data_offset']} (32-bit words)
                            Flags: {tcp_info['flag_names']}
                            Window Size: {tcp_info['window']}
                            """
                            tcp_placeholder.text(tcp_text)
                            
                            # Check for UDS or DoIP protocol
                            payload = tcp_packet["payload"]
                            
                            # Detect if this is DoIP (port 13400 is commonly used for DoIP)
                            if tcp_info['src_port'] == 13400 or tcp_info['dest_port'] == 13400:
                                doip_info = detect_doip(payload)
                                doip_data = doip_info["doip"]
                                
                                # Create complete UDS text with all available DoIP information
                                uds_text = f"Protocol Version: {doip_data['protocol_version']}\n"
                                uds_text += f"Inverse Protocol Version: {doip_data['inverse_protocol_version']}\n"
                                uds_text += f"Payload Type: {doip_data['payload_type']}\n"
                                uds_text += f"Payload Length: {doip_data['payload_length']} bytes"

                                # Add additional DoIP fields if they exist
                                if 'source_address' in doip_data:
                                    uds_text += f"\nSource Address: {doip_data['source_address']}"
                                if 'target_address' in doip_data:
                                    uds_text += f"\nTarget Address: {doip_data['target_address']}"
                                if 'ack_code' in doip_data:
                                    uds_text += f"\nACK Code: {doip_data['ack_code']}"
                                if 'nack_code' in doip_data:
                                    uds_text += f"\nNACK Code: {doip_data['nack_code']}"
                                if 'client_address' in doip_data:
                                    uds_text += f"\nClient Address: {doip_data['client_address']}"
                                if 'doip_entity_address' in doip_data:
                                    uds_text += f"\nDoIP Entity Address: {doip_data['doip_entity_address']}"
                                if 'routing_response_code' in doip_data:
                                    uds_text += f"\nRouting Response: {doip_data['routing_response_code']}"

                                uds_placeholder.text(uds_text)
                                
                                # Try to parse UDS within DoIP
                                uds_data = parse_uds_packet(doip_info["payload"])
                                
                                service_text = f"""
                                message: {uds_data['payload']}
                                Service ID: {uds_data['uds']['service_id']}
                                Service Type: {uds_data['uds']['service_type']}
                                """
                                
                                # Add details if available
                                if 'details' in uds_data['uds'] and uds_data['uds']['details']:
                                    service_text += "\nDetails:"
                                    for key, value in uds_data['uds']['details'].items():
                                        service_text += f"\n- {key}: {value}"
                                
                                service_placeholder.text(service_text)
                            else:
                                # Try normal UDS parsing
                                uds_data = parse_uds_packet(payload)
                                uds_text = f"""
                                message: {uds_data['payload']}
                                Service ID: {uds_data['uds']['service_id']}
                                Service Type: {uds_data['uds']['service_type']}
                                """
                                uds_placeholder.text(uds_text)
                                
                                # Show service details
                                service_text = "Service Details:"
                                if 'details' in uds_data['uds'] and uds_data['uds']['details']:
                                    for key, value in uds_data['uds']['details'].items():
                                        service_text += f"\n- {key}: {value}"
                                else:
                                    service_text += "\nNo detailed information available."
                                
                                service_placeholder.text(service_text)
                        else:
                            tcp_placeholder.text("Could not parse TCP packet from IPv6 payload.")
                            uds_placeholder.text("No UDS layer detected.")
                            service_placeholder.text("No service information available.")
                    else:
                        tcp_placeholder.text("No TCP layer detected in this IPv6 packet.")
                        uds_placeholder.text("No UDS layer detected.")
                        service_placeholder.text("No service information available.")
                else:
                    ip_placeholder.text("Could not parse IPv6 packet.")
                    tcp_placeholder.text("No TCP layer detected.")
                    uds_placeholder.text("No UDS layer detected.")
                    service_placeholder.text("No service information available.")
            else:
                ip_placeholder.text(f"Unknown EtherType: {eth_info['eth_type']}")
                tcp_placeholder.text("No TCP layer detected.")
                uds_placeholder.text("No UDS layer detected.")
                service_placeholder.text("No service information available.")
        else:
            eth_placeholder.text("Could not parse Ethernet packet.")
            ip_placeholder.text("No IP layer detected.")
            tcp_placeholder.text("No TCP layer detected.")
            uds_placeholder.text("No UDS layer detected.")
            service_placeholder.text("No service information available.")
            
    # Additional information about the application
    st.sidebar.header("About")
    st.sidebar.info("""
    This application analyzes OBD Ethernet logs from automotive diagnostic communications.
    
    It parses:
    - Ethernet frames
    - IP packets
    - TCP segments
    - UDS diagnostic messages
    
    Select a row from the table to see detailed protocol information.
    """)
    
    # Add a section to display the raw packet data in a formatted way
    st.subheader("Raw Packet Data")
    if selected_index is not None:
        selected_data = df.iloc[selected_index]['data']
        formatted_data = ' '.join([selected_data[i:i+2] for i in range(0, len(selected_data), 2)])
        st.text_area("Raw Hex Data", formatted_data, height=100)
else:
    st.error("Failed to parse the OBD Ethernet log data. Please check the format and try again.")