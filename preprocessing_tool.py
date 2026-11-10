import subprocess
import dpkt
import pandas as pd
from functools import reduce
import numpy as np
from scipy import stats
import argparse
import os

# Crear el parser
parser = argparse.ArgumentParser(description="Analizar un archivo pcap con una ventana de tamaño definido.")

# Definir los argumentos
parser.add_argument("pcap_file", type=str, help="Ruta del archivo pcap a analizar")
parser.add_argument("--size_of_window", type=int, default=10, help="Tamaño de la ventana en paquetes (por defecto: 10)")
parser.add_argument("--mode", type=str, choices=["combinada", "paquetes", "ventana", "flujos", "all"],
                    default="all", help="mode de análisis (combinada, paquetes, ventana, flujos, all). Por defecto: all")
parser.add_argument("--output_dir", type=str, default=".",
                    help="Carpeta donde se escriben los CSV (por defecto: la carpeta actual)")
parser.add_argument("--disable_smb_dissection", action="store_true", help="Disables dissection of SMB packets.\nNone of the outputs are needed for the analysis, but enabling this setting can significantly shorten processing time when heavy SMB traffic is appearing in PCAPs.")

# Parsear los argumentos
args = parser.parse_args()

# Definir variables
size_of_window = args.size_of_window
mode = args.mode
pcap_file = args.pcap_file
# Extraer el nombre base del archivo pcap sin la extensión
#pcap_base_name = os.path.splitext(pcap_file)[0]
# Definir el nombre del CSV principal a partir del pcap
#output_base = f"{pcap_base_name}.csv"
# Extraer el nombre base del archivo de salida sin la extensión
#output_base_name = os.path.splitext(output_base)[0]
output_base_name = os.path.basename(pcap_file).replace(".pcap", "")

# Generar nombres personalizados para los otros CSVs
os.makedirs(args.output_dir, exist_ok=True)
output_csv = os.path.join(args.output_dir, f"paquetes_{output_base_name}.csv")
output_stats = os.path.join(args.output_dir, f"estadisticas_ventanas_{output_base_name}.csv")
output_flow_stats = os.path.join(args.output_dir, f"estadisticas_flujo_{output_base_name}.csv")
output_combined_stats = os.path.join(args.output_dir, f"estadisticas_combinadas_{output_base_name}.csv")

# Nueva gestión de flujos usando un diccionario
flows = {}

# 1. Ejecutar tshark para extraer los datos del pcap a un archivo CSV
def run_tshark(pcap_file, output_csv):
    command = [
        "tshark", "-r", pcap_file, "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto", "-e", "frame.len", "-e", "tcp.flags",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.len", "-e", "udp.length", "-e", "tcp.hdr_len",
        "-e", "udp.srcport", "-e", "udp.dstport", "-e", "eth.type", "-e", "llc.control",
        "-e", "frame.time_epoch", "-e", "ip.ttl", "-e", "ip.hdr_len",
        "-e", "tcp.analysis.initial_rtt", "-e", "tcp.connection.fin", "-e", "tcp.connection.syn", "-e", "tcp.flags.cwr", "-e", "tcp.flags.ece",
        "-e", "tcp.urgent_pointer", "-e", "ip.frag_offset", "-e", "eth.src_not_group",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"
    ]

    if args.disable_smb_dissection:
        command += ["--disable-protocol", "smb,smb2"]  # Disables the dissection of SMB protocols.

    with open(output_csv, 'w') as f:
        try:
            subprocess.run(command, stdout=f, check=True)
        except subprocess.CalledProcessError:
            print("Error ejecutando tshark. Verifica los campos seleccionados.")

# 2. Procesar ventanas de 10 paquetes
def process_windows(df, window_size=size_of_window):
    df.fillna(0, inplace=True)

    # Identificar protocolos basados en puertos
    def check_protocol(row, ports):
        return 1 if row['tcp.srcport'] in ports or row['tcp.dstport'] in ports or row['udp.srcport'] in ports or row['udp.dstport'] in ports else 0

    df['HTTP'] = df.apply(lambda row: check_protocol(row, [80]), axis=1)
    df['HTTPS'] = df.apply(lambda row: check_protocol(row, [443]), axis=1)
    df['DNS'] = df.apply(lambda row: check_protocol(row, [53]), axis=1)
    df['Telnet'] = df.apply(lambda row: check_protocol(row, [23]), axis=1)
    df['SMTP'] = df.apply(lambda row: check_protocol(row, [25]), axis=1)
    df['SSH'] = df.apply(lambda row: check_protocol(row, [22]), axis=1)
    df['IRC'] = df.apply(lambda row: check_protocol(row, [6667]), axis=1)
    df['TCP'] = df.apply(lambda row: 1 if row['tcp.srcport'] > 0 or row['tcp.dstport'] > 0 else 0, axis=1)
    df['UDP'] = df.apply(lambda row: 1 if row['udp.srcport'] > 0 or row['udp.dstport'] > 0 else 0, axis=1)
    df['tcp_analysis_initial_rtt'] = df['tcp.analysis.initial_rtt']
    df['tcp_connection_fin'] = df['tcp.connection.fin']
    df['tcp_connection_syn'] = df['tcp.connection.syn']
    df['tcp_flags_cwr'] = df['tcp.flags.cwr']
    df['tcp_flags_ece'] = df['tcp.flags.ece']
    df['TCP_Urgent_Pointer'] = df['tcp.urgent_pointer'].astype(float)  # Puntero de datos urgentes en TCP  
     

    # Protocolos ARP, ICMP e IGMP directamente de ip.proto
    if 'ip.proto' in df.columns:
        df['ARP'] = df['ip.proto'].apply(lambda x: 1 if str(x) == 'ARP' else 0)
        df['ICMP'] = df['ip.proto'].apply(lambda x: 1 if str(x) == '1' else 0)  # ICMP es 1 en ip.proto
        df['IGMP'] = df['ip.proto'].apply(lambda x: 1 if str(x) == '2' else 0)  # IGMP es 2 en ip.proto
    df['ip.frag_offset'] = pd.to_numeric(df['ip.frag_offset'], errors='coerce')
    df['IP_Frag_Offset'] = df['ip.frag_offset'].astype(float) 
    df['ETH_Src_Not_Group'] = df['eth.src_not_group'].astype(int)  # ¿Origen no pertenece a grupo de red? (0 o 1) 
    df['ETH_Src_Not_Group'] = pd.to_numeric(df['ETH_Src_Not_Group'], errors='coerce')
    df['ETH_Src_Not_Group'] = df['ETH_Src_Not_Group'].fillna(0)

    # Calcular la duración de la ventana (diferencia entre el primer y último timestamp de la ventana)
    #df['frame.time'] = pd.to_datetime(df['frame.time'])
    df["frame.time_epoch"] = pd.to_datetime(df["frame.time_epoch"], unit="s")
    df['Window'] = df.index // window_size

    # Calcular la duración total de la ventana (diferencia entre el primer y último paquete)
    df['window_start_time'] = df.groupby('Window')['frame.time_epoch'].transform('min')
    df['window_end_time'] = df.groupby('Window')['frame.time_epoch'].transform('max')
    df['Duration'] = (df['window_end_time'] - df['window_start_time']).dt.total_seconds()

    # Función para extraer los flags TCP correctamente
    def extract_tcp_flags(flag_value):
        try:
            flags = int(flag_value, 16)
            return {
                'fin': (flags & 0x01) > 0,  # FIN flag
                'syn': (flags & 0x02) > 0,  # SYN flag
                'rst': (flags & 0x04) > 0,  # RST flag
                'psh': (flags & 0x08) > 0,  # PSH flag
                'ack': (flags & 0x10) > 0,  # ACK flag
                'ece': (flags & 0x40) > 0,  # ECE flag
                'cwr': (flags & 0x80) > 0   # CWR flag
            }
        except (ValueError, TypeError):
            return { 'fin': False, 'syn': False, 'rst': False, 'psh': False, 'ack': False, 'ece': False, 'cwr': False }

    # Extraer los flags TCP como columnas  
    tcp_flags = df['tcp.flags'].apply(lambda x: extract_tcp_flags(x))
    flags_df = pd.json_normalize(tcp_flags)
    flags_df = flags_df.astype(int) 
    df = pd.concat([df, flags_df], axis=1)

    # Calcular el número de paquetes por ventana contando los paquetes
    df['Number'] = df.groupby('Window')['frame.len'].transform('count')

    # Calcular ttl
    df['TTL'] = pd.to_numeric(df['ip.ttl'], errors='coerce')

    # Calcular la tasa de transmisión de paquetes: número de paquetes / duración en segundos
    df['Rate'] = df['Number'] / df['Duration']  # Tasa de paquetes por segundo

    # Filtrar paquetes IPv4 usando la presencia de direcciones IP de origen y destino
    df['IPV4'] = df['eth.type'].apply(lambda x: 1 if str(x).strip().lower() == '0x00000800' or str(x) == '2048' else 0)  
    

    # Filtrar paquetes LLC
    df['LLC'] = df.apply(lambda row: 1 if row['eth.type'] == '0x0000AAAA' or row['llc.control'] == '0x000003' else 0, axis=1)
    # df.apply(lambda row: print(f"eth.type: {row['eth.type']}, llc.control: {row.get('llc.control', 'N/A')}"), axis=1)

    # Calcula la longitud de la cabecera del paquete desde un diccionario de tshark.
    def calculate_header_length(row):

        #ip_header_len = int(row.get("ip.hdr_len", 0) or 0)

        tcp_header_len = int(row.get("tcp.hdr_len", 0) if not pd.isna(row.get("tcp.hdr_len")) else 0)
        udp_header_len = 8 if row.get("udp.length") else 0
        icmp_header_len = 8 if row.get("icmp.type") else 0
        total_len = int(row.get("frame.len", 0) if not pd.isna(row.get("frame.len")) else 0)
        data_len = int(row.get("udp.length", 0) if not pd.isna(row.get("udp.length")) else 0) - 8 if row.get("udp.length") else \
                   int(row.get("tcp.len", 0) if not pd.isna(row.get("tcp.len")) else 0) if "tcp.len" in row else \
                   len(row.get("icmp.data", "")) if "icmp.data" in row else 0

        header_len = (
            tcp_header_len + udp_header_len + icmp_header_len
        )

        return header_len



    # Aplicar la función para calcular la longitud de la cabecera
    df['Header_Length'] = df.apply(calculate_header_length, axis=1)
    # Calcular las estadísticas por ventana y ordenar según el esquema deseado
    stats = df.groupby('Window').agg(
        Header_Length=('Header_Length', 'mean'),
        Protocol_Type=('ip.proto', 'mean'),  # Tipo de protocolo (promedio)
        TTL=('TTL', 'mean'),
        fin_flag_number=('fin', 'mean'),
        syn_flag_number=('syn', 'mean'),
        rst_flag_number=('rst', 'mean'),
        psh_flag_number=('psh', 'mean'),
        ack_flag_number=('ack', 'mean'),
        ece_flag_number=('ece', 'mean'),
        cwr_flag_number=('cwr', 'mean'),
        HTTP=('HTTP', 'mean'),
        HTTPS=('HTTPS', 'mean'),
        DNS=('DNS', 'mean'),
        Telnet=('Telnet', 'mean'),
        SMTP=('SMTP', 'mean'),
        SSH=('SSH', 'mean'),
        IRC=('IRC', 'mean'),
        TCP=('TCP', 'mean'),
        UDP=('UDP', 'mean'),
        DHCP=('ARP', 'mean'),  # Assuming DHCP is tracked under ARP (adjust if needed)
        ARP=('ARP', 'mean'),
        ICMP=('ICMP', 'mean'),
        IGMP=('IGMP', 'mean'),
        IPV4=('IPV4', 'mean'),  
        LLC=('LLC', 'mean'),  # Ajustar si hay identificador específico para LLC
        IAT=('frame.time_epoch', lambda x: (x.diff().mean()).total_seconds()),  # Intervalo medio entre el paquete actual y el anterior
        Tot_size=('frame.len', 'mean'),
        tcp_analysis_initial_rtt =('tcp_analysis_initial_rtt', 'mean'),
        tcp_connection_fin =('tcp_connection_fin', 'mean'),
        tcp_connection_syn =('tcp_connection_syn', 'mean'),
        tcp_flags_cwr =('tcp_flags_cwr', 'mean'),
        tcp_flags_ece =('tcp_flags_ece', 'mean'),
        tcp_urgent_pointer =('TCP_Urgent_Pointer', 'mean'),
        ip_frag_offset =('IP_Frag_Offset', 'mean'),
        eth_src_not_group =('ETH_Src_Not_Group', 'mean'),
    ).reset_index()

    return stats

# Calcula la longitud de la cabecera del paquete desde un diccionario de tshark.
def calculate_header_length(row):

    tcp_header_len = int(row.get("tcp.hdr_len", 0) if not pd.isna(row.get("tcp.hdr_len")) else 0)
    udp_header_len = 8 if row.get("udp.length") else 0
    icmp_header_len = 8 if row.get("icmp.type") else 0
    total_len = int(row.get("frame.len", 0) if not pd.isna(row.get("frame.len")) else 0)
    data_len = int(row.get("udp.length", 0) if not pd.isna(row.get("udp.length")) else 0) - 8 if row.get("udp.length") else \
               int(row.get("tcp.len", 0) if not pd.isna(row.get("tcp.len")) else 0) if "tcp.len" in row else \
               len(row.get("icmp.data", "")) if "icmp.data" in row else 0

    header_len = (tcp_header_len + udp_header_len + icmp_header_len)

    return header_len

# 3. Procesar flujos dentro de ventanas
def process_flows(df, window_size=size_of_window):
    window_flows = {}  # Almacenar los flujos por ventana antes de reiniciarlos
    df['Window'] = df.index // window_size
    tcp_flags = df['tcp.flags'].apply(lambda x: extract_tcp_flags(x))
    flags_df = pd.json_normalize(tcp_flags)
    df = pd.concat([df, flags_df], axis=1)
    for window, group in df.groupby('Window'):
        window_flows[window] = {}  # Guardar los flujos de cada ventana antes de reiniciar
        flows = {}  # Reiniciar los flujos en cada ventana
        srcs, dsts = {}, {}  # Diccionarios para rastrear IPs vistas

        for index, row in group.iterrows():
            header_length = calculate_header_length(row)
            payload_length = row['frame.len']- header_length
            src_ip, dst_ip = row['ip.src'], row['ip.dst']
            src_port, dst_port = row.get('tcp.srcport', 0), row.get('tcp.dstport', 0)
            flow = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
            flow_data = {'byte_count': row['frame.len'], 'ts': pd.to_datetime(row['frame.time_epoch']), 'window': row['Window'], 'tcp_flags': row['tcp.flags'], 'header_length': header_length, 'payload_length': payload_length, 'src_ip': src_ip, 'dst_ip': dst_ip }

            if flow in window_flows[window]:
                window_flows[window][flow].append(flow_data)
            else:
                window_flows[window][flow] = [flow_data]
        
    # Cálculos basados en flujos
    def get_flow_info(window, flow, df):
        packets = window_flows[window][flow]
        bytes = sum(p['byte_count'] for p in packets)
        
        # Obtener las longitudes de los paquetes (byte_count)
        packet_lengths = [p['byte_count'] for p in packets]
        payload_bytes = sum(p['payload_length'] for p in packets)
        header_bytes = sum(p['header_length'] for p in packets)
        
   
        # Calcular las métricas de longitud de los paquetes
        min_length = np.min(packet_lengths) if packet_lengths else 0
        max_length = np.max(packet_lengths) if packet_lengths else 0
        avg_length = np.mean(packet_lengths) if packet_lengths else 0
        std_length = np.std(packet_lengths) if packet_lengths else 0
        # Duración del flujo
        times = sorted(p['ts'].timestamp() for p in packets)
        duration = times[-1] - times[0] if len(times) > 1 else 0
        # Información sobre el flujo
        window = packets[0]['window']
        num_packets = len(packets)
        # Calcular tasas
        rate = len(packets) / duration if duration > 0 else 0
        src_to_dst_pkt = sum(1 for p in packets if (p['byte_count'] > 0))  # Simplificada
        dst_to_src_pkt = len(packets) - src_to_dst_pkt
        srate = src_to_dst_pkt / duration if duration > 0 else 0
        drate = dst_to_src_pkt / duration if duration > 0 else 0
        # Contar flags TCP
        ack_count = sum(1 for p in packets if extract_tcp_flags(p['tcp_flags'])['ack']) 
        syn_count = sum(1 for p in packets if extract_tcp_flags(p['tcp_flags'])['syn']) 
        fin_count = sum(1 for p in packets if extract_tcp_flags(p['tcp_flags'])['fin']) 
        rst_count = sum(1 for p in packets if extract_tcp_flags(p['tcp_flags'])['rst'])  
        # División de paquetes entrantes y salientes
        incoming_pack, outgoing_pack = [], []
        orig_bytes, resp_bytes = 0, 0
        orig_pkts, resp_pkts = 0, 0
        fwd_pkts_tot, bwd_pkts_tot = 0, 0
        fwd_data_pkts_tot, bwd_data_pkts_tot = 0, 0
        fwd_header_size, bwd_header_size = 0, 0
        flow_pkts_payload, fwd_pkts_payload, bwd_pkts_payload = 0, 0, 0
        fwd_timestamps, bwd_timestamps, flow_timestamps = [], [], []
        for p in packets:
            src, dst, ethernet_frame_size, payload, header = p['src_ip'], p['dst_ip'], p['byte_count'], p['payload_length'], p['header_length']
            timestamp = p['ts'].timestamp()
            flow_timestamps.append(timestamp)
            flow_pkts_payload += 1
            if src in dsts:
                outgoing_pack.append(ethernet_frame_size)
                fwd_pkts_tot += 1
                fwd_pkts_payload += payload
                fwd_header_size += header
                orig_bytes += payload
                orig_pkts += 1
                fwd_timestamps.append(timestamp)  # Paquete saliente
            else:
                dsts[src] = 1
                outgoing_pack.append(ethernet_frame_size)

            if dst in srcs:
                incoming_pack.append(ethernet_frame_size)
                bwd_pkts_tot += 1
                bwd_pkts_payload += payload
                bwd_header_size += header
                resp_bytes += payload
                resp_pkts += 1
                bwd_timestamps.append(timestamp)  # Paquete entrante
            else:
                srcs[dst] = 1
                incoming_pack.append(ethernet_frame_size)

        # Calcular tiempos de llegada inter-arrival (IAT)
        fwd_iat = np.mean(np.diff(sorted(fwd_timestamps))) if len(fwd_timestamps) > 1 else 0
        bwd_iat = np.mean(np.diff(sorted(bwd_timestamps))) if len(bwd_timestamps) > 1 else 0
        flow_iat = np.mean(np.diff(sorted(flow_timestamps))) if len(flow_timestamps) > 1 else 0
        # Calcular paquetes por segundo
        fwd_pkts_per_sec = fwd_pkts_tot / duration if duration > 0 else 0
        bwd_pkts_per_sec = bwd_pkts_tot / duration if duration > 0 else 0
        flow_pkts_per_sec = num_packets / duration if duration > 0 else 0

        # Cálculos dinámicos
        magnite, radius, covariance, var_ratio, weight = dynamic_two_streams(incoming_pack, outgoing_pack)
       
        return (
            flow,                       # Informacion Ip, puertos destino y origen
            window,                     # Ventana a la que pertenece el flujo
            bytes,                      # Total de bytes en el flujo
            min_length,                 # Tamaño mínimo de los paquetes en el flujo
            max_length,                 # Tamaño máximo de los paquetes en el flujo
            avg_length,                 # Tamaño promedio de los paquetes en el flujo
            std_length,                 # Desviación estándar del tamaño de paquetes
            num_packets,                # Número total de paquetes en el flujo
            rate,                       # Tasa de paquetes por segundo en el flujo
            srate,                      # Tasa de paquetes forward por segundo
            drate,                      # Tasa de paquetes backward por segundo
            magnite,                    # Métrica dinámica
            radius,                     # Métrica dinámica
            covariance,                 # Métrica dinámica
            var_ratio,                  # Métrica dinámica
            weight,                     # Métrica dinámica
            ack_count,                  # Cantidad de paquetes con flag ACK
            syn_count,                  # Cantidad de paquetes con flag SYN
            fin_count,                  # Cantidad de paquetes con flag FIN
            rst_count,                  # Cantidad de paquetes con flag RST
            orig_bytes,                 # Bytes enviados por el originador
            resp_bytes,                 # Bytes enviados por el respondedor
            orig_pkts,                  # Paquetes enviados por el originador
            resp_pkts,                  # Paquetes enviados por el respondedor
            flow_timestamps,            # Duración del flujo en segundos
            fwd_timestamps,             # Duración del flujo de salida en segundos
            bwd_timestamps,             # Duración del flujo de entrada en segundos
            fwd_pkts_tot,               # Total de paquetes forward
            bwd_pkts_tot,               # Total de paquetes backward
            fwd_data_pkts_tot,          # Total de paquetes de datos forward
            bwd_data_pkts_tot,          # Total de paquetes de datos backward
            fwd_pkts_per_sec,           # Tasa de paquetes forward por segundo
            bwd_pkts_per_sec,           # Tasa de paquetes backward por segundo
            flow_pkts_per_sec,          # Tasa de paquetes totales en el flujo
            fwd_header_size,            # Tamaño total de headers forward
            bwd_header_size,            # Tamaño total de headers backward
            fwd_pkts_payload,           # Total de bytes de payload forward
            bwd_pkts_payload,           # Total de bytes de payload backward
            flow_pkts_payload,          # Total de bytes de payload en el flujo
            fwd_iat,                    # Tiempo de llegada entre paquetes forward
            bwd_iat,                    # Tiempo de llegada entre paquetes backward
            flow_iat                    # Tiempo de llegada entre cualquier paquete del flujo
        )



    def dynamic_two_streams(incoming, outgoing):
        inco_ave = sum(incoming) / len(incoming) if len(incoming) > 0 else 0
        outgoing_ave = sum(outgoing) / len(outgoing) if len(outgoing) > 0 else 0
        magnite = (inco_ave + outgoing_ave) ** 0.5

        inco_var = np.var(incoming) if len(incoming) > 0 else 0
        outgo_var = np.var(outgoing) if len(outgoing) > 0 else 0
        radius = (inco_var + outgo_var) ** 0.5
       

        covariance = sum((a - inco_ave) * (b - outgoing_ave) for (a, b) in zip(incoming, outgoing)) / len(incoming) if len(incoming) > 0 else 0
        var_ratio = inco_var / outgo_var if outgo_var != 0 else 0
        weight = len(incoming) * len(outgoing)

        return magnite, radius, covariance, var_ratio, weight


    # Crear DataFrame de estadísticas con medias de los flows
    flow_stats = []
    for window in window_flows:
        for flow in window_flows[window]:
                flow, window, bytes, min_length, max_length, avg_length, std_length, num_packets, rate, srate, drate, magnite, radius, covariance, var_ratio, weight, ack_count, syn_count, fin_count, rst_count, orig_bytes, resp_bytes, orig_pkts, resp_pkts, flow_timestamps, fwd_timestamps, bwd_timestamps, fwd_pkts_tot, bwd_pkts_tot, fwd_data_pkts_tot, bwd_data_pkts_tot, fwd_pkts_per_sec, bwd_pkts_per_sec, flow_pkts_per_sec, fwd_header_size, bwd_header_size, fwd_pkts_payload, bwd_pkts_payload, flow_pkts_payload, fwd_iat, bwd_iat, flow_iat = get_flow_info(window, flow, df)

                flow_stats.append([window,flow, rate, srate, drate, ack_count, syn_count, fin_count, rst_count, bytes, min_length, max_length, avg_length, std_length, num_packets, magnite, radius, covariance, var_ratio, weight, orig_bytes, resp_bytes, orig_pkts, resp_pkts, flow_timestamps, fwd_timestamps, bwd_timestamps, fwd_pkts_tot, bwd_pkts_tot, fwd_data_pkts_tot, bwd_data_pkts_tot, fwd_pkts_per_sec, bwd_pkts_per_sec, flow_pkts_per_sec, fwd_header_size, bwd_header_size, fwd_pkts_payload, bwd_pkts_payload, flow_pkts_payload, fwd_iat, bwd_iat, flow_iat])

                columns = ['Window', 'flow', 'Rate', 'Srate', 'Drate', 'ack_count', 'syn_count', 'fin_count', 'rst_count', 'Bytes', 'Min_Length', 'Max_Length', 'Avg_Length', 'Std_Length', 'Number', 'Magnite', 'Radius', 'Covariance', 'Var_Ratio', 'Weight', 'Orig_Bytes', 'Resp_Bytes', 'Orig_Pkts', 'Resp_Pkts', 'flow_timestamps', 'fwd_timestamps', 'bwd_timestamps', 'Fwd_Pkts_Tot', 'Bwd_Pkts_Tot', 'Fwd_Data_Pkts_Tot', 'Bwd_Data_Pkts_Tot', 'Fwd_Pkts_Per_Sec', 'Bwd_Pkts_Per_Sec', 'Flow_Pkts_Per_Sec', 'Fwd_Header_Size', 'Bwd_Header_Size', 'Fwd_Pkts_Payload', 'Bwd_Pkts_Payload', 'Flow_Pkts_Payload', 'Fwd_IAT', 'Bwd_IAT', 'Flow_IAT']


    stats_flow_df = pd.DataFrame(flow_stats, columns=columns)  
    
    return stats_flow_df

def extract_tcp_flags(flag_value):
    if flag_value is None: 
        return { 'fin': False, 'syn': False, 'rst': False, 'ack': False }  
    try:
        #print(f"Valor de tcp.flags {flag_value}")
        flags = int(flag_value, 16)
        return {
            'fin': (flags & 0x01) > 0,  # FIN flag
            'syn': (flags & 0x02) > 0,  # SYN flag
            'rst': (flags & 0x04) > 0,  # RST flag
            'ack': (flags & 0x10) > 0,  # ACK flag
        }
    except (ValueError, TypeError):
        #print(f"Error al procesar los flags")
        return { 'fin': False, 'syn': False, 'rst': False, 'ack': False }

# 4. Procesar el pcap y guardar resultados según el mode seleccionado
def process_pcap(pcap_file, output_csv, output_stats, output_flow_stats, output_combined_stats, mode):
    run_tshark(pcap_file, output_csv)
    #df = pd.read_csv(output_csv, low_memory=False)
    chunksize = 200_000  # Ajustad según vuestra RAM, podéis probar 50_000 si sigue fallando

    chunks = []
    for chunk in pd.read_csv(output_csv, chunksize=chunksize, low_memory=False):
        chunks.append(chunk)

    df = pd.concat(chunks, ignore_index=True)
    if mode in ["paquetes", "all"]:
        # Guardar el CSV de paquetes tal cual
        df.to_csv(output_csv, index=False)

        print(f"Archivo de paquetes guardado en {output_csv}")

    if mode in ["combinada", "flujos", "ventana", "all"]:
        first_chunk_ven = True
        first_chunk_Comb = True
        first_chunk_fluj = True
        for chunk in pd.read_csv(output_csv, chunksize=200_000, low_memory=False):
            if mode in ["combinada", "flujos", "all"]:
                # Calcular estadísticas de flujos y agregarlas por ventana
                stats_flow = process_flows(chunk, window_size=size_of_window)
                if mode in ["flujos", "all"]:
                    # Guardar estadísticas de flows
                    stats_flow.to_csv(output_flow_stats, mode='w' if first_chunk_fluj else 'a', index=False, header=first_chunk_fluj)
                    first_chunk_fluj = False
                if mode in ["combinada", "all"]:
                    stats_window_avg_df = stats_flow.groupby('Window', as_index=False).mean(numeric_only=True)
            if mode in ["combinada", "ventana", "all"]:
                # Calcular estadísticas por ventana
                stats_window = process_windows(chunk, window_size=size_of_window)
                if mode in ["ventana", "all"]:
                    stats_window.to_csv(output_stats, mode='w' if first_chunk_ven else 'a', index=False, header=first_chunk_ven)
                    first_chunk_ven = False
                if mode in ["combinada", "all"]:
                    # Combinar ambas estadísticas por 'Window'
                    combined_stats = stats_window.merge(stats_window_avg_df, on='Window', how='left')
            if mode in ["combinada", "all"]:
                # Guardar al CSV
                combined_stats.to_csv(output_combined_stats, mode='w' if first_chunk_Comb else 'a',index=False, header=first_chunk_Comb)
                first_chunk_Comb = False

        print(f"Estadísticas por ventana guardadas en {output_stats}")
        print(f"Estadísticas por flujo guardadas en {output_flow_stats}")
        print(f"Estadísticas combinadas guardadas en {output_combined_stats}")

process_pcap(pcap_file, output_csv, output_stats, output_flow_stats, output_combined_stats, mode)



"""
    if mode in ["ventana", "all"]:
        first_chunk = True
        for chunk in pd.read_csv(output_csv, chunksize=100_000, low_memory=False):
            stats = process_windows(chunk, window_size=size_of_window)
            stats.to_csv(output_stats, mode='w' if first_chunk else 'a', index=False, header=first_chunk)
            first_chunk = False

        print(f"Estadísticas por ventana guardadas en {output_stats}")


    if mode in ["flujos", "all"]:
        first_chunk = True
        for chunk in pd.read_csv(output_csv, chunksize=100_000, low_memory=False):
            # Procesar flows por chunk (reinicia cada vez)
            stats_flow = process_flows(chunk, window_size=size_of_window)
            # Guardar estadísticas de flows
            stats_flow.to_csv(output_flow_stats, mode='w' if first_chunk else 'a', index=False, header=first_chunk)
            first_chunk = False

        print(f"Estadísticas por flujo guardadas en {output_flow_stats}")
"""
