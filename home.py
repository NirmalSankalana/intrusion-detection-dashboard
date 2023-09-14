import streamlit as st
import numpy as np


from components.side_bar import side_bar

#services
from services.load_data import load_data, filter_data
from services.get_description import get_description

# graphs
from graphs.threed_plot import plot_3d
from graphs.bar_graph import bar_graph, create_attact_count_dataframe

# model
from services.get_prediction import get_prediction

def main():
    st.title("Network Attack Detection")
    st.caption("Attack detection system")
    df = load_data()

    arp_opcode, arp_hw_size, icmp_checksum, icmp_seq_le, icmp_unused, http_content_length, http_request_method, http_referer, http_request_version, http_response, http_tls_port, tcp_ack, tcp_ack_raw, tcp_checksum, tcp_connection_fin, tcp_connection_rst, tcp_connection_syn, tcp_connection_synack, tcp_flags, tcp_flags_ack, tcp_len, tcp_seq, udp_stream, udp_time_delta, dns_qry_name, dns_qry_name_len, dns_qry_qu, dns_qry_type, dns_retransmission, dns_retransmit_request, dns_retransmit_request_in, mqtt_conack_flags, mqtt_conflag_cleansess, mqtt_conflags, mqtt_hdrflags, mqtt_len, mqtt_msg_decoded_as, mqtt_msgtype, mqtt_proto_len, mqtt_protoname, mqtt_topic, mqtt_topic_len, mqtt_ver, mbtcp_len, mbtcp_trans_id, mbtcp_unit_id, Attack_label = side_bar()

    input_data = [arp_opcode, arp_hw_size, icmp_checksum, icmp_seq_le, icmp_unused, http_content_length, http_request_method, http_referer, http_request_version, http_response, http_tls_port, tcp_ack, tcp_ack_raw, tcp_checksum, tcp_connection_fin, tcp_connection_rst, tcp_connection_syn, tcp_connection_synack, tcp_flags, tcp_flags_ack, tcp_len, tcp_seq, udp_stream, udp_time_delta, dns_qry_name, dns_qry_name_len, dns_qry_qu, dns_qry_type, dns_retransmission, dns_retransmit_request, dns_retransmit_request_in, mqtt_conack_flags, mqtt_conflag_cleansess, mqtt_conflags, mqtt_hdrflags, mqtt_len, mqtt_msg_decoded_as, mqtt_msgtype, mqtt_proto_len, mqtt_protoname, mqtt_topic, mqtt_topic_len, mqtt_ver, mbtcp_len, mbtcp_trans_id, mbtcp_unit_id, Attack_label]  

    input_data_2d = np.array(input_data).reshape(1, -1)

    attact_label = get_prediction(input_data_2d)

    # Display the attack type with different colors
    st.subheader("Attact Type: ")
    if attact_label[0] == "Normal":
        st.success("Normal")
    else:
        st.error(f"{attact_label[0]}")

    st.write("Accuracy: 93")

    df = load_data()
    get_description(df)


    # filters = {
    #     'arp.opcode': arp_opcode, 'arp.hw.size': arp_hw_size, 'icmp.checksum': icmp_checksum, 'icmp.seq_le': icmp_seq_le, 'icmp.unused': icmp_unused, 'http.content_length': http_content_length, 'http.request.method': http_request_method, 'http.referer': http_referer, 'http.request.version': http_request_version, 'http.response': http_response, 'http.tls_port': http_tls_port, 'tcp.ack': tcp_ack, 'tcp.ack_raw': tcp_ack_raw, 'tcp.checksum': tcp_checksum, 'tcp.connection.fin': tcp_connection_fin, 'tcp.connection.rst': tcp_connection_rst, 'tcp.connection.syn': tcp_connection_syn, 'tcp.connection.synack': tcp_connection_synack, 'tcp.flags': tcp_flags, 'tcp.flags.ack': tcp_flags_ack, 'tcp.len': tcp_len, 'tcp.seq':tcp_seq, 'udp.stream': udp_stream, 'udp.time_delta': udp_time_delta, 'dns.qry.name': dns_qry_name, 'dns.qry.name.len': dns_qry_name_len, 'dns.qry.qu': dns_qry_qu, 'dns.qry.type': dns_qry_type, 'dns.retransmission': dns_retransmission, 'dns.retransmit_request': dns_retransmit_request, 'dns.retransmit_request_in': dns_retransmit_request_in, 'mqtt.conack.flags': mqtt_conack_flags, 'mqtt.conflag.cleansess': mqtt_conflag_cleansess, 'mqtt.conflags': mqtt_conflags, 'mqtt.hdrflags': mqtt_hdrflags, 'mqtt.len': mqtt_len, 'mqtt.msg_decoded_as': mqtt_msg_decoded_as, 'mqtt.msgtype': mqtt_msgtype,
    #    'mqtt.proto_len': mqtt_proto_len, 'mqtt.protoname': mqtt_protoname, 'mqtt.topic': mqtt_topic, 'mqtt.topic_len': mqtt_topic_len, 'mqtt.ver': mqtt_ver, 'mbtcp.len': mbtcp_len, 'mbtcp.trans_id': mbtcp_trans_id, 'mbtcp.unit_id': mbtcp_unit_id, 'Attack_label': Attack_label
    # }
   

    attack_type_counts = df['Attack_type'].value_counts().reset_index()
    attack_type_counts.columns = ['Attack_type', 'Count']

    # Display the DataFrame with counts
    attact_type_counts = create_attact_count_dataframe(df)
    bar_graph(attack_type_counts)



if __name__ == "__main__":
    main()
