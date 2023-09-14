import streamlit as st
import numpy as np

#components
from components.side_bar import side_bar

#services
from services.load_data import load_data, filter_data
from services.get_description import get_description
from services.get_accuracy import x_y_split, get_confusion_matrix

# graphs
from graphs.threed_plot import plot_3d
from graphs.bar_graph import bar_graph, create_attact_count_dataframe

# model
from services.get_prediction import get_prediction

import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

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
    X, y = x_y_split(df)
    y_pred = get_prediction(X)
    get_confusion_matrix(y, y_pred)
    
    get_description(df)

    attack_type_counts = df['Attack_type'].value_counts().reset_index()
    attack_type_counts.columns = ['Attack_type', 'Count']

    # Display the DataFrame with counts
    attact_type_counts = create_attact_count_dataframe(df)
    bar_graph(attack_type_counts)



if __name__ == "__main__":
    main()
