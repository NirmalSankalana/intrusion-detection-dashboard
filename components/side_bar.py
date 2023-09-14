import streamlit as st


def side_bar():
    # Feature 0
    arp_opcode = st.sidebar.selectbox(
        "arp.opcode",
        (0.0, 0.5, 1.0)
    )

    # Feature 1
    arp_hw_size = st.sidebar.selectbox(
        "arp.hw.size",
        (0.0, 1.0)
    )

    # Feature 2
    icmp_checksum = st.sidebar.slider(
        'icmp.checksum',
        0.0, 1.0)

    # Feature 3
    icmp_seq_le = st.sidebar.slider(
        'icmp.seq_le',
        0.0, 1.0)

    # Feature 4
    icmp_unused = st.sidebar.selectbox(
        'icmp.unused',
        (0.0, 1.0)
    )

    # Feature 5
    http_content_length = st.sidebar.slider(
        "http.content_length",
        0.0, 1.0
    )

    # Feature 6
    http_request_method = st.sidebar.selectbox(
        "http.request.method",
        (0.0, 0.2, 0.4, 0.6, 0.8, 1.0)
    )

    # Feature 7
    http_referer = st.sidebar.slider(
        "http.referer",
        0.0, 1.0
    )

    # Feature 8
    http_request_version = st.sidebar.slider(
        "http.request.version",
        0.0, 1.0
    )

    # Feature 9
    http_response = st.sidebar.selectbox(
        "http.response",
        (0.0, 1.0)
    )

    # Feature 10
    http_tls_port = st.sidebar.slider(
        "http.tls_port",
        0.0, 1.0
    )

    # Feature 11
    tcp_ack = st.sidebar.slider(
        'tcp.ack',
        0.0, 1.0)

    # Feature 12
    tcp_ack_raw = st.sidebar.slider(
        'tcp.ack_raw',
        0.0, 1.0)

    # Feature 13
    tcp_checksum = st.sidebar.slider(
        'tcp.checksum',
        0.0, 1.0)

    # Feature 14
    tcp_connection_fin = st.sidebar.slider(
        "tcp.connection.fin",
        0.0, 1.0
    )

    # Feature 15
    tcp_connection_rst = st.sidebar.selectbox(
        "tcp.connection.rst",
        (0, 1)
    )

    # Feature 16
    tcp_connection_syn = st.sidebar.selectbox(
        "tcp.connection.syn",
        (0, 1)
    )

    # Feature 17
    tcp_connection_synack = st.sidebar.selectbox(
        "tcp.connection.synack",
        (0, 1)
    )

    # Feature 18
    tcp_flags = st.sidebar.slider(
        'tcp.flags',
        0.0, 1.0)

    # Feature 19
    tcp_flags_ack = st.sidebar.selectbox(
        "tcp.flags.ack",
        (0, 1)
    )

    # Feature 20
    tcp_len	 = st.sidebar.slider(
        'tcp.len',
        0.0, 1.0)
    
    # Feature 21
    tcp_seq	 = st.sidebar.slider(
        'tcp.seq',
        0.0, 1.0)
    
    # Feature 22
    udp_stream	 = st.sidebar.slider(
        'udp.stream',
        0.0, 1.0)
    
    # Feature 23
    udp_time_delta = st.sidebar.slider(
        'udp.time_delta',
        0.0, 1.0)
    
    # Feature 24
    dns_qry_name = st.sidebar.slider(
        'dns.qry.name',
        0.0, 1.0)
    
    # Feature 25
    dns_qry_name_len = st.sidebar.slider(
        'dns.qry.name.len',
        0.0, 1.0)
    
    # Feature 26
    dns_qry_qu = st.sidebar.slider(
        'dns.qry.qu',
        0.0, 1.0)
    
    # Feature 27
    dns_qry_type = st.sidebar.slider(
        'dns.qry.type',
        0.0, 1.0)
    
    # Feature 28
    dns_retransmission = st.sidebar.slider(
        'dns.retransmission',
        0.0, 1.0)
    
    # Feature 29
    dns_retransmit_request = st.sidebar.selectbox(
        "dns.retransmit_request	",
        (0, 1)
    )

    # Feature 30
    dns_retransmit_request_in = st.sidebar.slider(
        'dns.retransmit_request_in',
        0.0, 1.0)
    
    # Feature 31
    mqtt_conack_flags = st.sidebar.selectbox(
        "mqtt.conack.flags",
        (0.0, 0.5, 1.0)
    )

    # Feature 32
    mqtt_conflag_cleansess = st.sidebar.selectbox(
        "mqtt.conflag.cleansess",
        (0.0, 1.0)
    )

    # Feature 33
    mqtt_conflags = st.sidebar.selectbox(
        "mqtt.conflags",
        (0.0, 1.0)
    )

    # Feature 34
    mqtt_hdrflags = st.sidebar.selectbox(
        "mqtt.hdrflags",
        (0.0, 0.25, 0.5, 0.75, 1.0)
    )

    # Feature 35
    mqtt_len = st.sidebar.slider(
        'mqtt.len',
        0.0, 1.0)
    
    # Feature 36
    mqtt_msg_decoded_as = st.sidebar.slider(
        'mqtt.msg_decoded_as',
        0.0, 1.0)
    
    # Feature 37
    mqtt_msgtype = st.sidebar.selectbox(
        "mqtt.msgtype",
        (0.0, 0.25, 0.5, 0.75, 1.0)
    )

    # Feature 38
    mqtt_proto_len = st.sidebar.selectbox(
        "mqtt.proto_len",
        (0.0, 1.0)
    )

    # Feature 39
    mqtt_protoname = st.sidebar.selectbox(
        "mqtt.protoname",
        (0.0, 0.5, 1.0)
    )

    # Feature 40
    mqtt_topic = st.sidebar.selectbox(
        "mqtt.topic",
        (0.0, 0.5, 1.0)
    )

    # Feature 41
    mqtt_topic_len = st.sidebar.selectbox(
        "mqtt.topic_len",
        (0.0, 1.0)
    )

    # Feature 42
    mqtt_ver = st.sidebar.selectbox(
        "mqtt.ver",
        (0.0, 1.0)
    )

    # Feature 43
    mbtcp_len = st.sidebar.slider(
        'mbtcp.len',
        0.0, 1.0)
    
    # Feature 44
    mbtcp_trans_id = st.sidebar.slider(
        'mbtcp.trans_id',
        0.0, 1.0)
    
    # Feature 45
    mbtcp_unit_id = st.sidebar.slider(
        'mbtcp.unit_id',
        0.0, 1.0)
    
    # Feature 46
    Attack_label = st.sidebar.selectbox(
        "Attack_label",
        (0.0, 1.0)
    )

    return arp_opcode, arp_hw_size, icmp_checksum, icmp_seq_le, icmp_unused, http_content_length, http_request_method, http_referer, http_request_version, http_response, http_tls_port, tcp_ack, tcp_ack_raw, tcp_checksum, tcp_connection_fin, tcp_connection_rst, tcp_connection_syn, tcp_connection_synack, tcp_flags, tcp_flags_ack, tcp_len, tcp_seq, udp_stream, udp_time_delta, dns_qry_name, dns_qry_name_len, dns_qry_qu, dns_qry_type, dns_retransmission, dns_retransmit_request, dns_retransmit_request_in, mqtt_conack_flags, mqtt_conflag_cleansess, mqtt_conflags, mqtt_hdrflags, mqtt_len, mqtt_msg_decoded_as, mqtt_msgtype, mqtt_proto_len, mqtt_protoname, mqtt_topic, mqtt_topic_len, mqtt_ver, mbtcp_len, mbtcp_trans_id, mbtcp_unit_id, Attack_label
