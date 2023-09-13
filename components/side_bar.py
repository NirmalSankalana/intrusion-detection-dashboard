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
        0, 1, 2, 3
    )

    # Feature 15
    tcp_connection_rst = st.sidebar.selectbox(
        "tcp.connection.rst",
        (0, 1)
    )
    return arp_opcode, arp_hw_size, icmp_checksum, icmp_seq_le, icmp_unused, http_content_length, http_request_method, http_referer, http_request_version, http_response, http_tls_port, tcp_ack, tcp_ack_raw, tcp_checksum, tcp_connection_fin, tcp_connection_rst
