import streamlit as st

def side_bar():
    arp_opcode = st.sidebar.selectbox(
        "arp.opcode",
        (0.0, 0.5, 1.0)
    )

    arp_hw_size = st.sidebar.selectbox(
        "arp.hw.size",
        (0.0, 1.0)
    )

    icmp_checksum = st.sidebar.slider(
        'icmp.checksum',
        0.0, 1.0)
    return arp_opcode, arp_hw_size, icmp_checksum
