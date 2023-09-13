import streamlit as st

from components.side_bar import side_bar
from services.load_data import load_data, filter_data


def main():
    st.title("Network Attack Detection")
    st.caption("Attack detection system")
    df = load_data()

    arp_opcode, arp_hw_size, icmp_checksum = side_bar()
    st.write(arp_opcode, arp_hw_size, icmp_checksum)
    df = load_data()
    filtered_df = filter_data(df, arp_opcode, arp_hw_size, icmp_checksum)
    st.write(filtered_df)


if __name__ == "__main__":
    main()
