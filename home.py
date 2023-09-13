import streamlit as st

from components.side_bar import side_bar
from services.load_data import load_data, filter_data

import plotly.graph_objects as go
import plotly.express as px


def plot_3d(df, xyzk, title):
    fig = go.Figure(data=[go.Scatter3d(
        x=df[xyzk[0]],
        y=df[xyzk[1]],
        z=df[xyzk[2]],
        mode='markers',
        marker=dict(
            size=5,
            color=df[xyzk[3]],
            colorscale='Viridis',
            opacity=0.8
        ),
        text=df[xyzk[3]]
    )])

    fig.update_layout(
        scene=dict(
            xaxis_title=xyzk[0],
            yaxis_title=xyzk[1],
            zaxis_title=xyzk[2]
        ),
        title=title,
        width=800,
        height=600
    )

    st.plotly_chart(fig)  # Display the Plotly figure in Streamlit


def main():
    st.title("Network Attack Detection")
    st.caption("Attack detection system")
    df = load_data()

    arp_opcode, arp_hw_size, icmp_checksum = side_bar()
    st.write(arp_opcode, arp_hw_size, icmp_checksum)
    df = load_data()
    filtered_df = filter_data(df, arp_opcode, arp_hw_size, icmp_checksum)
    st.write(filtered_df)
    plot_3d(df, ['tcp.checksum', 'icmp.seq_le', 'icmp.checksum',
            'Attack_type'], title='The Plot of the Attack_type')


if __name__ == "__main__":
    main()
