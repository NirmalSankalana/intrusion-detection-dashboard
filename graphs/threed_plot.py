import streamlit as st

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