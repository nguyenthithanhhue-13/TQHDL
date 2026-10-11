# Dashboard Streamlit: Trực quan hóa lưu lượng mạng UNSW-NB15
# Chạy:  streamlit run app.py   (đặt file UNSW_NB15_training-set.csv cùng thư mục, hoặc tải lên ở thanh bên)
import os

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title='UNSW-NB15 — Phân tích tấn công mạng', page_icon='🛡️', layout='wide')

ORDER = ['Normal', 'Generic', 'Exploits', 'Fuzzers', 'DoS', 'Reconnaissance',
         'Analysis', 'Backdoor', 'Shellcode', 'Worms']
PALETTE = {'Normal': '#9AA0A6', 'Generic': '#D62728', 'Exploits': '#FF7F0E', 'Fuzzers': '#1F77B4',
           'DoS': '#9467BD', 'Reconnaissance': '#2CA02C', 'Analysis': '#8C564B', 'Backdoor': '#E377C2',
           'Shellcode': '#17BECF', 'Worms': '#BCBD22'}
TOP_PROTO = ['tcp', 'udp', 'unas', 'arp', 'ospf', 'sctp']
LOG_COLS = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sload', 'dload',
            'sinpkt', 'dinpkt', 'sjit', 'djit', 'smean', 'dmean']
RADAR = ['dur', 'sbytes', 'dbytes', 'rate', 'sload', 'smean', 'sttl', 'ct_srv_src', 'ct_dst_src_ltm']
DEFAULT_FILE = 'UNSW_NB15_training-set.csv'


def rgba(hex_color, alpha):
    h = hex_color.lstrip('#')
    return f'rgba({int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)},{alpha})'


@st.cache_data(show_spinner='Đang đọc dữ liệu...')
def load(source):
    df = pd.read_csv(source)
    df = df.drop(columns=[c for c in ['id'] if c in df.columns])
    for c in ['proto', 'service', 'state', 'attack_cat']:
        df[c] = df[c].astype(str).str.strip()
    df['service'] = df['service'].replace('-', 'unknown')
    df['proto_grp'] = np.where(df['proto'].isin(TOP_PROTO), df['proto'], 'hiếm (khác)')
    df['label_name'] = np.where(df['label'] == 1, 'Attack', 'Normal')
    # hạng phần trăm tính trên TOÀN BỘ dữ liệu để spider chart không đổi thang khi lọc
    for c in RADAR:
        df[f'pct_{c}'] = df[c].rank(pct=True)
    return df


# ---------------- Thanh bên: nguồn dữ liệu và bộ lọc ----------------
st.sidebar.title('🛡️ UNSW-NB15')
uploaded = st.sidebar.file_uploader('Tải file CSV (nếu không có sẵn cạnh app.py)', type='csv')
if uploaded is not None:
    data = load(uploaded)
elif os.path.exists(DEFAULT_FILE):
    data = load(DEFAULT_FILE)
elif os.path.exists(os.path.join('data', DEFAULT_FILE)):
    data = load(os.path.join('data', DEFAULT_FILE))
else:
    st.info(f'Hãy đặt `{DEFAULT_FILE}` cùng thư mục với `app.py` hoặc tải file lên ở thanh bên.')
    st.stop()

st.sidebar.header('Bộ lọc')
present = [c for c in ORDER if c in set(data['attack_cat'])]
sel_cat = st.sidebar.multiselect('Loại lưu lượng', present, default=present)
protos = sorted(data['proto_grp'].unique())
sel_proto = st.sidebar.multiselect('Giao thức', protos, default=protos)
services = data['service'].value_counts().index.tolist()
sel_service = st.sidebar.multiselect('Dịch vụ', services, default=services)

df = data[data['attack_cat'].isin(sel_cat) & data['proto_grp'].isin(sel_proto) & data['service'].isin(sel_service)]
if df.empty:
    st.warning('Không có luồng nào khớp bộ lọc.')
    st.stop()

# ---------------- Tiêu đề và KPI ----------------
st.title('Trực quan hóa lưu lượng mạng để phát hiện và phân tích tấn công')
st.caption('Bộ dữ liệu UNSW-NB15 · mỗi dòng là một luồng kết nối · màu của mỗi loại tấn công cố định trên mọi biểu đồ')

attacks = df[df['label'] == 1]
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric('Số luồng', f'{len(df):,}')
k2.metric('Tỉ lệ tấn công', f'{df["label"].mean() * 100:.1f}%')
k3.metric('Số loại tấn công', attacks['attack_cat'].nunique())
k4.metric('Loại phổ biến nhất', attacks['attack_cat'].mode().iat[0] if len(attacks) else '—')
k5.metric('Luồng không có phản hồi', f'{(df["dbytes"] == 0).mean() * 100:.1f}%')

tab1, tab2, tab3, tab4, tab5 = st.tabs(['Tổng quan', 'Giao thức & dịch vụ', 'Đặc trưng', 'Chân dung tấn công', 'Dữ liệu'])

# ---------------- Tab 1: Tổng quan ----------------
with tab1:
    c1, c2 = st.columns([1, 2])
    b = df['label_name'].value_counts().reset_index()
    b.columns = ['Nhãn', 'Số luồng']
    fig = px.pie(b, names='Nhãn', values='Số luồng', hole=0.55, color='Nhãn',
                 color_discrete_map={'Normal': PALETTE['Normal'], 'Attack': PALETTE['Generic']},
                 title='Bình thường và tấn công')
    c1.plotly_chart(fig, use_container_width=True)

    cnt = df['attack_cat'].value_counts().reset_index()
    cnt.columns = ['Loại', 'Số luồng']
    fig = px.bar(cnt.sort_values('Số luồng'), x='Số luồng', y='Loại', orientation='h', color='Loại',
                 color_discrete_map=PALETTE, text_auto=',', title='Phân bố các loại lưu lượng')
    fig.update_layout(showlegend=False, yaxis_title='')
    c2.plotly_chart(fig, use_container_width=True)

    h = df.groupby(['label_name', 'attack_cat', 'service']).size().reset_index(name='n')
    fig = px.treemap(h, path=[px.Constant('Tất cả'), 'label_name', 'attack_cat', 'service'], values='n',
                     color='attack_cat', color_discrete_map={**PALETTE, 'Attack': '#F2B8B5', '(?)': '#FFFFFF'},
                     title='Treemap: Nhãn → Loại tấn công → Dịch vụ')
    fig.update_traces(textinfo='label+percent parent', root_color='white')
    fig.update_layout(height=520, margin=dict(t=50, l=5, r=5, b=5))
    st.plotly_chart(fig, use_container_width=True)

# ---------------- Tab 2: Giao thức & dịch vụ ----------------
with tab2:
    c1, c2 = st.columns(2)
    ct = pd.crosstab(df['proto_grp'], df['attack_cat'], normalize='index').mul(100)
    ct = ct[[c for c in ORDER if c in ct.columns]].reset_index().melt('proto_grp', var_name='Loại', value_name='%')
    fig = px.bar(ct, x='%', y='proto_grp', color='Loại', orientation='h', color_discrete_map=PALETTE,
                 title='Thành phần lưu lượng theo giao thức (100%)')
    fig.update_layout(barmode='stack', yaxis_title='', legend_title='')
    c1.plotly_chart(fig, use_container_width=True)

    hm = pd.crosstab(df['service'], df['attack_cat'], normalize='columns').mul(100)
    hm = hm[[c for c in ORDER if c in hm.columns]]
    fig = px.imshow(hm.round(1), color_continuous_scale='Reds', aspect='auto', text_auto='.0f',
                    title='Mỗi loại tấn công dùng dịch vụ nào? (% theo cột)')
    fig.update_layout(xaxis_title='', yaxis_title='', coloraxis_colorbar_title='%')
    c2.plotly_chart(fig, use_container_width=True)

    # Sankey: giao thức -> dịch vụ -> trạng thái -> loại tấn công
    sk = df.copy()
    top_srv = sk['service'].value_counts().index[:6]
    sk['service_grp'] = np.where(sk['service'].isin(top_srv), sk['service'], 'dịch vụ khác')
    top_st = sk['state'].value_counts().index[:3]
    sk['state_grp'] = np.where(sk['state'].isin(top_st), sk['state'], 'trạng thái khác')
    stages = ['proto_grp', 'service_grp', 'state_grp', 'attack_cat']
    min_flow = max(1, int(len(sk) * 0.001))
    labels, index = [], {}

    def node(stage, value):
        key = (stage, str(value))
        if key not in index:
            index[key] = len(labels)
            labels.append(str(value))
        return index[key]

    src, dst, val, col = [], [], [], []
    for a, b_ in zip(stages[:-1], stages[1:]):
        keys = [a, b_] if b_ == 'attack_cat' else [a, b_, 'attack_cat']
        g = sk.groupby(keys).size().reset_index(name='n')
        for _, r in g[g['n'] >= min_flow].iterrows():
            src.append(node(a, r[a])); dst.append(node(b_, r[b_])); val.append(int(r['n']))
            col.append(rgba(PALETTE.get(r['attack_cat'], '#444444'), 0.45))
    fig = go.Figure(go.Sankey(
        node=dict(label=labels, color=[PALETTE.get(l, '#444444') for l in labels], pad=18, thickness=16),
        link=dict(source=src, target=dst, value=val, color=col)))
    fig.update_layout(title='Sankey: Giao thức → Dịch vụ → Trạng thái → Loại tấn công', height=600)
    st.plotly_chart(fig, use_container_width=True)

# ---------------- Tab 3: Đặc trưng ----------------
with tab3:
    num_cols = [c for c in data.select_dtypes('number').columns if c != 'label' and not c.startswith('pct_')]
    c1, c2, c3 = st.columns([2, 1, 1])
    feat = c1.selectbox('Đặc trưng', num_cols, index=num_cols.index('sbytes') if 'sbytes' in num_cols else 0)
    use_log = c2.checkbox('Thang log10(x + 1)', value=feat in LOG_COLS)
    kind = c3.radio('Kiểu biểu đồ', ['Box', 'Violin'], horizontal=True)

    # lấy mẫu tối đa 3000 luồng mỗi loại để biểu đồ phản hồi nhanh
    samp = df.sample(frac=1, random_state=0).groupby('attack_cat').head(3000).copy()
    samp['value'] = np.log10(samp[feat] + 1) if use_log else samp[feat]
    ylab = f'log10({feat} + 1)' if use_log else feat
    cats = [c for c in ORDER if c in set(samp['attack_cat'])]
    plot = px.box if kind == 'Box' else px.violin
    fig = plot(samp, x='attack_cat', y='value', color='attack_cat', color_discrete_map=PALETTE,
               category_orders={'attack_cat': cats}, title=f'Phân phối của {feat} theo loại lưu lượng')
    fig.update_layout(showlegend=False, xaxis_title='', yaxis_title=ylab)
    st.plotly_chart(fig, use_container_width=True)

    c1, c2 = st.columns(2)
    fig = px.histogram(samp, x='value', color='label_name', barmode='overlay', nbins=60, histnorm='percent',
                       color_discrete_map={'Normal': PALETTE['Normal'], 'Attack': PALETTE['Generic']},
                       title=f'Histogram của {feat}: Normal so với Attack')
    fig.update_layout(xaxis_title=ylab, yaxis_title='% số luồng', legend_title='')
    c1.plotly_chart(fig, use_container_width=True)

    fig = px.density_heatmap(samp.assign(sb=np.log10(samp['sbytes'] + 1), db=np.log10(samp['dbytes'] + 1)),
                             x='sb', y='db', facet_col='label_name', nbinsx=40, nbinsy=40,
                             color_continuous_scale='Reds', title='Byte gửi đi so với byte nhận về')
    fig.update_xaxes(title='log10(sbytes + 1)'); fig.update_yaxes(title='log10(dbytes + 1)', col=1)
    c2.plotly_chart(fig, use_container_width=True)

# ---------------- Tab 4: Chân dung tấn công ----------------
with tab4:
    st.caption('Mỗi trục là hạng phần trăm trung bình (0–1) của đặc trưng, tính trên toàn bộ dữ liệu. 0,5 = mức trung bình chung.')
    prof = df.groupby('attack_cat')[[f'pct_{c}' for c in RADAR]].mean()
    prof.columns = RADAR
    cats = [c for c in ORDER if c in prof.index]
    chosen = st.multiselect('Chọn loại để so sánh', cats, default=cats[:3])
    fig = go.Figure()
    for cat in chosen:
        v = prof.loc[cat].tolist()
        fig.add_trace(go.Scatterpolar(r=v + v[:1], theta=RADAR + RADAR[:1], name=cat, fill='toself',
                                      line_color=PALETTE[cat], fillcolor=rgba(PALETTE[cat], 0.2)))
    fig.update_layout(polar=dict(radialaxis=dict(range=[0, 1])), height=560, title='Spider chart hồ sơ đặc trưng')
    c1, c2 = st.columns([3, 2])
    c1.plotly_chart(fig, use_container_width=True)
    fig = px.imshow(prof.loc[cats].round(2), color_continuous_scale='RdBu_r', zmin=0, zmax=1, text_auto=True,
                    aspect='auto', title='Bảng hồ sơ (heatmap)')
    fig.update_layout(height=560, yaxis_title='')
    c2.plotly_chart(fig, use_container_width=True)

# ---------------- Tab 5: Dữ liệu ----------------
with tab5:
    st.write(f'{len(df):,} luồng khớp bộ lọc (hiển thị 1.000 dòng đầu)')
    st.dataframe(df.drop(columns=[c for c in df.columns if c.startswith('pct_')]).head(1000), use_container_width=True)
