"""
app.py  —  LLM-Powered Intrusion Detection System
Streamlit Dashboard  |  InfoSec Semester Project 2026
"""

import os, sys, random, datetime
import pandas as pd
import streamlit as st
import plotly.express as px

sys.path.insert(0, os.path.dirname(__file__))

st.set_page_config(page_title="LLM-Powered IDS", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
[data-testid="stAppViewContainer"]{background:#0d1117}
[data-testid="stSidebar"]{background:#161b22;border-right:1px solid #30363d}
.block-container{padding-top:1rem}
.ids-header{background:linear-gradient(135deg,#0d1117,#161b22,#1f2937);
  border:1px solid #30363d;border-left:4px solid #238636;
  padding:1.4rem 1.8rem;border-radius:10px;margin-bottom:1.2rem}
.ids-header h1{color:#58a6ff;margin:0;font-size:1.65rem;font-weight:700}
.ids-header p{color:#8b949e;margin:.3rem 0 0;font-size:.9rem}
.mrow{display:flex;gap:12px;margin-bottom:1rem;flex-wrap:wrap}
.mc{flex:1;min-width:140px;background:#161b22;border:1px solid #30363d;
    border-radius:10px;padding:1rem;text-align:center}
.mc .v{font-size:2rem;font-weight:700;color:#58a6ff}
.mc .l{font-size:.75rem;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:.06em}
.sh{font-size:1rem;font-weight:600;color:#c9d1d9;border-bottom:1px solid #21262d;
    padding-bottom:6px;margin:1rem 0 .8rem}
.bdg{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.78rem;font-weight:600}
.bc{background:#3d1515;color:#ff7b7b;border:1px solid #da3633}
.bh{background:#2d1d00;color:#f0883e;border:1px solid #d29922}
.bm{background:#2d2a00;color:#e3b341;border:1px solid #9e6a03}
.bn{background:#0d2016;color:#3fb950;border:1px solid #238636}
div[data-testid="stExpander"]{border:1px solid #30363d !important;
    border-radius:8px !important;background:#161b22 !important}
</style>""", unsafe_allow_html=True)

CM = {"DoS":"#ff4444","BruteForce":"#ff8800","PortScan":"#ffcc00",
      "SQLInjection":"#aa00ff","Backdoor":"#ff0088","Benign":"#00cc66"}
CL = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
          font_color="#c9d1d9", legend_font_color="#c9d1d9",
          xaxis=dict(gridcolor="#21262d"), yaxis=dict(gridcolor="#21262d"))
SVBDG = {"Critical":"bc","High":"bh","Medium":"bm","None":"bn"}
SVICO = {"Critical":"🔴","High":"🟠","Medium":"🟡","None":"🟢"}

for k, v in {"alerts_log":[],"chat_history":[],"model_results":None,
             "batch_results":None,"api_key":os.getenv("OPENAI_API_KEY","")}.items():
    if k not in st.session_state:
        st.session_state[k] = v


def show_result(rec, pred):
    ca, cb = st.columns([1, 2])
    with ca:
        if pred["is_threat"]:
            st.error(f"🚨 **THREAT DETECTED**\n\n### {pred['prediction']}\n\n**{pred['confidence']}%** confidence")
        else:
            st.success(f"✅ **Benign Traffic**\n\n**{pred['confidence']}%** confidence")
        probs = pred.get("all_probabilities", {})
        if probs:
            pdf = (pd.DataFrame(list(probs.items()), columns=["Class","Prob (%)"])
                     .sort_values("Prob (%)", ascending=False))
            fig = px.bar(pdf, x="Prob (%)", y="Class", orientation="h",
                         color="Prob (%)", color_continuous_scale="Reds")
            fig.update_layout(height=220, margin=dict(t=5,b=5),
                               coloraxis_showscale=False, **CL)
            st.plotly_chart(fig, use_container_width=True)
    with cb:
        st.markdown("#### 📄 AI Threat Report")
        with st.spinner("Generating threat report …"):
            from utils.llm_analyzer import analyze_threat
            st.markdown(analyze_threat(rec, pred))
    st.session_state.alerts_log.append({
        **pred, "src_ip": rec.get("src_ip"), "dst_port": rec.get("dst_port"),
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
    })
    st.caption("✅ Alert logged.")


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ IDS Control Panel")
    st.divider()
    st.markdown("### 🔑 OpenAI API Key")
    api_in = st.text_input("API Key", type="password",
                            value=st.session_state.api_key, placeholder="sk-proj-…",
                            help="Optional — full fallback works without it.")
    if api_in:
        st.session_state.api_key = api_in
        os.environ["OPENAI_API_KEY"] = api_in
        st.success("✅ Key saved")
    st.divider()
    st.markdown("### 📍 Navigation")
    page = st.radio("", ["🏠 Dashboard","🔍 Analyze Traffic","📊 Batch Analysis",
                          "🧠 ML Model","📚 Threat KB","💬 Security Assistant"],
                    label_visibility="collapsed")
    st.divider()
    st.markdown("### ⚡ Quick Actions")
    if st.button("🎲 Generate Dataset", use_container_width=True):
        with st.spinner("Generating 5 000 records …"):
            try:
                from data.generate_dataset import generate_dataset
                os.makedirs("data", exist_ok=True)
                generate_dataset(5000, "data/network_traffic.csv")
                st.success("✅ Dataset ready")
            except Exception as e:
                st.error(str(e))
    if st.button("🤖 Train ML Model", use_container_width=True):
        with st.spinner("Training Random Forest …"):
            try:
                from models.ml_model import train_model
                r = train_model("data/network_traffic.csv")
                st.session_state.model_results = r
                st.success(f"✅ Accuracy: {r['accuracy']:.2%}")
            except Exception as e:
                st.error(str(e))
    if st.button("🔁 Run Batch Analysis", use_container_width=True):
        with st.spinner("Processing dataset …"):
            try:
                from utils.spark_processor import run_batch_analysis
                st.session_state.batch_results = run_batch_analysis("data/network_traffic.csv")
                st.success("✅ Batch done")
            except Exception as e:
                st.error(str(e))
    st.divider()
    st.caption("InfoSec Semester Project 2026 | LLM-IDS v1.0")

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""<div class="ids-header">
  <h1>🛡️ LLM-Powered Intrusion Detection System</h1>
  <p>AI-driven network threat detection · RAG Knowledge Base · GPT-4o · Scikit-learn · PySpark</p>
</div>""", unsafe_allow_html=True)


# ── PAGE: Dashboard ───────────────────────────────────────────────────────────
if page == "🏠 Dashboard":
    al = st.session_state.alerts_log
    th = [a for a in al if a.get("is_threat")]
    bn = len(al) - len(th)
    rt = f"{len(th)/len(al)*100:.1f}%" if al else "N/A"
    st.markdown(
        f'<div class="mrow">'
        f'<div class="mc"><div class="v">{len(al)}</div><div class="l">Total Alerts</div></div>'
        f'<div class="mc"><div class="v" style="color:#ff7b7b">{len(th)}</div><div class="l">Threats</div></div>'
        f'<div class="mc"><div class="v" style="color:#3fb950">{bn}</div><div class="l">Benign</div></div>'
        f'<div class="mc"><div class="v" style="color:#e3b341">{rt}</div><div class="l">Threat Rate</div></div>'
        f'</div>', unsafe_allow_html=True)

    if al:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<div class="sh">🎯 Threat Type Distribution</div>', unsafe_allow_html=True)
            tc = {}
            for a in al:
                k = a.get("prediction","?"); tc[k] = tc.get(k,0)+1
            fig = px.pie(values=list(tc.values()), names=list(tc.keys()),
                         color=list(tc.keys()), color_discrete_map=CM, hole=0.42)
            fig.update_layout(**{k:v for k,v in CL.items()}, margin=dict(t=10,b=10))
            fig.update_traces(textfont_color="#fff")
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            st.markdown('<div class="sh">📋 Recent Alerts</div>', unsafe_allow_html=True)
            df = pd.DataFrame(al[-15:][::-1])
            cs = [c for c in ["timestamp","prediction","confidence","src_ip","dst_port"] if c in df.columns]
            st.dataframe(df[cs], use_container_width=True, hide_index=True,
                         column_config={"confidence":st.column_config.ProgressColumn(
                             "Confidence %", min_value=0, max_value=100)})
        if len(al) >= 3:
            st.markdown('<div class="sh">📈 Threat Timeline</div>', unsafe_allow_html=True)
            tdf = pd.DataFrame(al); tdf["idx"] = range(len(tdf))
            fig2 = px.scatter(tdf, x="idx", y="confidence", color="prediction",
                              color_discrete_map=CM, labels={"idx":"Event #","confidence":"Confidence %"})
            fig2.update_layout(**CL)
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("🔍 No alerts yet. Go to **Analyze Traffic** to start detecting threats.")
        if os.path.exists("data/network_traffic.csv"):
            st.markdown('<div class="sh">📂 Dataset Preview</div>', unsafe_allow_html=True)
            st.dataframe(pd.read_csv("data/network_traffic.csv", nrows=10),
                         use_container_width=True, hide_index=True)
            df100 = pd.read_csv("data/network_traffic.csv", nrows=100)
            fig3 = px.histogram(df100, x="label", color="label", color_discrete_map=CM,
                                title="Traffic Label Distribution (first 100 records)")
            fig3.update_layout(**CL, showlegend=False)
            st.plotly_chart(fig3, use_container_width=True)


# ── PAGE: Analyze Traffic ─────────────────────────────────────────────────────
elif page == "🔍 Analyze Traffic":
    st.markdown('<div class="sh">🔍 Real-Time Traffic Analysis</div>', unsafe_allow_html=True)
    model_ready = os.path.exists("models/ids_model.pkl")
    if not model_ready:
        st.warning("⚠️ Model not trained. Click **Train ML Model** in the sidebar.")

    t1, t2 = st.tabs(["✍️ Manual Input", "🎲 Simulate Attack"])
    with t1:
        with st.form("pf"):
            c1, c2 = st.columns(2)
            with c1:
                si = st.text_input("Source IP",         "192.168.1.100")
                di = st.text_input("Destination IP",    "10.0.0.50")
                sp = st.number_input("Source Port",     1, 65535, 54321)
                dp = st.number_input("Destination Port",1, 65535, 80)
                pr = st.selectbox("Protocol",           ["TCP","UDP","ICMP"])
            with c2:
                fl = st.selectbox("TCP Flag",  ["SYN","ACK","SYN-ACK","FIN","RST","PSH-ACK"])
                pc = st.number_input("Packet Count",    1, 9999999,  50)
                bc = st.number_input("Byte Count",      1, 99999999, 5000)
                dm = st.number_input("Duration (ms)",   1, 9999999,  500)
            sub = st.form_submit_button("🔍 Analyze Packet", type="primary", use_container_width=True)
        if sub and model_ready:
            pps = round(pc/(dm/1000),2) if dm>0 else 0
            aps = round(bc/pc,2)        if pc>0 else 0
            rec = dict(src_ip=si,dst_ip=di,src_port=int(sp),dst_port=int(dp),protocol=pr,flag=fl,
                       packet_count=int(pc),byte_count=int(bc),duration_ms=int(dm),
                       packets_per_sec=pps,avg_packet_size=aps)
            with st.spinner("Running ML classifier …"):
                from models.ml_model import predict_single
                pred = predict_single(rec)
            show_result(rec, pred)

    with t2:
        at = st.selectbox("Attack type",
            ["Random","DoS","PortScan","BruteForce","SQLInjection","Backdoor","Benign"])
        if st.button("🎲 Generate & Analyze", type="primary", use_container_width=True):
            if model_ready:
                from data.generate_dataset import generate_record
                ch = at if at!="Random" else random.choice(
                    ["DoS","PortScan","BruteForce","SQLInjection","Backdoor","Benign"])
                rec = generate_record(ch)
                st.info(f"Simulated **{ch}** traffic record")
                with st.spinner("Classifying …"):
                    from models.ml_model import predict_single
                    pred = predict_single(rec)
                show_result(rec, pred)
            else:
                st.warning("Please train the model first.")


# ── PAGE: Batch Analysis ──────────────────────────────────────────────────────
elif page == "📊 Batch Analysis":
    st.markdown('<div class="sh">📊 Batch Traffic Analysis (PySpark / Pandas)</div>', unsafe_allow_html=True)
    path = st.text_input("Dataset path", "data/network_traffic.csv")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("⚡ Run Analysis", type="primary", use_container_width=True):
            if os.path.exists(path):
                with st.spinner("Processing …"):
                    from utils.spark_processor import run_batch_analysis
                    st.session_state.batch_results = run_batch_analysis(path)
                st.success("✅ Done")
            else:
                st.error(f"File not found: {path}")
    with c2:
        if st.session_state.batch_results:
            if st.button("📝 AI Executive Summary", use_container_width=True):
                proxy = [{"prediction":k,"confidence":95,"src_ip":"batch","dst_port":80,
                           "timestamp":"batch","is_threat":k!="Benign"}
                         for k,v in st.session_state.batch_results["threat_distribution"].items()
                         for _ in range(min(v,10))]
                with st.spinner("Generating …"):
                    from utils.llm_analyzer import summarize_alerts_batch
                    st.markdown(summarize_alerts_batch(proxy))

    r = st.session_state.batch_results
    if r:
        m1,m2,m3 = st.columns(3)
        m1.metric("Total Records",       f"{r['total_records']:,}")
        m2.metric("High-Vol DoS Events",  r.get("high_volume_dos_count",0))
        m3.metric("Threat Categories",   len(r["threat_distribution"]))
        st.divider()
        cl, cr = st.columns(2)
        with cl:
            st.markdown('<div class="sh">🎯 Threat Distribution</div>', unsafe_allow_html=True)
            td = r["threat_distribution"]
            fig = px.bar(x=list(td.keys()),y=list(td.values()),
                         color=list(td.keys()),color_discrete_map=CM,
                         labels={"x":"Threat","y":"Count"})
            fig.update_layout(**CL, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        with cr:
            st.markdown('<div class="sh">🌐 Protocol Distribution</div>', unsafe_allow_html=True)
            pd_ = r["protocol_distribution"]
            fig2 = px.pie(values=list(pd_.values()),names=list(pd_.keys()),
                          hole=0.42,color_discrete_sequence=["#58a6ff","#3fb950","#f0883e"])
            fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)",font_color="#c9d1d9",legend_font_color="#c9d1d9")
            fig2.update_traces(textfont_color="#fff")
            st.plotly_chart(fig2, use_container_width=True)
        cp, ci = st.columns(2)
        with cp:
            st.markdown('<div class="sh">🎯 Top Attacked Ports</div>', unsafe_allow_html=True)
            if r.get("top_attacked_ports"):
                st.dataframe(pd.DataFrame(r["top_attacked_ports"]),use_container_width=True,hide_index=True)
        with ci:
            st.markdown('<div class="sh">🕵️ Top Attacker IPs</div>', unsafe_allow_html=True)
            if r.get("top_attacker_ips"):
                st.dataframe(pd.DataFrame(r["top_attacker_ips"]),use_container_width=True,hide_index=True)


# ── PAGE: ML Model ────────────────────────────────────────────────────────────
elif page == "🧠 ML Model":
    st.markdown('<div class="sh">🧠 ML Model — Random Forest Classifier</div>', unsafe_allow_html=True)
    if os.path.exists("models/ids_model.pkl") and st.session_state.model_results is None:
        try:
            from models.ml_model import train_model
            with st.spinner("Loading metrics …"):
                st.session_state.model_results = train_model("data/network_traffic.csv")
        except Exception:
            pass
    r = st.session_state.model_results
    if r:
        m1,m2,m3,m4 = st.columns(4)
        m1.metric("Accuracy",       f"{r['accuracy']:.2%}")
        m2.metric("F1 Score (wtd)", f"{r['f1_score']:.2%}")
        m3.metric("Classes",        len(r["classes"]))
        m4.metric("Algorithm",      "Random Forest")
        cl, cr = st.columns(2)
        with cl:
            st.markdown('<div class="sh">📊 Feature Importance</div>', unsafe_allow_html=True)
            fi = pd.DataFrame(list(r["feature_importance"].items()),
                              columns=["Feature","Importance"]).sort_values("Importance",ascending=False)
            fig = px.bar(fi,x="Importance",y="Feature",orientation="h",
                         color="Importance",color_continuous_scale="Blues")
            fig.update_layout(height=300,coloraxis_showscale=False,**CL)
            st.plotly_chart(fig, use_container_width=True)
        with cr:
            st.markdown('<div class="sh">🗂 Confusion Matrix</div>', unsafe_allow_html=True)
            fig2 = px.imshow(r["confusion_matrix"],x=r["class_names"],y=r["class_names"],
                             text_auto=True,aspect="auto",color_continuous_scale="Blues",
                             labels={"x":"Predicted","y":"Actual"})
            fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)",font_color="#c9d1d9",coloraxis_showscale=False)
            st.plotly_chart(fig2, use_container_width=True)
        with st.expander("📐 Model Architecture Details"):
            st.markdown("""
**Algorithm:** Random Forest Classifier (scikit-learn)

| Hyperparameter | Value |
|---|---|
| n_estimators | 100 |
| max_depth | 15 |
| min_samples_split | 5 |
| train/test split | 80% / 20% (stratified) |

**9 Features:** `src_port` · `dst_port` · `packet_count` · `byte_count` · `duration_ms`
· `packets_per_sec` · `avg_packet_size` · `protocol_enc` · `flag_enc`

**Classes:** Benign · DoS · PortScan · BruteForce · SQLInjection · Backdoor
            """)
    else:
        st.info("Click **Train ML Model** in the sidebar to train and view metrics.")


# ── PAGE: Threat KB ───────────────────────────────────────────────────────────
elif page == "📚 Threat KB":
    st.markdown('<div class="sh">📚 RAG-Based Threat Knowledge Base</div>', unsafe_allow_html=True)
    from rag.knowledge_base import get_kb
    kb = get_kb()
    cs, cb = st.columns([4,1])
    with cs:
        q = st.text_input("🔍 Search", placeholder="e.g. SYN flood port 80 high packet count …")
    with cb:
        st.markdown("<br>", unsafe_allow_html=True)
        dosearch = st.button("Search", type="primary", use_container_width=True)
    entries = kb.retrieve(q, top_k=3) if (q and dosearch) else kb.kb
    for e in entries:
        sv = e["severity"]
        lbl = f"{SVICO.get(sv,'⚪')} **{e['title']}**  ·  {e['threat_type']}"
        if "relevance_score" in e:
            lbl += f"  ·  Relevance: {e['relevance_score']:.2f}"
        with st.expander(lbl):
            st.markdown(f"**Description:** {e['description']}")
            st.markdown(f"**Indicators:** `{'` · `'.join(e['indicators'])}`")
            st.markdown(f"**Mitigation:** {e['mitigation']}")
            st.markdown(f'<span class="bdg {SVBDG.get(sv,"")}">Severity: {sv}</span>',
                        unsafe_allow_html=True)


# ── PAGE: Security Assistant ──────────────────────────────────────────────────
elif page == "💬 Security Assistant":
    st.markdown('<div class="sh">💬 AI Security Assistant (RAG-Powered)</div>', unsafe_allow_html=True)
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
    if not st.session_state.chat_history:
        st.markdown("**Try asking:**")
        starters = ["What is a SYN flood attack and how do I stop it?",
                    "How can I detect port scanning in my network?",
                    "Explain SQL injection at the network level",
                    "What does a backdoor beacon look like in traffic?"]
        cols = st.columns(2)
        for i, q in enumerate(starters):
            with cols[i%2]:
                if st.button(q, use_container_width=True, key=f"s{i}"):
                    st.session_state._pq = q; st.rerun()
    if hasattr(st.session_state,"_pq"):
        user_input = st.session_state._pq; del st.session_state._pq
    else:
        user_input = st.chat_input("Ask about cybersecurity, threats, or IDS …")
    if user_input:
        with st.chat_message("user"):
            st.markdown(user_input)
        with st.chat_message("assistant"):
            with st.spinner("Thinking …"):
                from utils.llm_analyzer import chat_with_security_assistant
                reply, hist = chat_with_security_assistant(user_input, st.session_state.chat_history)
            st.markdown(reply)
            st.session_state.chat_history = hist
    if st.session_state.chat_history:
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.chat_history = []; st.rerun()
    st.divider()
    st.markdown('<div class="sh">📋 Real-Time Alert NLP Summarizer</div>', unsafe_allow_html=True)
    if st.session_state.alerts_log:
        if st.button("📊 Summarize All Alerts", type="secondary", use_container_width=True):
            with st.spinner("Analysing …"):
                from utils.llm_analyzer import summarize_alerts_batch
                st.markdown(summarize_alerts_batch(st.session_state.alerts_log))
    else:
        st.info("Analyse some traffic first to use the summarizer.")
