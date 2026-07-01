import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import subprocess, glob, os
from datetime import datetime

st.set_page_config(page_title="Domain Hunter Toolkit", page_icon="🔍", layout="wide")

st.markdown("""<style>
.stMetric { background:#1a1a2e; border-radius:8px; padding:12px; border:1px solid #2a2a4a }
div[data-testid="metric-container"] { background:#1a1a2e; border-radius:8px; padding:12px }
</style>""", unsafe_allow_html=True)

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
NICHES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'niches.json')

GRADE_COLORS = {'A':'#2e7d32','B':'#1565c0','C':'#f57f17','D':'#e65100','F':'#b71c1c'}
IDX_COLORS   = {'CLEAN':'#2e7d32','NOT_INDEXED':'#f57f17','SPAM':'#b71c1c','ERR':'#546e7a','N/A':'#37474f'}

@st.cache_data(ttl=10)
def load_niches():
    """Load niche->synonym keyword mapping. Returns {} if missing/invalid."""
    try:
        import json
        with open(NICHES_PATH, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, Exception):
        return {}

def domain_matches_keywords(domain, keywords):
    """Case-insensitive substring match of any keyword against the domain name.
    Returns the list of keywords that matched (empty list = no match)."""
    domain_lower = str(domain).lower()
    return [kw for kw in keywords if kw.lower() in domain_lower]

@st.cache_data(ttl=30)
def load_reports():
    files = sorted(glob.glob(os.path.join(REPORTS_DIR,'pipeline_report_*.csv')), reverse=True)
    if not files: return pd.DataFrame(), []
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f)
            df['_source'] = os.path.basename(f)
            df['_ts'] = os.path.getmtime(f)
            dfs.append(df)
        except: pass
    if not dfs: return pd.DataFrame(), files
    out = pd.concat(dfs, ignore_index=True)
    out = out.sort_values('_ts', ascending=False).drop_duplicates('domain', keep='first')
    return out, files

def run_pipeline():
    r = subprocess.run(['bash', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pipeline.sh')],
                       capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.abspath(__file__)))
    return r.returncode, r.stdout, r.stderr

# ── Sidebar ───────────────────────────────────────────────────────
with st.sidebar:
    st.title("🔍 Domain Hunter")
    st.caption("Toolkit v2.0 — 12 checks")
    st.divider()

    st.subheader("⚙ Pipeline")
    if st.button("▶ Run Pipeline", use_container_width=True):
        with st.spinner("Running... ~2 minutes"):
            code, out, _ = run_pipeline()
            if code == 0:   st.success("Complete!")
            elif code == 2: st.error("Fatal error — check credentials")
            else:           st.warning("Finished with some failures")
            st.cache_data.clear()
            with st.expander("Output"): st.code(out[-3000:])

    st.divider()
    st.subheader("📥 Import from Extension")
    uploaded = st.file_uploader("Upload CSV", type=['csv'])
    if uploaded:
        try:
            imp = pd.read_csv(uploaded)
            doms = imp['domain'].dropna().tolist() if 'domain' in imp.columns else []
            if doms:
                with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'domains.txt'), 'w') as f:
                    f.write('\n'.join(doms))
                st.success(f"Imported {len(doms)} domains")
        except Exception as e: st.error(str(e))

    st.divider()
    df_all, report_files = load_reports()

    st.subheader("🔧 Filters")
    if not df_all.empty:
        avail_f  = st.multiselect("Availability", ['FREE','TAKEN'], default=['FREE'])
        idx_f    = st.multiselect("Index", ['CLEAN','NOT_INDEXED','SPAM','ERR'], default=['CLEAN','NOT_INDEXED'])
        grade_f  = st.multiselect("Min Grade", ['A','B','C','D','F'], default=['A','B','C'])
        min_score= st.slider("Min Score", 0, 100, 0)
        hide_scheme = st.checkbox("Hide link schemes", True)
        hide_spike  = st.checkbox("Hide velocity spikes", False)

        st.divider()
        st.subheader("🏷 Niche / Name Filter")
        niches = load_niches()
        niche_options = ["(none)"] + sorted(niches.keys())
        selected_niche = st.selectbox(
            "Match domain names against a niche",
            niche_options,
            help="Filters by keywords found in the domain NAME itself — e.g. selecting 'pet' shows domains containing pet, dog, cat, vet, etc."
        )
        custom_kw_input = st.text_input(
            "Custom keywords (comma-separated, optional)",
            placeholder="e.g. fish, aquarium, reptile",
            help="Adds extra keywords on top of the selected niche, or use alone without picking a niche above."
        )

        # Build final keyword list — niche keywords + any custom additions
        active_keywords = []
        if selected_niche != "(none)" and selected_niche in niches:
            active_keywords.extend(niches[selected_niche])
        if custom_kw_input.strip():
            active_keywords.extend([k.strip() for k in custom_kw_input.split(',') if k.strip()])

        if active_keywords:
            st.caption(f"Matching against: {', '.join(sorted(set(active_keywords)))}")

# ── Main ──────────────────────────────────────────────────────────
st.title("🔍 Domain Hunter Dashboard")

tab_overview, tab_domains, tab_compare, tab_charts = st.tabs(
    ["📊 Overview", "📋 Domains", "⚖ Compare", "📈 Charts"])

if df_all.empty:
    with tab_overview:
        st.info("No reports found. Run the pipeline first.")
        st.code("./pipeline.sh")
    st.stop()

# Numeric coercion
NUM_COLS = ['rank','backlinks','ref_domains','spam_score','score','wb_age',
            'foreign_pct','velocity_spike_pct','ip_conc_pct','spam_rd_count',
            'authority','spam_risk','link_profile','stability']
for c in NUM_COLS:
    if c in df_all.columns:
        df_all[c] = pd.to_numeric(df_all[c], errors='coerce').fillna(0)

# Apply filters
df = df_all.copy()
if 'available'     in df.columns and avail_f:  df = df[df['available'].isin(avail_f)]
if 'index_status'  in df.columns and idx_f:    df = df[df['index_status'].isin(idx_f)]
if 'grade'         in df.columns and grade_f:  df = df[df['grade'].isin(grade_f)]
if 'score'         in df.columns:              df = df[df['score'] >= min_score]
if hide_scheme and 'link_flag'    in df.columns: df = df[df['link_flag'] != 'LIKELY_SCHEME']
if hide_spike  and 'velocity_flag' in df.columns:
    df = df[~df['velocity_flag'].isin(['SPIKE','SEVERE_SPIKE'])]

# Niche/name filter — matches keywords against the domain name itself,
# purely a display filter (every domain was already fully checked
# regardless of name, so switching niches doesn't require a re-run)
if active_keywords and 'domain' in df.columns:
    matched_kw_series = df['domain'].apply(lambda d: domain_matches_keywords(d, active_keywords))
    df = df[matched_kw_series.apply(len) > 0].copy()
    df['matched_keywords'] = matched_kw_series[matched_kw_series.apply(len) > 0].apply(lambda kws: ', '.join(kws))

# ── Overview tab ──────────────────────────────────────────────────
with tab_overview:
    total = len(df_all)
    free  = len(df_all[df_all.get('available','') == 'FREE']) if 'available' in df_all.columns else 0
    c1,c2,c3,c4,c5,c6,c7,c8 = st.columns(8)
    with c1: st.metric("Total",    total)
    with c2: st.metric("Free",     free)
    with c3: st.metric("🅰 Grade A", len(df_all[df_all.get('grade','') == 'A']) if 'grade' in df_all.columns else 0)
    with c4: st.metric("🅱 Grade B", len(df_all[df_all.get('grade','') == 'B']) if 'grade' in df_all.columns else 0)
    with c5: st.metric("🟢 Clean",  len(df_all[df_all.get('index_status','') == 'CLEAN']) if 'index_status' in df_all.columns else 0)
    with c6: st.metric("🟡 Not Idx",len(df_all[df_all.get('index_status','') == 'NOT_INDEXED']) if 'index_status' in df_all.columns else 0)
    with c7: st.metric("⚡ Spikes", len(df_all[df_all.get('velocity_flag','').isin(['SPIKE','SEVERE_SPIKE'])]) if 'velocity_flag' in df_all.columns else 0)
    with c8: st.metric("🌏 Foreign",len(df_all[df_all.get('foreign_flag','') == 'HIGH_FOREIGN']) if 'foreign_flag' in df_all.columns else 0)

    st.divider()
    r1c1, r1c2, r1c3 = st.columns(3)

    with r1c1:
        st.subheader("Score Distribution")
        if 'score' in df_all.columns:
            sc = df_all[df_all['score'] > 0]['score']
            if not sc.empty:
                fig = px.histogram(sc, nbins=20, color_discrete_sequence=['#1565c0'])
                fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                                  font_color='#e0e0e0', showlegend=False,
                                  margin=dict(t=0,b=0,l=0,r=0), height=220,
                                  xaxis_title="Score", yaxis_title="Count")
                fig.add_vline(x=75, line_dash="dash", line_color="#2e7d32", annotation_text="A")
                fig.add_vline(x=60, line_dash="dash", line_color="#1565c0", annotation_text="B")
                st.plotly_chart(fig, use_container_width=True)

    with r1c2:
        st.subheader("Grade Breakdown")
        if 'grade' in df_all.columns:
            gc = df_all['grade'].value_counts().reset_index()
            gc.columns = ['grade','count']
            colors = [GRADE_COLORS.get(g,'#546e7a') for g in gc['grade']]
            fig = px.pie(gc, values='count', names='grade',
                         color_discrete_sequence=colors, hole=0.4)
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color='#e0e0e0',
                               margin=dict(t=0,b=0,l=0,r=0), height=220)
            st.plotly_chart(fig, use_container_width=True)

    with r1c3:
        st.subheader("Index Status")
        if 'index_status' in df_all.columns:
            ic = df_all['index_status'].value_counts().reset_index()
            ic.columns = ['status','count']
            colors = [IDX_COLORS.get(s,'#546e7a') for s in ic['status']]
            fig = px.pie(ic, values='count', names='status',
                         color_discrete_sequence=colors, hole=0.4)
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color='#e0e0e0',
                               margin=dict(t=0,b=0,l=0,r=0), height=220)
            st.plotly_chart(fig, use_container_width=True)

    # Top domains by score
    st.divider()
    st.subheader("🏆 Top Domains by Score")
    if not df.empty and 'score' in df.columns:
        top = df[df['available'] == 'FREE'].sort_values('score', ascending=False).head(10) if 'available' in df.columns else df.sort_values('score', ascending=False).head(10)
        for _, row in top.iterrows():
            sc = int(row.get('score', 0))
            gr = row.get('grade', '?')
            idx = row.get('index_status', '?')
            dr  = int(row.get('rank', 0))
            bl  = int(row.get('backlinks', 0))
            flags = str(row.get('score_flags', ''))
            color = GRADE_COLORS.get(gr, '#546e7a')
            st.markdown(f"""
            <div style="background:#16213e;border-left:5px solid {color};padding:10px 14px;border-radius:4px;margin:4px 0;display:flex;justify-content:space-between;align-items:center">
                <span style="font-family:monospace;font-size:14px;color:#e0e0e0;font-weight:bold">{row['domain']}</span>
                <span style="color:{color};font-weight:bold;font-size:16px">{sc}/100 ({gr})</span>
                <span style="color:#888;font-size:12px">DR:{dr} BL:{bl:,} {idx}</span>
                <span style="color:#555;font-size:11px;max-width:300px;overflow:hidden">{flags[:60]}</span>
            </div>""", unsafe_allow_html=True)

# ── Domains tab ───────────────────────────────────────────────────
with tab_domains:
    st.subheader(f"Domains ({len(df)} shown after filters)")
    if df.empty:
        st.warning("No domains match filters.")
    else:
        disp_cols = ['domain','available','index_status','score','grade',
                     'authority','spam_risk','link_profile','stability',
                     'rank','backlinks',
                     'ref_domains','spam_score','niche','niche_status','redirect_status',
                     'anchor_flag','velocity_flag','foreign_flag','ip_flag',
                     'link_flag','wb_age','score_flags']
        if 'matched_keywords' in df.columns:
            disp_cols.append('matched_keywords')
        disp_cols = [c for c in disp_cols if c in df.columns]
        df_disp = df[disp_cols].copy().sort_values('score', ascending=False) if 'score' in df.columns else df[disp_cols].copy()
        df_disp = df_disp.rename(columns={
            'domain':'Domain','available':'Avail','index_status':'Index',
            'score':'Score','grade':'Grade',
            'authority':'Authority','spam_risk':'Spam Risk',
            'link_profile':'Link Profile','stability':'Stability',
            'rank':'DR','backlinks':'Backlinks',
            'ref_domains':'Ref Domains','spam_score':'Spam%','niche':'Niche',
            'niche_status':'Niche Status','redirect_status':'Redirect',
            'anchor_flag':'Anchors','velocity_flag':'Velocity',
            'foreign_flag':'Foreign','ip_flag':'IP Div',
            'link_flag':'Link Flag','wb_age':'Age(y)','score_flags':'Flags',
            'matched_keywords':'Matched On'
        })

        def style_score(val):
            try:
                v = int(val)
                if v >= 75: return 'background-color:#1b5e20;color:white;font-weight:bold'
                if v >= 60: return 'background-color:#0d47a1;color:white'
                if v >= 45: return 'background-color:#e65100;color:white'
                return 'background-color:#b71c1c;color:white'
            except: return ''

        def style_idx(val):
            m = {'CLEAN':'background-color:#1b5e20;color:white',
                 'NOT_INDEXED':'background-color:#f57f17;color:black',
                 'SPAM':'background-color:#b71c1c;color:white'}
            return m.get(str(val), '')

        def style_flag(val):
            bad = ['LIKELY_SCHEME','SPIKE','SEVERE_SPIKE','HIGH_FOREIGN','SINGLE_HOST',
                   'OVER_OPTIMISED','SELF_REFERENTIAL','REDIRECTS_AWAY']
            return 'color:#ef9a9a;font-weight:bold' if str(val) in bad else ''

        styled = df_disp.style
        if 'Score' in df_disp.columns: styled = styled.map(style_score, subset=['Score'])
        if 'Index' in df_disp.columns: styled = styled.map(style_idx,   subset=['Index'])
        for col in ['Link Flag','Velocity','Foreign','Redirect','Anchors']:
            if col in df_disp.columns: styled = styled.map(style_flag, subset=[col])

        st.dataframe(styled, use_container_width=True, height=600)

        col_a, col_b, col_c = st.columns([2,1,1])
        with col_a: st.caption(f"{len(df)} domains from {len(report_files)} run(s)")
        with col_b:
            if 'domain' in df.columns:
                domains_out = '\n'.join(df['domain'].tolist())
                st.download_button("📄 Export domains.txt", domains_out,
                                   "domains.txt", "text/plain", use_container_width=True)
        with col_c:
            csv_out = df_disp.to_csv(index=False)
            st.download_button("⬇ Export CSV", csv_out,
                               f"domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                               "text/csv", use_container_width=True)

# ── Compare tab ───────────────────────────────────────────────────
with tab_compare:
    st.subheader("⚖ Domain Comparison")
    if df_all.empty:
        st.info("No data to compare.")
    else:
        all_domains = sorted(df_all['domain'].tolist()) if 'domain' in df_all.columns else []
        selected = st.multiselect("Select 2-5 domains to compare", all_domains,
                                  default=all_domains[:min(3, len(all_domains))])
        if len(selected) < 2:
            st.info("Select at least 2 domains.")
        else:
            comp = df_all[df_all['domain'].isin(selected)].set_index('domain')
            comp_cols = ['score','grade','rank','backlinks','ref_domains','spam_score',
                         'index_status','niche_status','velocity_flag','foreign_flag',
                         'ip_flag','cache_status','link_flag','wb_age']
            comp_cols = [c for c in comp_cols if c in comp.columns]
            st.dataframe(comp[comp_cols].T, use_container_width=True)

            # Radar chart
            if 'score' in comp.columns and len(selected) <= 5:
                st.subheader("Score Radar")
                radar_metrics = ['rank','backlinks','ref_domains']
                radar_metrics = [c for c in radar_metrics if c in comp.columns]
                if radar_metrics:
                    fig = go.Figure()
                    for dom in selected:
                        if dom in comp.index:
                            row = comp.loc[dom]
                            vals = [min(float(row.get(m, 0)), 100) for m in radar_metrics]
                            vals += [vals[0]]
                            fig.add_trace(go.Scatterpolar(
                                r=vals, theta=radar_metrics + [radar_metrics[0]],
                                fill='toself', name=dom))
                    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color='#e0e0e0',
                                      polar=dict(bgcolor='rgba(0,0,0,0)'), height=350)
                    st.plotly_chart(fig, use_container_width=True)

# ── Charts tab ────────────────────────────────────────────────────
with tab_charts:
    st.subheader("📈 Analysis Charts")
    if df_all.empty:
        st.info("No data.")
    else:
        ch1, ch2 = st.columns(2)

        with ch1:
            st.markdown("**DR vs Backlinks**")
            if 'rank' in df_all.columns and 'backlinks' in df_all.columns:
                plot = df_all[(df_all['rank'] > 0) | (df_all['backlinks'] > 0)].copy()
                plot['index_status'] = plot.get('index_status', 'N/A')
                fig = px.scatter(plot, x='rank', y='backlinks', color='index_status',
                                 hover_data=['domain'], color_discrete_map=IDX_COLORS,
                                 log_y=True)
                fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                                  font_color='#e0e0e0', margin=dict(t=0,b=0,l=0,r=0), height=300)
                st.plotly_chart(fig, use_container_width=True)

        with ch2:
            st.markdown("**Spam Score vs DR**")
            if 'spam_score' in df_all.columns and 'rank' in df_all.columns:
                fig = px.scatter(df_all, x='rank', y='spam_score',
                                 color='grade' if 'grade' in df_all.columns else None,
                                 hover_data=['domain'],
                                 color_discrete_map=GRADE_COLORS)
                fig.add_hline(y=30, line_dash="dash", line_color="#f57f17",
                              annotation_text="Spam threshold")
                fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                                  font_color='#e0e0e0', margin=dict(t=0,b=0,l=0,r=0), height=300)
                st.plotly_chart(fig, use_container_width=True)

        ch3, ch4 = st.columns(2)
        with ch3:
            st.markdown("**Foreign Anchor % Distribution**")
            if 'foreign_pct' in df_all.columns:
                fp = df_all[df_all['foreign_pct'] >= 0]['foreign_pct']
                fig = px.histogram(fp, nbins=20, color_discrete_sequence=['#e65100'])
                fig.add_vline(x=10, line_dash="dash", line_color="#f57f17")
                fig.add_vline(x=30, line_dash="dash", line_color="#b71c1c")
                fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                                  font_color='#e0e0e0', showlegend=False,
                                  margin=dict(t=0,b=0,l=0,r=0), height=280)
                st.plotly_chart(fig, use_container_width=True)

        with ch4:
            st.markdown("**Score vs Wayback Age**")
            if 'score' in df_all.columns and 'wb_age' in df_all.columns:
                wa = df_all[df_all['wb_age'] > 0]
                fig = px.scatter(wa, x='wb_age', y='score',
                                 color='grade' if 'grade' in wa.columns else None,
                                 hover_data=['domain'], color_discrete_map=GRADE_COLORS)
                fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                                  font_color='#e0e0e0', margin=dict(t=0,b=0,l=0,r=0), height=280,
                                  xaxis_title="Domain Age (years)", yaxis_title="Score")
                st.plotly_chart(fig, use_container_width=True)

# Footer
if report_files:
    with st.expander("Recent Pipeline Runs"):
        for f in report_files[:5]:
            ts = datetime.fromtimestamp(os.path.getmtime(f)).strftime('%Y-%m-%d %H:%M:%S')
            try: n = len(pd.read_csv(f))
            except: n = '?'
            st.text(f"{ts}  —  {os.path.basename(f)}  ({n} domains)")
