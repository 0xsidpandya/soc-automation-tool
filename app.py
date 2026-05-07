import streamlit as st
import pandas as pd
from datetime import datetime, timedelta, timezone

# -------- IST TIMEZONE --------
IST = timezone(timedelta(hours=5, minutes=30))

st.set_page_config(layout="wide")

# -------- TIME CONVERSION --------
def convert_alert_time(raw_time):
    try:
        dt = datetime.strptime(raw_time, "%b %d, %Y @ %H:%M:%S.%f")
        dt = dt.replace(tzinfo=IST)
        return dt.strftime("%d %b %Y %H:%M")
    except:
        return raw_time

# -------- PAGE STATE --------
if "page" not in st.session_state:
    st.session_state.page = "home"

# ============================
# 🏠 DASHBOARD
# ============================
if st.session_state.page == "home":

    st.title("SOC Automation Dashboard")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("🚨 Raise Incident", use_container_width=True):
            st.session_state.page = "raise"

    with col2:
        if st.button("✅ Close Incident", use_container_width=True):
            st.session_state.page = "close"

# ============================
# 🚨 RAISE INCIDENT
# ============================
elif st.session_state.page == "raise":

    st.title("Raise Incident")

    if st.button("⬅ Back"):
        st.session_state.page = "home"

    col1, col2 = st.columns(2)

    with col1:
        alert_title = st.text_input("Alert Title")
        alert_summary = st.text_area("Alert Summary")
        alert_id = st.text_input("Alert ID")
        alert_time = st.text_input("Alert Time (e.g. May 4, 2026 @ 16:49:43.465)")
        alert_source = st.text_input("Alert Source")
        risk = st.text_input("Risk Score")
        severity = st.selectbox("Severity", ["Low", "Medium", "High"])
        affected_host = st.text_input("Affected Host")
        affected_user = st.text_input("Affected User")

    with col2:
        event_time = st.text_input("Event Time")
        host_ip = st.text_input("Host IP")
        source_ip = st.text_input("Source IP")
        destination_ip = st.text_input("Destination IP")
        mitre_tactic = st.text_input("MITRE Tactic")
        mitre_technique = st.text_input("MITRE Technique")
        event_category = st.text_input("Event Category")
        logon_type = st.text_input("Logon Type")

    process_path = st.text_area("Process / Command")
    analysis = st.text_area("Analysis")
    activity = st.text_area("Activity Pattern Indicates")
    recommendation = st.text_area("Recommendations")

    st.subheader("Threat Intel")
    ti_ip = st.text_input("IP Address")
    ti_isp = st.text_input("ISP")
    ti_score = st.text_input("VT Score")
    ti_result = st.text_input("Result")

    assigned_to = st.text_input("Assigned To")

    if st.button("Generate Email & Tracker"):

        # -------- TIME LOGIC --------
        formatted_alert_time = convert_alert_time(alert_time)
        alert_detected = formatted_alert_time

        now_dt = datetime.now(IST)

        ack_dt = now_dt + timedelta(minutes=10)
        ack_time = ack_dt.strftime("%d %b %Y %H:%M")

        email_sent_time = ack_time

        # -------- AGING + MTTR --------
        try:
            alert_dt = datetime.strptime(formatted_alert_time, "%d %b %Y %H:%M")
            alert_dt = alert_dt.replace(tzinfo=IST)

            aging_days = (now_dt.date() - alert_dt.date()).days
            mttr_hours = round((ack_dt - alert_dt).total_seconds() / 3600, 2)

        except:
            aging_days = 0
            mttr_hours = 0

        prev_alert = "No Previous Occurrences were found for the same Alert Type and Host."
        prev_desc = "-"

        # =========================================
        # 📧 EMAIL TEMPLATE (DO NOT MODIFY STRUCTURE)
        # =========================================

        email_html = f"""
        <html>
<body style="font-family:Calibri; font-size:12px; background:#ffffff;">
<div style="width:850px; margin:auto;">

<p>Hello Team,</p>

<table style="border-collapse:collapse; width:100%; border:1px solid #c5c5c5;">

<colgroup>
<col style="width:20%">
<col style="width:30%">
<col style="width:20%">
<col style="width:30%">
</colgroup>

<!-- ALERT TITLE -->
<tr style="background:#e6cbb3;">
<td colspan="4" style="padding:10px; font-size:14px; border:1px solid #c5c5c5;"><b>Alert Title</b></td>
</tr>
<tr>
<td colspan="4" style="padding:14px; border:1px solid #c5c5c5;">{alert_title}</td>
</tr>

<tr><td colspan="4" style="height:20px;"></td></tr>

<!-- ALERT SUMMARY -->
<tr style="background:#e6cbb3;">
<td colspan="4" style="padding:10px; font-size:14px; border:1px solid #c5c5c5;"><b>Alert Summary</b></td>
</tr>
<tr>
<td colspan="4" style="padding:14px; border:1px solid #c5c5c5;">{alert_summary}</td>
</tr>

<tr><td colspan="4" style="height:20px;"></td></tr>

<!-- MAIN GRID -->
<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Alert ID</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{alert_id}</td>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Alert Time</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{alert_time}</td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Alert Source</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{alert_source}</td>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Event Time</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{event_time}</td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Risk</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{risk}</td>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Severity</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{severity}</td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Affected Host</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{affected_host}</td>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Affected User</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{affected_user}</td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Host IP</b></td>
<td colspan="3" style="padding:10px; border:1px solid #c5c5c5;">{host_ip}</td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Source IP</b></td>
<td colspan="3" style="padding:10px; border:1px solid #c5c5c5;">{source_ip}</td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Destination IP</b></td>
<td colspan="3" style="padding:10px; border:1px solid #c5c5c5;">{destination_ip}</td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>MITRE Tactic</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{mitre_tactic}</td>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>MITRE Technique</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{mitre_technique}</td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Event Category</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{event_category}</td>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Logon Type</b></td>
<td style="padding:10px; border:1px solid #c5c5c5;">{logon_type}</td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Process / Command</b></td>
<td colspan="3" style="padding:10px; border:1px solid #c5c5c5;">{process_path}</td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Add More if found</b></td>
<td colspan="3" style="padding:10px; border:1px solid #c5c5c5;"></td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Add more if found</b></td>
<td colspan="3" style="padding:10px; border:1px solid #c5c5c5;"></td>
</tr>

<tr>
<td style="background:#b7c9d6; padding:10px; border:1px solid #c5c5c5;"><b>Remove Empty Fields above(including this)</b></td>
<td colspan="3" style="padding:10px; border:1px solid #c5c5c5;"></td>
</tr>

<tr><td colspan="4" style="height:20px;"></td></tr>

<!-- ANALYSIS -->
<tr style="background:#e6cbb3;">
<td colspan="4" style="padding:10px; font-size:14px; border:1px solid #c5c5c5;"><b>Analysis</b></td>
</tr>
<tr>
<td colspan="4" style="padding:14px; height:100px; border:1px solid #c5c5c5; vertical-align:top;">
{analysis}
</td>
</tr>

<tr><td colspan="4" style="height:20px;"></td></tr>

<!-- ACTIVITY -->
<tr style="background:#e6cbb3;">
<td colspan="4" style="padding:10px; font-size:14px; border:1px solid #c5c5c5;"><b>Activity Pattern Indicates</b></td>
</tr>
<tr>
<td colspan="4" style="padding:14px; height:80px; border:1px solid #c5c5c5; vertical-align:top;">
{activity}
</td>
</tr>

<tr><td colspan="4" style="height:20px;"></td></tr>

<!-- PREVIOUS OCCURRENCE -->
<tr style="background:#e6cbb3;">
<td colspan="4" style="padding:10px; font-size:14px; border:1px solid #c5c5c5;"><b>Previous Occurrence in 7 Days</b></td>
</tr>

<tr>
<td colspan="4" style="padding:10px; border:1px solid #c5c5c5;">
<table style="width:100%; border-collapse:collapse;">

<tr style="background:#d9d9d9;">
<td style="border:1px solid #c5c5c5; padding:8px;"><b>Alert ID</b></td>
<td style="border:1px solid #c5c5c5; padding:8px;"><b>Description</b></td>
</tr>

<tr>
<td style="border:1px solid #c5c5c5; padding:8px;">{prev_alert}</td>
<td style="border:1px solid #c5c5c5; padding:8px;">{prev_desc}</td>
</tr>

</table>
</td>
</tr>

<tr><td colspan="4" style="height:20px;"></td></tr>

<!-- PREVIOUS OCCURRENCE -->
<tr style="background:#e6cbb3;">
<td colspan="4" style="padding:10px; font-size:14px; border:1px solid #c5c5c5;"><b>Recent 3 Occurences</b></td>
</tr>

<tr>
<td colspan="4" style="padding:10px; border:1px solid #c5c5c5;">
<table style="width:100%; border-collapse:collapse;">

<tr style="background:#d9d9d9;">
<td style="border:1px solid #c5c5c5; padding:8px;"><b>Alert ID</b></td>
<td style="border:1px solid #c5c5c5; padding:8px;"><b>Description</b></td>
</tr>

<tr>
<td style="border:1px solid #c5c5c5; padding:8px;">{prev_alert}</td>
<td style="border:1px solid #c5c5c5; padding:8px;">{prev_desc}</td>
</tr>

</table>
</td>
</tr>

<tr><td colspan="4" style="height:20px;"></td></tr>

<!-- THREAT INTEL -->
<tr style="background:#e6cbb3;">
<td colspan="4" style="padding:10px; font-size:14px; border:1px solid #c5c5c5;"><b>Threat Intel</b></td>
</tr>

<tr>
<td colspan="4" style="padding:10px; border:1px solid #c5c5c5;">
<table style="width:100%; border-collapse:collapse;">

<tr style="background:#d9d9d9;">
<td style="border:1px solid #c5c5c5; padding:8px;"><b>IP</b></td>
<td style="border:1px solid #c5c5c5; padding:8px;"><b>ISP</b></td>
<td style="border:1px solid #c5c5c5; padding:8px;"><b>Score</b></td>
<td style="border:1px solid #c5c5c5; padding:8px;"><b>Result</b></td>
</tr>

<tr>
<td style="border:1px solid #c5c5c5; padding:8px;">{ti_ip}</td>
<td style="border:1px solid #c5c5c5; padding:8px;">{ti_isp}</td>
<td style="border:1px solid #c5c5c5; padding:8px;">{ti_score}</td>
<td style="border:1px solid #c5c5c5; padding:8px;">{ti_result}</td>
</tr>

</table>
</td>
</tr>

<tr><td colspan="4" style="height:20px;"></td></tr>

<!-- RECOMMENDATIONS -->
<tr style="background:#e6cbb3;">
<td colspan="4" style="padding:10px; font-size:14px; border:1px solid #c5c5c5;"><b>Recommendations</b></td>
</tr>
<tr>
<td colspan="4" style="padding:14px; border:1px solid #c5c5c5;">
{recommendation}
</td>
</tr>

</table>

<p style="margin-top:20px;">
Thanks & Regards,<br>
<b>SOC SBFC</b>
</p>

</div>
</body>
</html>

        """

        # =========================================
        # 📊 TRACKER
        # =========================================

        tracker = {
            "AlertID": alert_id,
            "FromEmail": "soc.sbfc@talakunchi.com",
            "User": "Siddharth",
            "Assigned_to": assigned_to,

            
            "AlertDetected": alert_detected,

            
            "AcknowledgeTime": ack_time,

            "Aging (Days)": aging_days,
            "MTTR (Hours)": mttr_hours,

            "Subject": f"{alert_id} | {alert_title} | {affected_host}",
            "AlertSource": alert_source,
            "AffectedAsset": affected_host,
            "Severity": severity,
            "Risk Score": risk,
            "MITRETactic": mitre_tactic,
            "MITRETechnique": mitre_technique,

            "Status": "Open",
            "EmailStatus": "Email Sent",
            "Remarks": "Email Sent; awaiting response",
            "FollowUpCount": 0
        }

        df = pd.DataFrame([tracker])

        # =========================================
        # OUTPUT
        # =========================================

        st.subheader("Email Output")
        st.markdown(email_html, unsafe_allow_html=True)

        st.subheader("Tracker Data")
        st.dataframe(df)

# ============================
# CLOSE INCIDENT
# ============================
elif st.session_state.page == "close":

    st.title("Close Incident")

    if st.button("⬅ Back"):
        st.session_state.page = "home"

    st.info("Closure module ready to be integrated with your existing template.")
