import streamlit as st
import json
import concurrent.futures
import time
import main  # Import backend functions

# Streamlit Page Configuration
st.set_page_config(
    page_title="Automated Penetration Testing Tool",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🔍 Automated Penetration Testing Tool")

# Sidebar Configuration
st.sidebar.header("⚙️ Scan Configuration")
target_ips = st.sidebar.text_area("Enter Target IPs (comma-separated)").strip()
target_list = [ip.strip() for ip in target_ips.split(",") if ip.strip()]

# Add Tabs for Scanning & Exploitation
tab1, tab2 = st.tabs(["🛡️ Scanning", "💀 Exploitation"])

scan_results = {}  # Store results globally

with tab1:
    st.subheader("🎯 Target Scanning")

    if st.sidebar.button("🚀 Start Scan"):
        if not target_list:
            st.sidebar.error("❌ Please enter at least one valid target IP!")
        else:
            st.sidebar.success("🔍 Scanning in progress... Please wait.")

            progress_bar = st.progress(0)
            scan_results = {}

            # Run scanning in a separate thread to prevent UI freeze
            def scan_target(target):
                return {target: main.scan_target(target)}

            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_results = {executor.submit(scan_target, target): target for target in target_list}

                for i, future in enumerate(concurrent.futures.as_completed(future_results)):
                    result = future.result()
                    scan_results.update(result)
                    progress_bar.progress((i + 1) / len(target_list))
                    st.write(f"✅ Scan completed for `{list(result.keys())[0]}`")

            progress_bar.empty()
            st.sidebar.success("✅ Scan Completed!")
            st.json(scan_results)

            # Display results dynamically
            for target, results in scan_results.items():
                st.subheader(f"📌 Results for {target}")
                for entry in results:
                    with st.expander(f"🔍 Port {entry['port']}: {entry['service']} ({entry['version']})"):
                        st.write(f"**🔢 Port:** {entry['port']}")
                        st.write(f"**🖥 Service:** {entry['service']} ({entry['version']})")
                        st.write(f"**📝 Banner:** {entry.get('banner', 'N/A')}")
                        st.write("🛑 **Vulnerabilities:**")
                        st.write(", ".join(entry["vulnerabilities"]))
                        st.write("💥 **Possible Exploits:**")
                        for exploit in entry["exploits"]:
                            st.markdown(f"- [{exploit['CVE']}]({exploit['exploit_url']})")
                st.markdown("---")

            # Save Scan Report
            with open("scan_results.json", "w") as file:
                json.dump(scan_results, file, indent=4)
            st.sidebar.download_button("📥 Download Report", "scan_results.json", file_name="scan_results.json")

with tab2:
    st.subheader("💀 Exploitation")

    if not target_list:
        st.warning("⚠️ Please enter and scan targets before exploiting.")
    else:
        selected_target = st.selectbox("🎯 Select Target", target_list)
        exploit_options = [
            "SMB Exploit (EternalBlue)",
            "SQL Injection Scanner",
            "LFI Scanner",
            "Brute Force Attack"
        ]
        selected_exploit = st.selectbox("💣 Select Exploit Type", exploit_options)

        if st.button("🔥 Launch Exploit"):
            if selected_target and selected_exploit:
                st.warning(f"⚠️ Running `{selected_exploit}` on `{selected_target}`... Please wait.")
                exploit_result = main.run_exploit(selected_target, selected_exploit)
                st.success(exploit_result)
            else:
                st.error("❌ Please select a valid target and exploit!")

# Footer
st.markdown(
    "🚀 **Automated Penetration Testing Tool v2.0** - Built with Streamlit, Nmap, and ExploitDB | Developed by CyberSec Enthusiasts 🛡️"
)
