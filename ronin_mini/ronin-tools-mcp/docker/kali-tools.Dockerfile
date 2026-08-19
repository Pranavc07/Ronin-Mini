# Purpose-built image for the network_exploit category's Kali tools --
# exactly what Ronin needs today, not the full Kali toolset. New tools get
# added here one at a time when a concrete capability gap shows up (same
# discipline as skills/*.md growing 4 -> 14), not preemptively.
#
# Long-lived container, not ephemeral like execute_python's sandbox -- see
# executor.py's ensure_kali_container_ready()/run_in_kali_container().
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    sqlmap \
    hydra \
    wordlists \
    seclists \
    gobuster \
    enum4linux-ng \
    exploitdb \
    metasploit-framework \
    && gunzip -k /usr/share/wordlists/rockyou.txt.gz \
    && rm -rf /var/lib/apt/lists/*

# No `msfdb init` -- msfconsole works fine database-less for scripted,
# non-interactive use (categories/metasploit.py always drives it via
# `-r <resource-script>`), and skipping it keeps the image build simpler.
