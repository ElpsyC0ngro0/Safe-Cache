import tkinter as tk
from tkinter import messagebox, scrolledtext
import dns.resolver
import dns.query
import dns.dnssec
import dns.message
import dns.rdatatype

# ---------------------------- DNS MODULES ----------------------------

def get_dns_record(domain, dns_server):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    try:
        answer = resolver.resolve(domain, 'A')
        ip_address = answer[0].address
        ttl = answer.rrset.ttl
        return ip_address, ttl
    except Exception:
        return None, None

def compare_ttl(domain, local_dns, trusted_dns):
    local_ip, local_ttl = get_dns_record(domain, local_dns)
    trusted_ip, trusted_ttl = get_dns_record(domain, trusted_dns)
    output = "\n🟢 [TTL MODULE]\n"
    output += f"Local DNS ({local_dns}) - IP: {local_ip}, TTL: {local_ttl}\n"
    output += f"Trusted DNS ({trusted_dns}) - IP: {trusted_ip}, TTL: {trusted_ttl}\n"
    if local_ip != trusted_ip:
        output += "⚠️ ALERT: DNS Cache Poisoning suspected! IP addresses do not match.\n"
    else:
        output += "✅ No DNS Cache Poisoning detected.\n"
    return output

def compare_tcp_udp(domain, dns_server):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    try:
        udp_answer = resolver.resolve(domain, 'A', tcp=False)
        tcp_answer = resolver.resolve(domain, 'A', tcp=True)
        udp_ip = udp_answer[0].address
        tcp_ip = tcp_answer[0].address
        udp_ttl = udp_answer.rrset.ttl
        tcp_ttl = tcp_answer.rrset.ttl

        output = "\n🔵 [TCP/UDP MODULE]\n"
        output += f"UDP - IP: {udp_ip}, TTL: {udp_ttl}\n"
        output += f"TCP - IP: {tcp_ip}, TTL: {tcp_ttl}\n"
        if udp_ip != tcp_ip or udp_ttl != tcp_ttl:
            output += "⚠️ ALERT: DNS Cache Poisoning suspected due to mismatch!\n"
        else:
            output += "✅ No DNS Cache Poisoning detected.\n"
        return output
    except Exception as e:
        return f"\n🔵 [TCP/UDP MODULE] ❌ Error: {e}\n"

def verify_dnssec(domain, dns_server):
    try:
        query = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
        response = dns.query.udp(query, dns_server, timeout=3)

        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, dns_server, timeout=3)

        if response.rcode() != dns.rcode.NOERROR:
            return f"\n🟣 [DNSSEC MODULE] ⚠️ DNS query failed for {domain}: {dns.rcode.to_text(response.rcode())}\n"

        if not response.flags & dns.flags.AD:
            return f"\n🟣 [DNSSEC MODULE] ⚠️ DNSSEC validation NOT authenticated (no AD flag) for {domain}.\n"

        return f"\n🟣 [DNSSEC MODULE] ✅ DNSSEC validation PASSED for {domain} on {dns_server}.\n"

    except dns.exception.Timeout:
        return f"\n🟣 [DNSSEC MODULE] ❌ Timeout while querying {domain}.\n"
    except Exception as e:
        return f"\n🟣 [DNSSEC MODULE] ❌ Unexpected error for {domain}: {e}\n"

# ---------------------------- GUI ACTIONS ----------------------------

def get_inputs():
    return domain_entry.get(), local_dns_entry.get(), trusted_dns_entry.get()

def run_ttl_module():
    domain, local_dns, trusted_dns = get_inputs()
    if not domain or not local_dns or not trusted_dns:
        messagebox.showwarning("Input Error", "Please enter all fields.")
        return
    output = compare_ttl(domain, local_dns, trusted_dns)
    output_box.insert(tk.END, output)

def run_tcp_udp_module():
    domain, _, trusted_dns = get_inputs()
    if not domain or not trusted_dns:
        messagebox.showwarning("Input Error", "Please enter Domain and Trusted DNS.")
        return
    output = compare_tcp_udp(domain, trusted_dns)
    output_box.insert(tk.END, output)

def run_dnssec_module():
    domain, _, trusted_dns = get_inputs()
    if not domain or not trusted_dns:
        messagebox.showwarning("Input Error", "Please enter Domain and Trusted DNS.")
        return
    output = verify_dnssec(domain, trusted_dns)
    output_box.insert(tk.END, output)

def run_all():
    output_box.delete(1.0, tk.END)
    run_ttl_module()
    run_tcp_udp_module()
    run_dnssec_module()

# ---------------------------- GUI DESIGN ----------------------------

root = tk.Tk()
root.title("🛡️ SAFE-CACHE DNS Security Toolkit")
root.configure(bg="#1e1e2f")
root.geometry("900x700")

title_label = tk.Label(root, text="SAFE-CACHE DNS Security Toolkit", font=("Helvetica", 20, "bold"), bg="#1e1e2f", fg="#00ffe7")
title_label.pack(pady=10)

frame = tk.Frame(root, bg="#1e1e2f")
frame.pack(pady=5)

def styled_entry(parent):
    return tk.Entry(parent, width=50, font=("Consolas", 12), bg="#2b2b3c", fg="#ffffff", insertbackground="white")

tk.Label(frame, text="Domain:", bg="#1e1e2f", fg="#ffffff", font=("Consolas", 12)).grid(row=0, column=0, sticky="e")
domain_entry = styled_entry(frame)
domain_entry.grid(row=0, column=1, padx=5)

tk.Label(frame, text="Local DNS Server:", bg="#1e1e2f", fg="#ffffff", font=("Consolas", 12)).grid(row=1, column=0, sticky="e")
local_dns_entry = styled_entry(frame)
local_dns_entry.grid(row=1, column=1, padx=5)

tk.Label(frame, text="Trusted DNS Server:", bg="#1e1e2f", fg="#ffffff", font=("Consolas", 12)).grid(row=2, column=0, sticky="e")
trusted_dns_entry = styled_entry(frame)
trusted_dns_entry.grid(row=2, column=1, padx=5)

button_frame = tk.Frame(root, bg="#1e1e2f")
button_frame.pack(pady=20)

def styled_button(parent, text, cmd, bg_color):
    return tk.Button(parent, text=text, command=cmd, font=("Helvetica", 10, "bold"), bg=bg_color, fg="white", padx=10, pady=5)

styled_button(button_frame, "Run TTL Module", run_ttl_module, "#6c63ff").grid(row=0, column=0, padx=8)
styled_button(button_frame, "Run TCP/UDP Module", run_tcp_udp_module, "#f77f00").grid(row=0, column=1, padx=8)
styled_button(button_frame, "Run DNSSEC Module", run_dnssec_module, "#4ecdc4").grid(row=0, column=2, padx=8)
styled_button(button_frame, "Run FULL SAFE-CACHE Analysis", run_all, "#009688").grid(row=0, column=3, padx=8)

output_box = scrolledtext.ScrolledText(root, width=110, height=25, font=("Consolas", 10), bg="#12121c", fg="#00ffcc", insertbackground="white")
output_box.pack(padx=10, pady=20)

root.mainloop()
