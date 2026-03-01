from flask import Flask, request
import nmap
import requests as req

app = Flask(__name__)

def scan_target(target):
    nm = nmap.PortScanner()
    nm.scan(target, "1-1000", arguments="-sV")
    
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                state = nm[host][proto][port]["state"]
                service = nm[host][proto][port]["name"]
                version = nm[host][proto][port]["version"]
                if state == "open":
                    results.append((port, service, version))
    return results

def build_table(results, target):
    rows = ""
    for port, service, version in results:
        danger_ports = {22: "⚠️ SSH", 21: "🔴 FTP", 80: "🟡 HTTP", 443: "🟢 HTTPS", 3306: "🔴 MySQL"}
        danger = danger_ports.get(port, "🔵 Kiểm tra")
        rows += f"""
        <tr>
            <td>{port}</td>
            <td style="color:#00ff00">OPEN</td>
            <td>{service}</td>
            <td>{version}</td>
            <td>{danger}</td>
        </tr>"""
    
    return f"""
    <html>
    <head>
        <title>Scan Result - {target}</title>
        <style>
            body {{ background:#0a0a0a; color:white; font-family:monospace; padding:30px }}
            h1 {{ color:#00d4ff }}
            table {{ width:100%; border-collapse:collapse; margin-top:20px }}
            th {{ background:#1a1f2e; color:#00d4ff; padding:12px; text-align:left }}
            td {{ padding:12px; border-bottom:1px solid #2a2a2a }}
            tr:hover {{ background:#1a1f2e55 }}
            .back {{ color:#00d4ff; text-decoration:none }}
        </style>
    </head>
    <body>
        <h1>🛡️ Kết quả scan: {target}</h1>
        <a class="back" href="/">← Scan lại</a>
        <table>
            <tr>
                <th>Port</th><th>Trạng thái</th>
                <th>Dịch vụ</th><th>Phiên bản</th><th>Nguy hiểm</th>
            </tr>
            {rows}
        </table>
        <p style="margin-top:20px;color:#888">Tổng port mở: {len(results)}</p>
    </body>
    </html>"""

@app.route("/")
def index():
    return """
    <html>
    <head>
        <title>Security Scanner</title>
        <style>
            body {{ background:#0a0a0a; color:white; font-family:monospace; padding:50px; text-align:center }}
            h1 {{ color:#00d4ff; margin-bottom:30px }}
            input {{ padding:12px; width:300px; background:#1a1a1a; color:white; border:1px solid #00d4ff; border-radius:5px; font-size:16px }}
            button {{ padding:12px 25px; background:#00d4ff; color:black; border:none; border-radius:5px; cursor:pointer; font-size:16px; margin-left:10px; font-weight:bold }}
            button:hover {{ background:#0099bb }}
            p {{ color:#888; margin-top:20px }}
        </style>
    </head>
    <body>
        <h1>🛡️ Network Security Scanner</h1>
        <form action="/scan" method="POST">
            <input name="target" placeholder="Nhập IP hoặc domain...">
            <button type="submit">Scan!</button>
        </form>
        <p>Ví dụ: scanme.nmap.org</p>
    </body>
    </html>
    """

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form["target"]
    results = scan_target(target)
    return build_table(results, target)

if __name__ == "__main__":
    app.run(debug=True)
