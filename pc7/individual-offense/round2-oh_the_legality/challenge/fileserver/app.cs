using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

class Program
{
    static void Main(string[] args)
    {
        int port = 55454;
        string secretKey = "ERROR404";

        // Explicitly bind to all interfaces inside the container
        var localEp = new IPEndPoint(IPAddress.Any, port);
        using var udp = new UdpClient();

        // Allow receiving broadcast packets
        udp.EnableBroadcast = true;

        // Bind explicitly
        udp.Client.Bind(localEp);

        Console.WriteLine($"[INFO] UDP server bound to {localEp.Address}:{port}");
        Console.WriteLine("[INFO] Waiting for packets...");

        var remoteEp = new IPEndPoint(IPAddress.Any, 0);

        while (true)
        {
            try
            {
                byte[] receivedBytes = udp.Receive(ref remoteEp);
                string receivedData = Encoding.UTF8.GetString(receivedBytes);

                Console.WriteLine($"[INFO] Received {receivedBytes.Length} bytes from {remoteEp.Address}:{remoteEp.Port}");
                Console.WriteLine($"[DEBUG] Raw data: {receivedData}");

                CommandData? commandData;
                try
                {
                    commandData = JsonSerializer.Deserialize<CommandData>(receivedData);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] JSON parse failed: {ex.Message}");
                    SendUdpResponse(udp, remoteEp, $"[ERROR] Invalid JSON: {ex.Message}");
                    continue;
                }

                if (commandData?.Key == null || commandData.Command == null)
                {
                    Console.WriteLine("[ERROR] Missing key or command.");
                    SendUdpResponse(udp, remoteEp, "[ERROR] Missing key or command.");
                    continue;
                }

                if (commandData.Key != secretKey)
                {
                    Console.WriteLine("[WARN] Invalid secret key.");
                    SendUdpResponse(udp, remoteEp, "[ERROR] Invalid secret key.");
                    continue;
                }

                Console.WriteLine("[INFO] Key matched. Executing command...");
                string output = ExecuteShellCommand(commandData.Command);

                Console.WriteLine("[OUTPUT]");
                Console.WriteLine(output);

                SendUdpResponse(udp, remoteEp, output);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Exception in loop: {ex}");
                // keep looping
            }
        }
    }

    static void SendUdpResponse(UdpClient udp, IPEndPoint remoteEp, string message)
    {
        try
        {
            byte[] response = Encoding.UTF8.GetBytes(message ?? "");
            int sent = udp.Send(response, response.Length, remoteEp);
            Console.WriteLine($"[INFO] Sent UDP response ({sent} bytes) to {remoteEp.Address}:{remoteEp.Port}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to send UDP response: {ex}");
        }
    }

    static string ExecuteShellCommand(string command)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "pwsh",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-Command");
            psi.ArgumentList.Add(command);

            using var process = Process.Start(psi);
            if (process == null)
                return "[EXCEPTION] Failed to start pwsh process (Process.Start returned null).";

            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            string combined = (stdout ?? "") + (stderr ?? "");
            if (string.IsNullOrWhiteSpace(combined))
                combined = $"[INFO] Command ran with no output. ExitCode={process.ExitCode}";

            return combined + $"\n[INFO] ExitCode={process.ExitCode}\n";
        }
        catch (Exception ex)
        {
            return "[EXCEPTION] " + ex;
        }
    }
}

class CommandData
{
    public string? Key { get; set; }
    public string? Command { get; set; }
}
