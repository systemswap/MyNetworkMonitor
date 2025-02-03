using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Threading.Tasks;
using System.Threading;
using System.Text;
using MyNetworkMonitor;
using System.Runtime.ConstrainedExecution;
using static MyNetworkMonitor.ServiceScanData;
using System.Data;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public enum ServiceType
{
    // Remote Apps
    RDP,
    UltraVNC,
    BigFixRemote,
    Rustdesk,
    Teamviewer,
    Anydesk,

    // Datenbanken
    MSSQLServer,
    PostgreSQL,
    MariaDB,
    OracleDB,

    // Industrieprotokolle
    OPCDA,
    OPCUA
}

public enum PortStatus
{
    Open,
    Filtered,
    NoResponse,
    Closed,
    IsRunning,
    UnknownResponse,
    Error
}


//public class PortResult
//{
//    public int Port { get; set; }
//    public PortStatus Status { get; set; }
//    public string PortLog { get; set; }
//}

//public class ServiceResult
//{
//    public ServiceType Service { get; set; }
//    public List<PortResult> Ports { get; set; } = new List<PortResult>();
//}

//public class ServiceScanResult
//{
//    public string IP { get; set; }
//    public List<ServiceResult> Services { get; set; } = new List<ServiceResult>();
//}

public class ScanningMethod_Services
{
    private const int MaxParallelIPs = 10;
    private const int Timeout = 3000; // 3 Sekunden Timeout pro Dienst
    private const int RetryCount = 3;
    
    public event Action<IPToScan> ServiceIPScanFinished;
    //public event Action<ServiceScanResult> ServiceIPScanFinished;
    public event Action<int, int, int> ProgressUpdated;
    public event Action ServiceScanFinished;


    private int current = 0;
    private int responded = 0;
    private int total = 0;

    public async Task ScanIPsAsync(List<IPToScan> IPsToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts = null)
    {
        current = 0;
        responded = 0;
        total = IPsToScan.Count;

        var semaphore = new SemaphoreSlim(MaxParallelIPs);
        var tasks = IPsToScan.Select(async ipToScan =>
        {
            await semaphore.WaitAsync();
            try
            {
                int currentValue = Interlocked.Increment(ref current);
                ProgressUpdated?.Invoke(current, responded, total);

                await Task.Run(() => ScanIPAsync(ipToScan, services, extraPorts));

            }
            finally
            {
                semaphore.Release();
            }
        }).ToArray();

        await Task.WhenAll(tasks);

        // ✅ Garantiert: SMBScanFinished wird NUR ausgelöst, wenn alle SMB-Scans beendet sind
        ServiceScanFinished?.Invoke();
    }

    //private async Task<ServiceScanResult> ScanIPAsync(IPToScan ipToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts)
    private async Task ScanIPAsync(IPToScan ipToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts)
    {
        //var result = new ServiceScanResult { IP = ipToScan.IPorHostname };
       

        foreach (ServiceType service in services)
        {
            var serviceResult = new ServiceResult { Service = service };            
            var ports = GetServicePorts(service);

            if (extraPorts != null && extraPorts.ContainsKey(service))
            {
                ports.AddRange(extraPorts[service]);
            }

            var detectionPacket = GetDetectionPacket(service);

            //foreach (var port in ports.Distinct())
            //{
            //    var portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);

            //    if (service == ServiceType.Teamviewer)
            //    {
            //        // 🔹 Prüfe TeamViewer auf Port 443 (TLS)
            //        bool isTlsAvailable = await CheckTLSHandshakeAsync(ipToScan.IPorHostname, 443);
            //        Console.WriteLine(isTlsAvailable ? "✅ TLS (Port 443) verfügbar" : "❌ Kein TLS (Port 443)");

            //        // 🔹 Prüfe TeamViewer auf Port 80 (HTTP)
            //        bool isHttpAvailable = await CheckHttpGetAsync(ipToScan.IPorHostname, 80);
            //        Console.WriteLine(isHttpAvailable ? "✅ HTTP (Port 80) verfügbar" : "❌ Kein HTTP (Port 80)");
            //    }
            //    serviceResult.Ports.Add(portResult);               
            //}




            //await Parallel.ForEachAsync(ports.Distinct(), async (port, _) =>
            //{
            //    var portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);

            //    if (service == ServiceType.Teamviewer)
            //    {
            //        // 🔹 Prüfe TeamViewer auf Port 443 (TLS)
            //        bool isTlsAvailable = await CheckTLSHandshakeAsync(ipToScan.IPorHostname, 443);
            //        Console.WriteLine(isTlsAvailable ? "✅ TLS (Port 443) verfügbar" : "❌ Kein TLS (Port 443)");

            //        // 🔹 Prüfe TeamViewer auf Port 80 (HTTP)
            //        bool isHttpAvailable = await CheckHttpGetAsync(ipToScan.IPorHostname, 80);
            //        Console.WriteLine(isHttpAvailable ? "✅ HTTP (Port 80) verfügbar" : "❌ Kein HTTP (Port 80)");
            //    }


            //    lock (serviceResult.Ports) // Sicherstellen, dass parallele Schreibzugriffe vermieden werden
            //    {
            //        serviceResult.Ports.Add(portResult);
            //    }
            //});



            var semaphore = new SemaphoreSlim(50); // Maximale gleichzeitige Scans begrenzen
            var tasks = new List<Task>();

            foreach (var port in ports.Distinct())
            {
                await semaphore.WaitAsync();
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);

                        lock (serviceResult.Ports) // Schutz vor parallelen Schreibzugriffen
                        {
                            serviceResult.Ports.Add(portResult);
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            // **Parallel ausführen & warten**
            await Task.WhenAll(tasks);





            //result.Services.Add(serviceResult);
            ipToScan.Services.Services.Add(serviceResult);
        }

        //if (result.Services.Count > 0)
        if (ipToScan.Services.Services.Count > 0)
        {
            int respondedValue = Interlocked.Increment(ref responded);
            ProgressUpdated?.Invoke(current, responded, total);

            ipToScan.UsedScanMethod = ScanMethod.Services;


            ServiceIPScanFinished?.Invoke(ipToScan); // Event auslösen            
            //ServiceIPScanFinished?.Invoke(result); // Event auslösen            
        }

        //return result;
        //return ipToScan;
    }

    private async Task<PortResult> ScanPortAsync(string ip, int port, byte[] detectionPacket)
    {
        PortResult portResult = new PortResult();
        portResult.Port = port;

        for (int attempt = 1; attempt <= RetryCount; attempt++)
        {
            using var client = new TcpClient();
            try
            {
                try
                {
                    using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                    {
                        socket.Blocking = false;
                        IAsyncResult result = socket.BeginConnect(ip, port, null, null);
                        bool success = result.AsyncWaitHandle.WaitOne(Timeout);

                        if (!success)
                        {
                            portResult.Status = PortStatus.Filtered;
                            portResult.PortLog += "Timeout, Port möglicherweise durch Firewall blockiert.";
                            return portResult;
                        }

                        try
                        {
                            socket.EndConnect(result);
                            portResult.Status = PortStatus.Open;
                        }
                        catch (SocketException ex)
                        {
                            if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                            {
                                portResult.Status = PortStatus.Closed;
                                portResult.PortLog += "Verbindung verweigert. Kein Dienst lauscht auf diesem Port.";
                            }
                            else
                            {
                                portResult.Status = PortStatus.NoResponse;
                                portResult.PortLog += "Unbekannter Verbindungsfehler: " + ex.Message;
                            }
                            return portResult;
                        }
                    }
                }
                catch (Exception ex)
                {
                    portResult.Status = PortStatus.Closed;
                    portResult.PortLog += "Unbekannter Fehler: " + ex.Message;
                }


                var connectTask = client.ConnectAsync(ip, port);
                if (await Task.WhenAny(connectTask, Task.Delay(Timeout)) != connectTask)
                {
                    portResult.Status = PortStatus.Closed;
                    portResult.PortLog += "Timeout:";
                }

                if (detectionPacket.Length > 0)
                {
                    try
                    {
                        using var stream = client.GetStream();
                        await stream.WriteAsync(detectionPacket, 0, detectionPacket.Length);
                        await Task.Delay(500);

                        if (stream.DataAvailable)
                        {
                            portResult.Status = PortStatus.IsRunning;
                        }
                        else
                        {
                            portResult.Status = PortStatus.NoResponse;
                            portResult.PortLog += "open, no application behind";
                        }
                    }
                    catch (Exception ex)
                    {
                        throw;
                    }
                }

                return portResult;
            }
            catch (SocketException ex)
            {
                if (attempt == RetryCount)
                {
                    //return new PortResult { Port = port, Status = PortStatus.Closed, PortLog = ex.Message };
                    portResult.Status = PortStatus.Closed;
                    portResult.PortLog += ex.Message;
                }
            }
        }

        //return new PortResult { Port = port, Status = PortStatus.Closed, PortLog = "Unbekannter Fehler" };
        portResult.PortLog = "unknown error";
        return portResult;
    }

   

    private static List<int> GetServicePorts(ServiceType service)
    {   DataTable dt = new DataTable();
        dt.Columns.Add("active", typeof(bool));
        dt.Columns.Add("ServiceType", typeof(string));
        dt.Columns.Add("Port", typeof(int));

        dt.Rows.Add(true, "RDP", 3389);
        dt.Rows.Add(true, "UltraVNC", 5900);
        dt.Rows.Add(true, "UltraVNC", 5901);
        dt.Rows.Add(true, "UltraVNC", 5902);
        dt.Rows.Add(true, "UltraVNC", 5903);
        dt.Rows.Add(true, "BigFixRemote", 52311);
        dt.Rows.Add(true, "Rustdesk", 21115);
        dt.Rows.Add(true, "Teamviewer", 5938);
        //dt.Rows.Add(true, "Teamviewer", 443);
        //dt.Rows.Add(true, "Teamviewer", 80);
        dt.Rows.Add(true, "Anydesk", 7070);
        dt.Rows.Add(true, "MSSQLServer", 1433);
        dt.Rows.Add(true, "PostgreSQL", 5432);
        dt.Rows.Add(true, "MariaDB", 3306);
        dt.Rows.Add(true, "OracleDB", 1521);
        dt.Rows.Add(true, "OPCDA", 135);
        dt.Rows.Add(true, "OPCUA", 4840);


        return service switch
        {
            ServiceType.RDP => new List<int> { 3389 },
            ServiceType.UltraVNC => new List<int> { 5900, 5901, 5902, 5903 },
            ServiceType.BigFixRemote => new List<int> { 888 },
            ServiceType.Rustdesk => new List<int> { 21115 },
            ServiceType.Teamviewer => new List<int> { 5938 },
            ServiceType.Anydesk => new List<int> { 7070 },
            ServiceType.MSSQLServer => new List<int> { 1433 },
            ServiceType.PostgreSQL => new List<int> { 5432 },
            ServiceType.MariaDB => new List<int> { 3306 },
            ServiceType.OracleDB => new List<int> { 1521 },
            ServiceType.OPCDA => new List<int> { 135 },
            ServiceType.OPCUA => new List<int> { 4840 },
            _ => new List<int>()
        };
    }

    public static byte[] GetDetectionPacket(ServiceType service)
    {
        return service switch
        {
            ServiceType.RDP => new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 },
            ServiceType.UltraVNC => new byte[] { 0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33 },
            //ServiceType.BigFixRemote => new byte[] { 0x42, 0x49, 0x47, 0x46, 0x49, 0x58 },
            ServiceType.BigFixRemote => new byte[] { 0x14, 0x2B, 0xB4, 0x91, 0x05, 0x02},


            ServiceType.Rustdesk => new byte[] { 0x52, 0x44, 0x50 },


            ////Teamviewer 11-15
            ServiceType.Teamviewer => new byte[]
            {
                0x17, 0x24, 0x0A, 0x20, 0x00, 0xE1, 0xBF, 0xE5,
                0x2A, 0x88, 0x13, 0x80, 0x00, 0x48, 0x00, 0x80,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x80, 0x00,
                0x00, 0x4F, 0xB3, 0x80, 0x80, 0x6E, 0xBD, 0xF3,
                0x9B, 0x8E, 0xDF, 0xA9, 0x03
            },
            ////Teamviewer 15
            //ServiceType.Teamviewer => new byte[]
            // {
            //     0x11, 0x30, 0x0A, 0x00, 0x28, 0x00, 0x00, 0x00,
            //     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            //     0x1B, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
            //     0x61, 0xBF, 0xE5, 0x2A, 0x88, 0x13, 0x80, 0x00,
            //     0x48, 0x00, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00,
            //     0x14, 0x80, 0x00, 0x00, 0x6D, 0xB7, 0x8C, 0x80,
            //     0x6E, 0xBD, 0xD3, 0x9B, 0x8E, 0xDF, 0xA9, 0x1C,
            //     0xE1, 0xBF, 0xE5, 0x2A, 0x80, 0x00, 0x00, 0x00
            // },

            ServiceType.Anydesk => new byte[] { 0x41, 0x4e, 0x59, 0x44, 0x45, 0x53, 0x4b },
            ServiceType.MSSQLServer => new byte[] { 0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x01, 0x00 },
            ServiceType.PostgreSQL => new byte[] { 0x00, 0x03, 0x00, 0x00 },
            ServiceType.MariaDB => new byte[] { 0x4d, 0x59, 0x53, 0x51, 0x4c },
            ServiceType.OracleDB => new byte[] { 0x30, 0x31, 0x30, 0x30 },
            ServiceType.OPCDA => new byte[] { 0x4f, 0x50, 0x43, 0x44, 0x41 },
            ServiceType.OPCUA => new byte[] { 0x48, 0x45, 0x4c, 0x4c, 0x4f },
            _ => new byte[0]
        };
    }





    public async Task<bool> CheckTLSHandshakeAsync(string ipAddress, int port)
    {
        try
        {
            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync(ipAddress, port);
                using (SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null))
                {
                    await sslStream.AuthenticateAsClientAsync(ipAddress);
                    return sslStream.IsAuthenticated; // ✅ TLS-Handshake erfolgreich?
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ TLS-Handshake auf Port {port} fehlgeschlagen: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> CheckHttpGetAsync(string ipAddress, int port)
    {
        try
        {
            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync(ipAddress, port);
                using (NetworkStream stream = client.GetStream())
                {
                    string httpRequest = "GET / HTTP/1.1\r\nHost: " + ipAddress + "\r\nConnection: Close\r\n\r\n";
                    byte[] requestBytes = Encoding.ASCII.GetBytes(httpRequest);

                    await stream.WriteAsync(requestBytes, 0, requestBytes.Length);
                    stream.Flush();

                    byte[] buffer = new byte[1024];
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);

                    string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    return response.Contains("HTTP"); // ✅ Antwort sieht aus wie HTTP?
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ HTTP-Anfrage auf Port {port} fehlgeschlagen: {ex.Message}");
            return false;
        }
    }

    private static bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        return true; // Akzeptiere alle Zertifikate (nur für Scanning-Zwecke)
    }


    public string GetFormattedOutput(ServiceScanResult services)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Scan-Ergebnisse für IP: {services.IP}\n");

        foreach (var service in services.Services)
        {
            sb.AppendLine($"Service: {service.Service}");
            sb.AppendLine(new string('-', 40));
            foreach (var port in service.Ports)
            {
                sb.AppendLine($"  Port: {port.Port}");
                sb.AppendLine($"  Status: {port.Status}");
                if (!string.IsNullOrWhiteSpace(port.PortLog))
                {
                    sb.AppendLine($"  Log: {port.PortLog}");
                }
                sb.AppendLine();
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }


}
