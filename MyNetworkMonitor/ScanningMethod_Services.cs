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
    IsRunning
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

            foreach (var port in ports.Distinct())
            {
                var portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                
                serviceResult.Ports.Add(portResult);               
            }

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
    {
        return service switch
        {
            ServiceType.RDP => new List<int> { 3389 },
            ServiceType.UltraVNC => new List<int> { 5900 },
            ServiceType.BigFixRemote => new List<int> { 52311 },
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
            ServiceType.BigFixRemote => new byte[] { 0x42, 0x49, 0x47, 0x46, 0x49, 0x58 },
            ServiceType.Rustdesk => new byte[] { 0x52, 0x44, 0x50 },
            ServiceType.Teamviewer => new byte[] { 0x54, 0x56, 0x00, 0x01 },
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
