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
using System.IO;
using System.Collections.Concurrent;

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
    OPCUA,
    ModBus,

    FTP,

    WebServices
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



            var semaphore = new SemaphoreSlim(50); // Maximale gleichzeitige Scans begrenzen
            var tasks = new List<Task>();

            foreach (var port in ports.Distinct())
            {
                await semaphore.WaitAsync();
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var portResult = new PortResult();
                        switch (service)
                        {
                            case ServiceType.RDP:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                                break;
                            case ServiceType.UltraVNC:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                                break;
                            case ServiceType.BigFixRemote:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                                break;
                            case ServiceType.Rustdesk:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                                break;
                            case ServiceType.Teamviewer:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                                break;
                            case ServiceType.Anydesk:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                                break;
                            case ServiceType.MSSQLServer:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);


                                //scan for dynamic sql ports
                                if (portResult.Status != PortStatus.IsRunning)
                                {
                                    int? dynamicPort = await GetMSSQLDynamicPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString());
                                    if (dynamicPort != null)
                                    {
                                        portResult.Port = (int)dynamicPort;
                                        portResult.Status = PortStatus.IsRunning;
                                    }
                                }

                                break;
                            case ServiceType.PostgreSQL:                                
                                break;
                            case ServiceType.MariaDB:
                                break;
                            case ServiceType.OracleDB:
                                break;
                            case ServiceType.OPCDA:
                                break;
                            case ServiceType.OPCUA:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                                break;
                            case ServiceType.ModBus:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                                break;
                            case ServiceType.FTP:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                                break;
                            case ServiceType.WebServices:
                                var serviceResult = new ServiceResult { Service = service };
                                portResult = await CheckWebServicePortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port);
                                break;
                            default:
                                portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
                                break;
                        }


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

            ipToScan.Services.Services.Add(serviceResult);
        }

        if (ipToScan.Services.Services.Count > 0)
        {
            int respondedValue = Interlocked.Increment(ref responded);
            ProgressUpdated?.Invoke(current, responded, total);

            ipToScan.UsedScanMethod = ScanMethod.Services;

            ServiceIPScanFinished?.Invoke(ipToScan); // Event auslösen
        }
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

                        byte[] buffer = new byte[4096]; // Größerer Buffer für TLS-Antwort
                        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);


                        //if (stream.DataAvailable)
                        if (bytesRead > 0)
                        {
                            portResult.Status = PortStatus.IsRunning;
                            string responseHex = BitConverter.ToString(buffer, 0, bytesRead).Replace("-", " ");

                            string responseAscii = Encoding.ASCII.GetString(buffer, 0, bytesRead).Replace("\r", "\\r").Replace("\n", "\\n").Replace("\0", "");  // Nullbytes entfernen
                            string filter = responseAscii.ToLower().Contains("anydesk") ? "found AnyDesk in server response." : "server replied, but AnyDesk wasn’t found in response.";

                            portResult.PortLog = filter;
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
            ServiceType.WebServices => new List<int> { 80, 443, 8080, 8443 },
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
            ServiceType.ModBus => new List<int> { 502 },
            ServiceType.FTP => new List<int> { 21 },
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
            ServiceType.BigFixRemote => new byte[] { 0x14, 0x2B, 0xB4, 0x91, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },

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

            //ServiceType.Anydesk => new byte[] { 0xf2, 0xa8, 0x1b, 0x9e, 0x18, 0xcc, 0x3b, 0x65, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xff, 0xff, 0x6a, 0x40, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02 },
            ServiceType.Anydesk => new byte[] 
            {
                 0x16, 0x03, 0x01, 0x00, 0xb7, 0x01, 0x00, 0x00, 0xb3, 0x03, 0x03, 0xf9, 0x37, 0x7f, 0xaa, 0xd3,
            0xa2, 0x95, 0x53, 0x76, 0xeb, 0xf1, 0x63, 0x7c, 0xa9, 0x23, 0x80, 0x4e, 0x48, 0x92, 0xc8, 0x90,
            0x8d, 0x6c, 0x03, 0x4c, 0xc5, 0xe3, 0x83, 0x79, 0xec, 0xb3, 0x8b, 0x00, 0x00, 0x38, 0xc0, 0x2c,
            0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
            0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14,
            0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c,
            0x00, 0x35, 0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0x52, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
            0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19,
            0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d,
            0x00, 0x2a, 0x00, 0x28, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09,
            0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
            0x03, 0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02
            },


            ServiceType.MSSQLServer => new byte[]
            {
                0x12, 0x01, 0x00, 0x66, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x06, 0x01, 0x00, 0x2a,
                0x00, 0x01, 0x02, 0x00, 0x2b, 0x00, 0x09, 0x03, 0x00, 0x34, 0x00, 0x04, 0x04, 0x00, 0x38, 0x00,
                0x01, 0x05, 0x00, 0x39, 0x00, 0x24, 0x06, 0x00, 0x5d, 0x00, 0x01, 0xff, 0x03, 0x0f, 0x5a, 0xfc,
                0x01, 0x00, 0x00, 0x6e, 0x65, 0x78, 0x65, 0x6e, 0x73, 0x6f, 0x73, 0x00, 0x00, 0x00, 0x2a, 0x60,
                0x00, 0xe9, 0xd5, 0x1f, 0xc3, 0x85, 0xa4, 0x0d, 0x46, 0x8b, 0xd1, 0x68, 0x48, 0x52, 0x80, 0x1d,
                0x28, 0xe2, 0xed, 0xe7, 0xba, 0xed, 0x5a, 0xaf, 0x49, 0xad, 0x3e, 0xb5, 0x19, 0xba, 0x6c, 0xcc,
                0xc6, 0x02, 0x00, 0x00, 0x00, 0x01
            },
            
            
            ServiceType.PostgreSQL => new byte[] { 0x00, 0x03, 0x00, 0x00 },
            ServiceType.MariaDB => new byte[] { 0x4d, 0x59, 0x53, 0x51, 0x4c },
            ServiceType.OracleDB => new byte[] { 0x30, 0x31, 0x30, 0x30 },
            ServiceType.OPCDA => new byte[] { 0x4f, 0x50, 0x43, 0x44, 0x41 },
            ServiceType.OPCUA => new byte[] { 0x48, 0x45, 0x4c, 0x4c, 0x4f },
            ServiceType.ModBus => new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 },
            ServiceType.FTP => new byte[]
            {
                0xCD, 0xCA, 0x00, 0x15, 0x5E, 0xE8, 0x15, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xFA, 0xF0,
                0x90, 0x80, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02
            },
            _ => new byte[0]
        };
    }

    private async Task<int?> GetMSSQLDynamicPortAsync(string serverIP)
    {
        using (UdpClient udpClient = new UdpClient())
        {
            udpClient.Client.ReceiveTimeout = 2000; // Timeout für Antwort setzen

            IPEndPoint sqlServerEndpoint = new IPEndPoint(IPAddress.Parse(serverIP), 1434);

            byte[] request = Encoding.ASCII.GetBytes("\x02"); // Anfrage für SQL-Browser-Information
            await udpClient.SendAsync(request, request.Length, sqlServerEndpoint);

            try
            {
                UdpReceiveResult response = await udpClient.ReceiveAsync();
                string responseText = Encoding.ASCII.GetString(response.Buffer);

                Console.WriteLine($"📡 SQL Browser Antwort: {responseText}");

                // 🔍 Suche nach "tcp;" im Antwortstring und extrahiere den Port
                int index = responseText.IndexOf("tcp;");
                if (index != -1)
                {
                    string portPart = responseText.Substring(index + 4).Split(';')[0];
                    if (int.TryParse(portPart, out int port))
                    {
                        return port; // ✅ Erfolgreich extrahierter Port
                    }
                }
            }
            catch (SocketException)
            {
                Console.WriteLine("⚠️ Keine Antwort vom SQL Browser-Dienst. Ist er aktiv?");
            }
        }

        return null; // ❌ Kein Port gefunden
    }





//private async Task<PortResult> CheckWebServicePortAsync(string ipAddress, int port)
//    {
//        PortResult portResult = new PortResult { Port = port, PortLog = "" };

//        using (var tcpClient = new TcpClient())
//        {
//            try
//            {
//                var connectTask = tcpClient.ConnectAsync(ipAddress, port);
//                var delayTask = Task.Delay(2000); // Timeout nach 2 Sekunden

//                if (await Task.WhenAny(connectTask, delayTask) == connectTask)
//                {
//                    portResult.Status = PortStatus.Open;

//                    // 📡 Falls es sich um einen Webservice handelt, Anfrage senden
//                    using (NetworkStream stream = tcpClient.GetStream())
//                    {
//                        // ⚡ HTTP-GET oder Modbus/MQTT Anfrage simulieren
//                        byte[] requestBytes = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: " + ipAddress + "\r\n\r\n");
//                        await stream.WriteAsync(requestBytes, 0, requestBytes.Length);

//                        // 📥 Antwort empfangen (bis zu 1024 Bytes)
//                        byte[] buffer = new byte[1024];
//                        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);

//                        if (bytesRead > 0)
//                        {
//                            string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
//                            portResult.PortLog += response;
//                            if (!string.IsNullOrEmpty(response)) portResult.Status = PortStatus.IsRunning;
//                        }
//                    }
//                }
//                else
//                {
//                    portResult.Status = PortStatus.NoResponse;
//                }
//            }
//            catch (SocketException ex)
//            {
//                switch (ex.SocketErrorCode)
//                {
//                    case SocketError.ConnectionRefused:
//                        portResult.Status = PortStatus.Closed;
//                        break;
//                    case SocketError.TimedOut:
//                        portResult.Status = PortStatus.Filtered;
//                        break;
//                    default:
//                        portResult.Status = PortStatus.UnknownResponse;
//                        break;
//                }
//            }
//        }
//        return portResult;
//    }





private async Task<PortResult> CheckWebServicePortAsync(string ipAddress, int port)
    {
        PortResult portResult = new PortResult { Port = port, PortLog = "" };

        using (var tcpClient = new TcpClient())
        {
            try
            {
                var connectTask = tcpClient.ConnectAsync(ipAddress, port);
                var delayTask = Task.Delay(2000); // Timeout nach 2 Sekunden

                if (await Task.WhenAny(connectTask, delayTask) == connectTask)
                {
                    portResult.Status = PortStatus.Open;

                    using (NetworkStream stream = tcpClient.GetStream())
                    {
                        // HTTP-GET Anfrage simulieren
                        byte[] requestBytes = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: " + ipAddress + "\r\n\r\n");
                        await stream.WriteAsync(requestBytes, 0, requestBytes.Length);

                        // 📥 Antwort empfangen
                        byte[] buffer = new byte[1024];

                        try
                        {
                            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);

                            if (bytesRead > 0)
                            {
                                string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                                portResult.PortLog += response;
                                if (!string.IsNullOrEmpty(response))
                                    portResult.Status = PortStatus.IsRunning;
                            }
                        }
                        catch (IOException ex)
                        {
                            portResult.Status = PortStatus.Closed;
                            portResult.PortLog += "❌ Verbindung wurde vom Remotehost geschlossen: " + ex.Message;
                        }
                        catch (ObjectDisposedException)
                        {
                            portResult.Status = PortStatus.Closed;
                            portResult.PortLog += "⚠️ Die Verbindung wurde unerwartet beendet.";
                        }
                    }
                }
                else
                {
                    portResult.Status = PortStatus.NoResponse;
                }
            }
            catch (SocketException ex)
            {
                switch (ex.SocketErrorCode)
                {
                    case SocketError.ConnectionRefused:
                        portResult.Status = PortStatus.Closed;
                        break;
                    case SocketError.TimedOut:
                        portResult.Status = PortStatus.Filtered;
                        break;
                    default:
                        portResult.Status = PortStatus.UnknownResponse;
                        break;
                }
            }
        }
        return portResult;
    }






}