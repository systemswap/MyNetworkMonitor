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
using System.Windows;
using System.Printing;


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



public enum ServiceType
{
    // 🌍 Netzwerk-Dienste
    WebServices,
    DNS_TCP,
    DNS_UDP,
    DHCP,
    SSH,
    FTP,

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
    MySQL,

    // Industrieprotokolle
    OPCUA,
    ModBus,
    S7
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
    bool scanDHCP = true;
    List<string> DHCP_Server_IPs = new List<string>();

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

    //public async Task ScanIPsAsync(List<IPToScan> IPsToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts = null)
    //{
    //    current = 0;
    //    responded = 0;
    //    total = IPsToScan.Count;

    //    var semaphore = new SemaphoreSlim(MaxParallelIPs);
    //    var tasks = IPsToScan.Select(async ipToScan =>
    //    {
    //        await semaphore.WaitAsync();
    //        try
    //        {
    //            int currentValue = Interlocked.Increment(ref current);
    //            ProgressUpdated?.Invoke(current, responded, total);

    //            await Task.Run(() => ScanIPAsync(ipToScan, services, extraPorts));

    //        }
    //        finally
    //        {
    //            semaphore.Release();
    //        }
    //    }).ToArray();

    //    await Task.WhenAll(tasks);

    //    // ✅ Garantiert: SMBScanFinished wird NUR ausgelöst, wenn alle SMB-Scans beendet sind
    //    ServiceScanFinished?.Invoke();
    //}


    public async Task ScanIPsAsync(List<IPToScan> IPsToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts = null)
    {
        bool scanDHCP = true;
        DHCP_Server_IPs.Clear();

        current = 0;
        responded = 0;
        total = IPsToScan.Count;

        var semaphore = new SemaphoreSlim(MaxParallelIPs);
        var tasks = new List<Task>();

        foreach (var ipToScan in IPsToScan)
        {
            await semaphore.WaitAsync(); // ✅ Wartet, bis ein neuer Slot frei ist
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    int currentValue = Interlocked.Increment(ref current);

                    // 🔹 Sicherstellen, dass UI-Updates nicht blockieren
                    await Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        ProgressUpdated?.Invoke(current, responded, total);
                    });

                    await ScanIPAsync(ipToScan, services, extraPorts);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Fehler beim Scannen von {ipToScan.IPorHostname}: {ex.Message}");
                }
                finally
                {
                    semaphore.Release(); // ✅ Stellt sicher, dass das Semaphore freigegeben wird
                }
            }));
        }

        // ✅ Prüft regelmäßig den Fortschritt, um Hänger zu vermeiden
        while (tasks.Any())
        {
            Task finishedTask = await Task.WhenAny(tasks);
            tasks.Remove(finishedTask);
        }

        // ✅ Stellt sicher, dass das Event ausgelöst wird, selbst wenn einige Tasks fehlschlagen
        await Application.Current.Dispatcher.InvokeAsync(() =>
        {
            ServiceScanFinished?.Invoke();
        });
    }












    //private async Task ScanIPAsync(IPToScan ipToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts)
    //  {
    //      //var result = new ServiceScanResult { IP = ipToScan.IPorHostname };


    //      foreach (ServiceType service in services)
    //      {
    //          var serviceResult = new ServiceResult { Service = service };
    //          var ports = GetServicePorts(service);

    //          if (extraPorts != null && extraPorts.ContainsKey(service))
    //          {
    //              ports.AddRange(extraPorts[service]);
    //          }

    //          var detectionPacket = GetDetectionPacket(service);



    //          var semaphore = new SemaphoreSlim(50); // Maximale gleichzeitige Scans begrenzen
    //          var tasks = new List<Task>();

    //          foreach (var port in ports.Distinct())
    //          {
    //              await semaphore.WaitAsync();
    //              tasks.Add(Task.Run(async () =>
    //              {
    //                  try
    //                  {
    //                      var portResult = new PortResult();
    //                      switch (service)
    //                      {
    //                          case ServiceType.RDP:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
    //                              break;
    //                          case ServiceType.UltraVNC:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
    //                              break;
    //                          case ServiceType.BigFixRemote:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
    //                              break;
    //                          case ServiceType.Rustdesk:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
    //                              break;
    //                          case ServiceType.Teamviewer:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
    //                              break;
    //                          case ServiceType.Anydesk:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
    //                              break;
    //                          case ServiceType.MSSQLServer:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);


    //                              //scan for dynamic sql ports
    //                              if (portResult.Status != PortStatus.IsRunning)
    //                              {
    //                                  try
    //                                  {
    //                                      int? dynamicPort = await GetMSSQLDynamicPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString());
    //                                      if (dynamicPort != null)
    //                                      {
    //                                          portResult.Port = (int)dynamicPort;
    //                                          portResult.Status = PortStatus.IsRunning;
    //                                      }
    //                                  }
    //                                  catch (Exception)
    //                                  {
    //                                      throw;
    //                                  }
    //                              }

    //                              break;
    //                          case ServiceType.PostgreSQL:
    //                              break;
    //                          case ServiceType.MariaDB:
    //                              break;
    //                          case ServiceType.OracleDB:
    //                              break;
    //                          case ServiceType.OPCDA:
    //                              break;
    //                          case ServiceType.OPCUA:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
    //                              break;
    //                          case ServiceType.ModBus:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
    //                              break;
    //                          case ServiceType.FTP:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
    //                              break;
    //                          case ServiceType.WebServices:
    //                              var serviceResult = new ServiceResult { Service = service };
    //                              portResult = await CheckWebServicePortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port);
    //                              break;
    //                          default:
    //                              portResult = await ScanPortAsync(IPAddress.Parse(ipToScan.IPorHostname).ToString(), port, detectionPacket);
    //                              break;
    //                      }


    //                      lock (serviceResult.Ports) // Schutz vor parallelen Schreibzugriffen
    //                      {
    //                          serviceResult.Ports.Add(portResult);
    //                      }
    //                  }
    //                  finally
    //                  {
    //                      semaphore.Release();
    //                  }
    //              }));
    //          }

    //          // **Parallel ausführen & warten**
    //          await Task.WhenAll(tasks);

    //          ipToScan.Services.Services.Add(serviceResult);
    //      }

    //      if (ipToScan.Services.Services.Count > 0)
    //      {
    //          int respondedValue = Interlocked.Increment(ref responded);
    //          ProgressUpdated?.Invoke(current, responded, total);

    //          ipToScan.UsedScanMethod = ScanMethod.Services;

    //          ServiceIPScanFinished?.Invoke(ipToScan); // Event auslösen
    //      }
    //  }


    


    private async Task ScanIPAsync(IPToScan ipToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts)
    {
        scanDHCP = true;
        string ipAddress = IPAddress.Parse(ipToScan.IPorHostname).ToString(); // Einmal parsen

        foreach (ServiceType service in services)
        {
            var serviceResult = new ServiceResult { Service = service };
            var ports = GetServicePorts(service);

            if (extraPorts != null && extraPorts.TryGetValue(service, out var additionalPorts))
            {
                ports.AddRange(additionalPorts);
            }

            byte[] detectionPacket = GetDetectionPacket(service);

            var semaphore = new SemaphoreSlim(50); // Begrenzung gleichzeitiger Scans
            var tasks = new List<Task>();

            foreach (var port in ports.Distinct())
            {
                await semaphore.WaitAsync();
                
                tasks.Add(ScanServicePortAsync(service, ipAddress, port, detectionPacket, serviceResult, semaphore));                
            }

            // Parallel ausführen und warten
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

    /// <summary>
    /// Scannt einen Port für einen bestimmten Service.
    /// </summary>
    private async Task ScanServicePortAsync(ServiceType service, string ipAddress, int port, byte[] detectionPacket, ServiceResult serviceResult, SemaphoreSlim semaphore)
    {
        try
        {
            PortResult portResult = new PortResult();            

            switch (service)
            {
                case ServiceType.WebServices:
                    portResult = await CheckWebServicePortAsync(ipAddress, port);
                    break;
                case ServiceType.DNS_TCP:

                    string dnsTCPServerIP = ipAddress; // Google Public DNS
                    string domain = "gotme.com";

                    byte[] dnsQuery = BuildDnsRequest(domain);
                    portResult = await SendTcpDnsQuery(dnsTCPServerIP, dnsQuery, port);

                    break;
                case ServiceType.DNS_UDP:

                    string dnsUDPServerIP = ipAddress; // Google Public DNS
                    string domain2 = "gotme.com";

                    byte[] dnsQuery2 = BuildDnsRequest(domain2);
                    portResult = await SendUdpDnsQuery(dnsUDPServerIP, dnsQuery2, port);

                    break;
                    case ServiceType.DHCP:
                    if (scanDHCP)
                    {
                        scanDHCP = false;
                        DHCP_Server_IPs = await SendDhcpDiscoverAsync(detectionPacket);                        
                    }

                    if (DHCP_Server_IPs.Contains(ipAddress))
                    {
                        portResult.Port = 67;
                        portResult.Status = PortStatus.IsRunning;
                    }
                    else
                    {
                        portResult.Port = 67;
                        portResult.Status = PortStatus.NoResponse;
                    }
                    break;
                case ServiceType.SSH:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.FTP:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.RDP:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.UltraVNC:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.BigFixRemote:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.Rustdesk:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.Teamviewer:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.Anydesk:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.MSSQLServer:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);

                    if (portResult.Status != PortStatus.IsRunning)
                    {
                        try
                        {
                            List<int> dynamicPort;

                            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3))) // ⏳ Timeout setzen
                            {
                                dynamicPort = await GetMSSQLDynamicPortsAsync(ipAddress).WaitAsync(cts.Token);
                            }

                            if (dynamicPort.Count > 0)
                            {
                                //only the first instance
                                portResult.Port = dynamicPort[0];
                                portResult.Status = PortStatus.IsRunning;
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"⚠️ Fehler beim Abrufen des dynamischen SQL-Ports für {ipAddress}: {ex.Message}");
                        }
                    }
                    break;
                case ServiceType.PostgreSQL:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.MariaDB:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.OracleDB:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.MySQL:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.OPCUA:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.ModBus:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                case ServiceType.S7:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
                default:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket);
                    break;
            }

            lock (serviceResult.Ports) // Schutz vor parallelem Zugriff
            {
                serviceResult.Ports.Add(portResult);
            }
        }
        finally
        {
            semaphore.Release();
        }
    }














    //private async Task<PortResult> ScanPortAsync(string ip, int port, byte[] detectionPacket)
    //{
    //    PortResult portResult = new PortResult();
    //    portResult.Port = port;

    //    for (int attempt = 1; attempt <= RetryCount; attempt++)
    //    {
    //        using var client = new TcpClient();
    //        try
    //        {
    //            try
    //            {
    //                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
    //                {
    //                    socket.Blocking = false;
    //                    IAsyncResult result = socket.BeginConnect(ip, port, null, null);
    //                    bool success = result.AsyncWaitHandle.WaitOne(Timeout);

    //                    if (!success)
    //                    {
    //                        portResult.Status = PortStatus.Filtered;
    //                        portResult.PortLog += "Timeout, Port möglicherweise durch Firewall blockiert.";
    //                        return portResult;
    //                    }

    //                    try
    //                    {
    //                        socket.EndConnect(result);
    //                        portResult.Status = PortStatus.Open;
    //                    }
    //                    catch (SocketException ex)
    //                    {
    //                        if (ex.SocketErrorCode == SocketError.ConnectionRefused)
    //                        {
    //                            portResult.Status = PortStatus.Closed;
    //                            portResult.PortLog += "Verbindung verweigert. Kein Dienst lauscht auf diesem Port.";
    //                        }
    //                        else
    //                        {
    //                            portResult.Status = PortStatus.NoResponse;
    //                            portResult.PortLog += "Unbekannter Verbindungsfehler: " + ex.Message;
    //                        }
    //                        return portResult;
    //                    }
    //                }
    //            }
    //            catch (Exception ex)
    //            {
    //                portResult.Status = PortStatus.Closed;
    //                portResult.PortLog += "Unbekannter Fehler: " + ex.Message;
    //            }


    //            var connectTask = client.ConnectAsync(ip, port);
    //            if (await Task.WhenAny(connectTask, Task.Delay(Timeout)) != connectTask)
    //            {
    //                portResult.Status = PortStatus.Closed;
    //                portResult.PortLog += "Timeout:";
    //            }

    //            if (detectionPacket.Length > 0)
    //            {
    //                try
    //                {
    //                    using var stream = client.GetStream();
    //                    await stream.WriteAsync(detectionPacket, 0, detectionPacket.Length);
    //                    await Task.Delay(500);

    //                    byte[] buffer = new byte[4096]; // Größerer Buffer für TLS-Antwort
    //                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);


    //                    //if (stream.DataAvailable)
    //                    if (bytesRead > 0)
    //                    {
    //                        portResult.Status = PortStatus.IsRunning;
    //                        string responseHex = BitConverter.ToString(buffer, 0, bytesRead).Replace("-", " ");

    //                        string responseAscii = Encoding.ASCII.GetString(buffer, 0, bytesRead).Replace("\r", "\\r").Replace("\n", "\\n").Replace("\0", "");  // Nullbytes entfernen
    //                        string filter = responseAscii.ToLower().Contains("anydesk") ? "found AnyDesk in server response." : "server replied, but AnyDesk wasn’t found in response.";

    //                        portResult.PortLog = filter;
    //                    }
    //                    else
    //                    {
    //                        portResult.Status = PortStatus.NoResponse;
    //                        portResult.PortLog += "open, no application behind";
    //                    }
    //                }
    //                catch (Exception ex)
    //                {
    //                    throw;
    //                }
    //            }

    //            return portResult;
    //        }
    //        catch (SocketException ex)
    //        {
    //            if (attempt == RetryCount)
    //            {
    //                //return new PortResult { Port = port, Status = PortStatus.Closed, PortLog = ex.Message };
    //                portResult.Status = PortStatus.Closed;
    //                portResult.PortLog += ex.Message;
    //            }
    //        }
    //    }

    //    //return new PortResult { Port = port, Status = PortStatus.Closed, PortLog = "Unbekannter Fehler" };
    //    portResult.PortLog = "unknown error";
    //    return portResult;
    //}




    private async Task<PortResult> ScanPortAsync(string ip, int port, byte[] detectionPacket)
    {
        var portResult = new PortResult { Port = port };
        var logBuilder = new StringBuilder();

        for (int attempt = 1; attempt <= RetryCount; attempt++)
        {
            using var client = new TcpClient();
            try
            {
                using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    socket.Blocking = false;
                    var result = socket.BeginConnect(ip, port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(Timeout);

                    if (!success)
                    {
                        portResult.Status = PortStatus.Filtered;
                        logBuilder.AppendLine("Timeout: Port möglicherweise durch Firewall blockiert.");
                        portResult.PortLog = logBuilder.ToString();
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
                            logBuilder.AppendLine("Verbindung verweigert: Kein Dienst lauscht auf diesem Port.");
                        }
                        else
                        {
                            portResult.Status = PortStatus.NoResponse;
                            logBuilder.AppendLine($"Unbekannter Verbindungsfehler: {ex.Message}");
                        }
                        portResult.PortLog = logBuilder.ToString();
                        return portResult;
                    }
                }

                // Verbindung mit TcpClient testen
                var connectTask = client.ConnectAsync(ip, port);
                if (await Task.WhenAny(connectTask, Task.Delay(Timeout)) != connectTask)
                {
                    portResult.Status = PortStatus.Closed;
                    logBuilder.AppendLine("Timeout beim Verbindungsaufbau.");
                    portResult.PortLog = logBuilder.ToString();
                    return portResult;
                }

                if (detectionPacket.Length > 0)
                {
                    try
                    {
                        await using var stream = client.GetStream();
                        await stream.WriteAsync(detectionPacket, 0, detectionPacket.Length);

                        var buffer = new byte[4096];
                        var cts = new CancellationTokenSource(Timeout);
                        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);

                        if (bytesRead > 0)
                        {
                            portResult.Status = PortStatus.IsRunning;
                            string responseAscii = Encoding.ASCII.GetString(buffer, 0, bytesRead)
                                .Replace("\r", "\\r")
                                .Replace("\n", "\\n")
                                .Replace("\0", ""); // Nullbytes entfernen

                            if (responseAscii.IndexOf("anydesk", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                logBuilder.AppendLine("✔ AnyDesk in Serverantwort gefunden.");
                            }
                            else
                            {
                                logBuilder.AppendLine("❓ Server hat geantwortet, aber AnyDesk nicht gefunden.");
                            }
                        }
                        else
                        {
                            portResult.Status = PortStatus.NoResponse;
                            logBuilder.AppendLine("🔎 Port ist offen, aber keine Antwort von einer Anwendung.");
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        logBuilder.AppendLine("⏳ Antwort vom Server dauerte zu lange.");
                    }
                    catch (Exception ex)
                    {
                        logBuilder.AppendLine($"❌ Fehler beim Lesen der Antwort: {ex.Message}");
                    }
                }

                portResult.PortLog = logBuilder.ToString();
                return portResult;
            }
            catch (SocketException ex)
            {
                if (attempt == RetryCount)
                {
                    portResult.Status = PortStatus.Closed;
                    logBuilder.AppendLine($"⚠️ Fehler nach {RetryCount} Versuchen: {ex.Message}");
                }
            }
        }

        portResult.PortLog = logBuilder.ToString();
        return portResult;
    }



    //private async Task<int?> GetMSSQLDynamicPortAsync(string serverIP)
    //{
    //    using (UdpClient udpClient = new UdpClient())
    //    {
    //        udpClient.Client.ReceiveTimeout = 2000; // Timeout für Antwort setzen

    //        IPEndPoint sqlServerEndpoint = new IPEndPoint(IPAddress.Parse(serverIP), 1434);

    //        byte[] request = Encoding.ASCII.GetBytes("\x02"); // Anfrage für SQL-Browser-Information
    //        await udpClient.SendAsync(request, request.Length, sqlServerEndpoint);

    //        try
    //        {
    //            UdpReceiveResult response = await udpClient.ReceiveAsync();
    //            string responseText = Encoding.ASCII.GetString(response.Buffer);

    //            Console.WriteLine($"📡 SQL Browser Antwort: {responseText}");

    //            // 🔍 Suche nach "tcp;" im Antwortstring und extrahiere den Port
    //            int index = responseText.IndexOf("tcp;");
    //            if (index != -1)
    //            {
    //                string portPart = responseText.Substring(index + 4).Split(';')[0];
    //                if (int.TryParse(portPart, out int port))
    //                {
    //                    return port; // ✅ Erfolgreich extrahierter Port
    //                }
    //            }
    //        }
    //        catch (SocketException)
    //        {
    //            Console.WriteLine("⚠️ Keine Antwort vom SQL Browser-Dienst. Ist er aktiv?");
    //        }
    //    }

    //    return null; // ❌ Kein Port gefunden
    //}


    //private async Task<int?> GetMSSQLDynamicPortAsync(string serverIP)
    //{
    //    using (UdpClient udpClient = new UdpClient())
    //    {
    //        udpClient.Client.ReceiveTimeout = 5000; // Timeout erhöht auf 5 Sekunden
    //        IPEndPoint sqlServerEndpoint = new IPEndPoint(IPAddress.Parse(serverIP), 1434);
    //        byte[] request = Encoding.ASCII.GetBytes("\x02"); // Anfrage für SQL-Browser-Information
    //        await udpClient.SendAsync(request, request.Length, sqlServerEndpoint);

    //        try
    //        {
    //            UdpReceiveResult response = await udpClient.ReceiveAsync();
    //            string responseText = Encoding.UTF8.GetString(response.Buffer); // UTF-8 für bessere Kompatibilität

    //            Console.WriteLine($"📡 SQL Browser Antwort: {responseText}");

    //            // 🔍 Suche nach "tcp;" und extrahiere den Port
    //            int index = responseText.IndexOf("tcp;");
    //            if (index != -1)
    //            {
    //                string[] parts = responseText.Substring(index + 4).Split(';');
    //                if (parts.Length > 0 && int.TryParse(parts[0], out int port))
    //                {
    //                    return port; // ✅ Erfolgreich extrahierter Port
    //                }
    //            }
    //        }
    //        catch (SocketException ex)
    //        {
    //            Console.WriteLine($"⚠️ Keine Antwort vom SQL Browser-Dienst (Fehler: {ex.Message}). Ist er aktiv?");
    //        }
    //        catch (Exception ex)
    //        {
    //            Console.WriteLine($"❌ Unerwarteter Fehler: {ex.Message}");
    //        }
    //    }

    //    return null; // ❌ Kein Port gefunden
    //}








    public async Task<List<string>> SendDhcpDiscoverAsync(byte[] dhcpDiscoverPacket)
    {
        List<string> dhcpServers = new List<string>();

        using UdpClient udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, 68)); // Lauscht auf Port 68
        udpClient.EnableBroadcast = true;
        IPEndPoint endPoint = new IPEndPoint(IPAddress.Broadcast, 67); // DHCP-Server-Port
        udpClient.Client.ReceiveTimeout = 3000; // Timeout für Empfang

        for (int attempt = 1; attempt <= 3; attempt++) // Bis zu 3 Wiederholungen
        {
            //Console.WriteLine($"📡 Versuch {attempt}: Sende DHCP-Discover...");
            await udpClient.SendAsync(dhcpDiscoverPacket, dhcpDiscoverPacket.Length, endPoint);

            DateTime startTime = DateTime.Now;
            while ((DateTime.Now - startTime).TotalSeconds < 3) // 3 Sekunden auf Antwort warten
            {
                try
                {
                    var receiveTask = udpClient.ReceiveAsync();
                    if (await Task.WhenAny(receiveTask, Task.Delay(1000)) == receiveTask)
                    {
                        byte[] response = receiveTask.Result.Buffer;
                        string serverIp = new IPAddress(response.Skip(20).Take(4).ToArray()).ToString();
                        string relayAgentIp = new IPAddress(response.Skip(24).Take(4).ToArray()).ToString();

                        //option 54
                        int index = Array.IndexOf(response, (byte)54);
                        string dhcpServerIp = index > 0 ? new IPAddress(response.Skip(index + 2).Take(4).ToArray()).ToString() : "Not Found";


                        if (!dhcpServers.Contains(serverIp))
                        {
                            dhcpServers.Add(dhcpServerIp);
                            //Console.WriteLine($"✅ DHCP-Server gefunden: {serverIp}");
                        }
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    //Console.WriteLine("⏳ Timeout: Keine Antwort vom DHCP-Server.");
                    break; // Keine weitere Schleife notwendig
                }
                catch (Exception ex)
                {
                    //Console.WriteLine($"❌ Fehler: {ex.Message}");
                    break;
                }
            }

            if (dhcpServers.Count > 0) break; // Stoppe Wiederholungen, wenn Server gefunden
        }

        return dhcpServers;
    }









    private async Task<List<int>> GetMSSQLDynamicPortsAsync(string serverIP)
    {
        const int MaxRetries = 3; // 🔄 Anzahl der Wiederholungen
        const int TimeoutMilliseconds = 3000; // ⏳ Timeout pro Versuch (3 Sekunden)
        var foundPorts = new List<int>();

        using (UdpClient udpClient = new UdpClient())
        {
            udpClient.Client.ReceiveTimeout = TimeoutMilliseconds;
            IPEndPoint sqlServerEndpoint = new IPEndPoint(IPAddress.Parse(serverIP), 1434);
            byte[] request = Encoding.ASCII.GetBytes("\x02"); // Anfrage für SQL-Browser-Information

            for (int attempt = 1; attempt <= MaxRetries; attempt++)
            {
                try
                {
                    await udpClient.SendAsync(request, request.Length, sqlServerEndpoint);

                    // Warte auf eine Antwort mit Timeout
                    var receiveTask = udpClient.ReceiveAsync();
                    if (await Task.WhenAny(receiveTask, Task.Delay(TimeoutMilliseconds)) == receiveTask)
                    {
                        // Antwort erhalten
                        UdpReceiveResult response = await receiveTask;
                        string responseText = Encoding.ASCII.GetString(response.Buffer);

                        Console.WriteLine($"📡 SQL Browser Antwort (Versuch {attempt}): {responseText}");

                        // 🔍 Alle "tcp;" Ports suchen (nicht nur den ersten!)
                        var matches = System.Text.RegularExpressions.Regex.Matches(responseText, @"tcp;(\d+)");
                        foreach (System.Text.RegularExpressions.Match match in matches)
                        {
                            if (match.Groups.Count > 1 && int.TryParse(match.Groups[1].Value, out int port))
                            {
                                foundPorts.Add(port);
                            }
                        }

                        if (foundPorts.Count > 0)
                        {
                            return foundPorts; // ✅ Erfolgreich gefundene Ports zurückgeben
                        }
                    }
                    else
                    {
                        Console.WriteLine($"⚠️ Versuch {attempt}: Timeout - Keine Antwort vom SQL Browser-Dienst.");
                    }
                }
                catch (SocketException ex)
                {
                    Console.WriteLine($"⚠️ Versuch {attempt}: Fehler beim Abrufen des SQL-Ports: {ex.Message}");
                }
            }
        }

        Console.WriteLine($"❌ Keine MSSQL-Dynamikports gefunden nach {MaxRetries} Versuchen.");
        return foundPorts; // ❌ Leere Liste, falls nichts gefunden wurde
    }







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






    static async Task<PortResult> SendTcpDnsQuery(string dnsServer, byte[] query, int Port )
    {
        PortResult portResult = new PortResult();
        portResult.Status = PortStatus.NoResponse;
        portResult.Port = Port;

        for (int i = 1; i <= 3; i++) // Maximal 3 Wiederholungen
        {
            try
            {
                using TcpClient client = new TcpClient();
                await client.ConnectAsync(dnsServer, portResult.Port);

                portResult.Status = PortStatus.Open;

                using NetworkStream stream = client.GetStream();

                // Füge 2-Byte-Längenfeld vor die Anfrage (TCP benötigt dies)
                byte[] tcpQuery = new byte[query.Length + 2];
                tcpQuery[0] = (byte)(query.Length >> 8);
                tcpQuery[1] = (byte)(query.Length & 0xFF);
                Buffer.BlockCopy(query, 0, tcpQuery, 2, query.Length);

                // Senden der DNS-Anfrage
                await stream.WriteAsync(tcpQuery, 0, tcpQuery.Length);
                //Console.WriteLine($"📡 DNS-Anfrage gesendet ({query.Length} Bytes)");

                // Antwort empfangen (Längenfeld zuerst lesen)
                byte[] lengthBuffer = new byte[2];
                await stream.ReadAsync(lengthBuffer, 0, 2);
                int responseLength = (lengthBuffer[0] << 8) | lengthBuffer[1];

                // Antwortdaten lesen
                byte[] responseBuffer = new byte[responseLength];
                await stream.ReadAsync(responseBuffer, 0, responseLength);

                portResult.Status = PortStatus.IsRunning;
                portResult.PortLog = Encoding.ASCII.GetString(responseBuffer);

                return portResult; // Gib die verarbeitete Antwort zurück
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"⚠️ Versuch {i}: Fehler beim DNS-Request - {ex.Message}");
            }

            await Task.Delay(500); // Warte 1 Sekunde vor nächstem Versuch
        }

        return portResult; // Keine Antwort nach 3 Versuchen
    }





    static async Task<PortResult> SendUdpDnsQuery(string dnsServer, byte[] query, int Port)
    {
        PortResult portResult = new PortResult();
        portResult.Status = PortStatus.NoResponse;
        portResult.Port = Port;

        using UdpClient udpClient = new UdpClient();
        udpClient.Connect(dnsServer, portResult.Port);

        for (int i = 1; i <= 3; i++) // Maximal 3 Wiederholungen
        {
            //Console.WriteLine($"🔄 Versuch {i}: Sende DNS-Anfrage an {dnsServer}...");
            await udpClient.SendAsync(query, query.Length);

            var receiveTask = udpClient.ReceiveAsync();
            if (await Task.WhenAny(receiveTask, Task.Delay(2000)) == receiveTask)
            {
                portResult.Status = PortStatus.IsRunning;
                portResult.PortLog = Encoding.ASCII.GetString(receiveTask.Result.Buffer);
                return portResult;
            }
            else
            {
                //Console.WriteLine("❌ Keine Antwort vom DNS-Server.");
            }

            if (i < 3) await Task.Delay(500); // Warte 1 Sekunde vor dem nächsten Versuch
        }

        return portResult; // Falls nach 3 Versuchen keine Antwort kam
    }


    static byte[] BuildDnsRequest(string domain)
    {
        byte[] header = new byte[]
        {
            0xAA, 0xAA,  // Transaction ID
            0x01, 0x00,  // Standard Query mit rekursiver Abfrage
            0x00, 0x01,  // Eine Frage
            0x00, 0x00,  // Keine Antworten vorhanden
            0x00, 0x00,  // Keine Autoritätsantworten
            0x00, 0x00   // Keine zusätzlichen Antworten
        };

        byte[] question = BuildDnsQuestion(domain);
        byte[] query = new byte[header.Length + question.Length];
        Buffer.BlockCopy(header, 0, query, 0, header.Length);
        Buffer.BlockCopy(question, 0, query, header.Length, question.Length);
        return query;
    }

    static byte[] BuildDnsQuestion(string domain)
    {
        var parts = domain.Split('.');
        byte[] question = new byte[domain.Length + 2 + 4];
        int position = 0;

        foreach (var part in parts)
        {
            question[position++] = (byte)part.Length;
            Encoding.ASCII.GetBytes(part, 0, part.Length, question, position);
            position += part.Length;
        }
        question[position++] = 0x00; // Null-Terminierung
        question[position++] = 0x00; // Type: A (IPv4-Adresse anfragen)
        question[position++] = 0x01;
        question[position++] = 0x00; // Class: IN (Internet)
        question[position++] = 0x01;

        return question;
    }






    private static List<int> GetServicePorts(ServiceType service)
    {
        return service switch
        {
            // 🌍 Netzwerk-Dienste
            ServiceType.WebServices => new List<int> { 80, 443, 8080, 8443 }, // HTTP/S
            ServiceType.DNS_TCP => new List<int> { 53 },  // Domain Name Service
            ServiceType.DNS_UDP => new List<int> { 53 },  // Domain Name Service
            ServiceType.DHCP => new List<int> { 67 },  // Dynamic Host Configuration Protocol
            ServiceType.SSH => new List<int> { 22 },  // Secure Shell
            ServiceType.FTP => new List<int> { 21 },  // File Transfer Protocol

            // 🖥️ Remote-Desktop & Fernwartung
            ServiceType.RDP => new List<int> { 3389 },  // Microsoft Remote Desktop
            ServiceType.UltraVNC => new List<int> { 5900, 5901, 5902, 5903 }, // VNC
            ServiceType.Teamviewer => new List<int> { 5938 },  // Teamviewer
            ServiceType.BigFixRemote => new List<int> { 888 },  // BigFix Remote
            ServiceType.Anydesk => new List<int> { 7070 },  // AnyDesk
            ServiceType.Rustdesk => new List<int> { 21115 },  // Rustdesk Remote

            // 🗄️ Datenbanken
            ServiceType.MSSQLServer => new List<int> { 1433 }, // Microsoft SQL Server
            ServiceType.PostgreSQL => new List<int> { 5432 }, // PostgreSQL
            ServiceType.MariaDB => new List<int> { 3306 }, // MariaDB / MySQL
            ServiceType.OracleDB => new List<int> { 1521 }, // Oracle DB
            ServiceType.MySQL => new List<int> { 3306 }, // MySQL

            // ⚙️ Industrieprotokolle (OT, Automatisierung)
            ServiceType.OPCUA => new List<int> { 4840 }, // OPC UA
            ServiceType.ModBus => new List<int> { 502 }, // ModBus TCP

            // 🏭 SPS / Industrielle Steuerungen
            ServiceType.S7 => new List<int> { 102, 1020 }, // Siemens S7 ISO-on-TCP

            _ => new List<int>()
        };

    }

    public static byte[] GetDetectionPacket(ServiceType service)
    {
        return service switch
        {
            // 🌍 Netzwerk-Dienste

            // Domain Name Service
            //ServiceType.DNS => new byte[]
            //{
            //    0xAA, 0xAA, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
            //    0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01
            //},            
            ServiceType.DHCP => new byte[]
            {
                0x01, 0x01, 0x06, 0x00, 0x60, 0xE7, 0xC5, 0x78, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xC0, 0xDE,
                0xCA, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
                0x35, 0x01, 0x01, 0x37, 0x40, 0xFC, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
                0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
                0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
                0x3B, 0x3C, 0x3D, 0x43, 0x42, 0xFF
            },

            // Secure Shell
            ServiceType.SSH => Encoding.ASCII.GetBytes("SSH-2.0-MySSHClient\r\n"),  

            // File Transfer Protocol
            ServiceType.FTP => new byte[]
            {
                0xCD, 0xCA, 0x00, 0x15, 0x5E, 0xE8, 0x15, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xFA, 0xF0,
                0x90, 0x80, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02
            },





            // 🖥️ Remote-Desktop & Fernwartung

            ServiceType.RDP => new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 },
            ServiceType.UltraVNC => new byte[] { 0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33 },
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




            // 🗄️ Datenbanken

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

            //ServiceType.PostgreSQL => new byte[]
            //{
            //    0x00, 0x00, 0x00, 0x16,  // Paketlänge (22 Bytes)
            //    0x00, 0x03, 0x00, 0x00,  // Protokollversion 3.0
            //    0x75, 0x73, 0x65, 0x72,  // "user"
            //    0x00,                    // Null-Terminator
            //    0x61, 0x64, 0x6D, 0x69,  // "admin"
            //    0x6E, 0x00,              // Null-Terminator
            //    0x00                     // Doppelte Null = Ende der Nachricht 
            //},
            ServiceType.PostgreSQL => new byte[]
            {
                0xC3, 0xA4, 0x15, 0x38, 0x68, 0x84, 0xA9, 0x3C,
                0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xFA, 0xF0,
                0xE5, 0xD7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4,
                0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02
            },

            ServiceType.MariaDB => new byte[] 
            {
                0xC3, 0xBC, 0x0C, 0xEA, 0x1E, 0xF7, 0x13, 0x5D,
                0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xFA, 0xF0,
                0xE5, 0xD7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4,
                0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02
            },

            ServiceType.OracleDB => new byte[] 
            { 
                0xC3, 0xC3, 0x05, 0xF1, 0xF2, 0x3C, 0x83, 0x34,
                0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xFA, 0xF0,
                0xE5, 0xD7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4,
                0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02 
            },

            ServiceType.MySQL => new byte[]
           {
                0xC3, 0xCE, 0x0C, 0xEA, 0xE5, 0x8F, 0x81, 0x10,
                0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xFA, 0xF0,
                0xE5, 0xD7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4,
                0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02
           },




            // ⚙️ Industrieprotokolle (OT, Automatisierung)
            ServiceType.OPCUA => new byte[] { 0x48, 0x45, 0x4c, 0x4c, 0x4f },
            ServiceType.ModBus => new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 },



            // 🏭 SPS / Industrielle Steuerungen

             // Siemens S7 ISO-on-TCP
            ServiceType.S7 => new byte[] 
            {
                0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01,
                0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02,
                0x01, 0x02
            },

            _ => new byte[0]
        };
    }
}









