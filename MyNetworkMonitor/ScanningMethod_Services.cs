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
using System.Reflection.Metadata;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Xml.Serialization;
using SnmpSharpNet;
using System.Text.RegularExpressions;


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
    // ?? Netzwerk-Dienste
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
    TeamViewer,
    Anydesk,
    RustdeskServer,
    RustdeskClient,

    // Datenbanken
    MSSQLServer,
    PostgreSQL,    
    MariaDB,
    MySQL,
    OracleDB,
    // no SQL Datenbanken
    MongoDB,
    InfluxDB2,
    //InfluxDB3,

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
    public ScanningMethod_Services(string ServiceXMLPath)
    {
        SetServicePorts(ServiceXMLPath);
        _serviceXMLPath = ServiceXMLPath;
    }

    private int current = 0;
    private int responded = 0;
    private int total = 0;

    private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen

    //int currentValue = Interlocked.Increment(ref current);
    //ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);

    //int respondedValue = Interlocked.Increment(ref responded);
    //ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

    //ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished);

    public void StopScan()
    {
        if (_cts != null && !_cts.IsCancellationRequested)
        {
            _cts.Cancel(); // 🔹 Scan abbrechen
            _cts.Dispose();
            _cts = new CancellationTokenSource();
        }

        // 🔹 Zähler zurücksetzen
        current = 0;
        responded = 0;
        total = 0;

        ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped); // 🔹 UI auf 0 setzen
    }

    private void StartNewScan()
    {
        if (_cts != null)
        {
            if (!_cts.IsCancellationRequested)
            {
                _cts.Cancel();
            }
            _cts.Dispose();
        }
        _cts = new CancellationTokenSource();

        // 🔹 Zähler zurücksetzen
        current = 0;
        responded = 0;
        total = 0;
    }




    private string _serviceXMLPath = string.Empty;

    bool scanDHCP = true;
    List<string> DHCP_Server_IPs = new List<string>();

    private const int MaxParallelIPs = 30;
    private const int Timeout = 2000; // 3 Sekunden Timeout pro Dienst
    private const int RetryCount = 3;

    public event Action<IPToScan> ServiceIPScanFinished;
  
    public event Action<int, int, int, ScanStatus> ProgressUpdated;
    public event Action ServiceScanFinished;

    public event Action<int, int, int> FindServicePortProgressUpdated;
    public event Action<IPToScan> FindServicePortFinished;

    public async Task ScanIPsAsync(List<IPToScan> IPsToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts = null)
    {
        StartNewScan();

        current = 0;
        responded = 0;
        total = IPsToScan.Count;
        
        ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);


        var semaphore = new SemaphoreSlim(MaxParallelIPs);
        var tasks = IPsToScan.Select(async ipToScan =>
        {
            await semaphore.WaitAsync(_cts.Token);

            if (_cts.Token.IsCancellationRequested)
                return; // Vorzeitig abbrechen

            try
            {
                await Task.Run(() => ScanIPAsync(ipToScan, services, extraPorts), _cts.Token);
            }
            finally
            {
                semaphore.Release();
            }
        }).ToArray();

        await Task.WhenAll(tasks);

        // ? Garantiert: SMBScanFinished wird NUR ausgelöst, wenn alle SMB-Scans beendet sind
        ServiceScanFinished?.Invoke();
    }


    //public async Task ScanIPsAsync(List<IPToScan> IPsToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts = null)
    //{
    //    bool scanDHCP = true;
    //    DHCP_Server_IPs.Clear();

    //    current = 0;
    //    responded = 0;
    //    total = IPsToScan.Count;

    //    var semaphore = new SemaphoreSlim(MaxParallelIPs);
    //    var tasks = new List<Task>();

    //    foreach (var ipToScan in IPsToScan)
    //    {
    //        await semaphore.WaitAsync(); // ? Wartet, bis ein neuer Slot frei ist
    //        tasks.Add(Task.Run(async () =>
    //        {
    //            try
    //            {
    //                int currentValue = Interlocked.Increment(ref current);

    //                // ?? Sicherstellen, dass UI-Updates nicht blockieren
    //                await Application.Current.Dispatcher.InvokeAsync(() =>
    //                {
    //                    ProgressUpdated?.Invoke(current, responded, total);
    //                });

    //                await ScanIPAsync(ipToScan, services, extraPorts);
    //            }
    //            catch (Exception ex)
    //            {
    //                Console.WriteLine($"?? Fehler beim Scannen von {ipToScan.IPorHostname}: {ex.Message}");
    //            }
    //            finally
    //            {
    //                semaphore.Release(); // ? Stellt sicher, dass das Semaphore freigegeben wird
    //            }
    //        }));
    //    }

    //    // ? Prüft regelmäßig den Fortschritt, um Hänger zu vermeiden
    //    while (tasks.Any())
    //    {
    //        Task finishedTask = await Task.WhenAny(tasks);
    //        tasks.Remove(finishedTask);
    //    }

    //    // ? Stellt sicher, dass das Event ausgelöst wird, selbst wenn einige Tasks fehlschlagen
    //    await Application.Current.Dispatcher.InvokeAsync(() =>
    //    {
    //        ServiceScanFinished?.Invoke();
    //    });
    //}












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
            if (_cts.Token.IsCancellationRequested) return; // Direkt abbrechen, falls nötig

            var serviceResult = new ServiceResult { Service = service };
            //var ports = GetDefaultServicePorts(service);

            //if (extraPorts != null && extraPorts.TryGetValue(service, out var additionalPorts))
            //{
            //    ports.AddRange(additionalPorts);
            //}

            extraPorts.TryGetValue(service, out var ports);

            byte[] detectionPacket = GetDetectionPacket(service);

            var semaphore = new SemaphoreSlim(50); // Begrenzung gleichzeitiger Scans
            var tasks = new List<Task>();

            foreach (var port in ports.Distinct())
            {
                await semaphore.WaitAsync(_cts.Token);

                if (_cts.Token.IsCancellationRequested) return; // Direkt abbrechen, falls nötig

                tasks.Add(ScanServicePortAsync(service, ipAddress, port, detectionPacket, serviceResult, semaphore));                
            }

            // Parallel ausführen und warten
            await Task.WhenAll(tasks);

            //ipToScan.Services.Services.Add(serviceResult);
            lock (ipToScan.Services.Services)
            {
                if (!ipToScan.Services.Services.Contains(serviceResult))
                    ipToScan.Services.Services.Add(serviceResult);
            }
        }

        if (ipToScan.Services.Services.Count > 0)
        {
            int respondedValue = Interlocked.Increment(ref responded);
            ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

            ipToScan.UsedScanMethod = ScanMethod.Services;
            ServiceIPScanFinished?.Invoke(ipToScan); // Event auslösen
        }
    }

    /// <summary>
    /// Scannt einen Port für einen bestimmten Service.
    /// </summary>
    private async Task ScanServicePortAsync(ServiceType service, string ipAddress, int port, byte[] detectionPacket, ServiceResult serviceResult, SemaphoreSlim semaphore)
    {
        if (_cts.Token.IsCancellationRequested) return; // Sofort abbrechen, falls Stopp angefordert wurde

        try
        {
            PortResult portResult = new PortResult();

            switch (service)
            {
                case ServiceType.WebServices:
                    portResult = await CheckWebServicePortAsync(ipAddress, port).WaitAsync(_cts.Token);
                    break;
                case ServiceType.DNS_TCP:

                    string dnsTCPServerIP = ipAddress; // Google Public DNS
                    string domain = "gotme.tcp.com";

                    byte[] dnsQuery = BuildDnsRequest(domain);
                    portResult = await SendTcpDnsQuery(dnsTCPServerIP, dnsQuery, port).WaitAsync(_cts.Token);

                    break;
                case ServiceType.DNS_UDP:

                    string dnsUDPServerIP = ipAddress; // Google Public DNS
                    string domain2 = "gotme.udp.com";

                    byte[] dnsQuery2 = BuildDnsRequest(domain2);
                    portResult = await SendUdpDnsQuery(dnsUDPServerIP, dnsQuery2, port).WaitAsync(_cts.Token);

                    break;
                case ServiceType.DHCP:

                    portResult.Port = 67;

                    if (scanDHCP)
                    {
                        scanDHCP = false;
                        DHCP_Server_IPs = await SendDhcpDiscoverAsync(detectionPacket).WaitAsync(_cts.Token);
                    }

                    if (DHCP_Server_IPs.Contains(ipAddress))
                    {
                        portResult.Status = PortStatus.IsRunning;
                    }
                    else
                    {
                        portResult.Status = PortStatus.NoResponse;
                    }
                    break;
                case ServiceType.SSH:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.FTP:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.RDP:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.UltraVNC:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.BigFixRemote:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.RustdeskServer:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.TeamViewer:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.Anydesk:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.MSSQLServer:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);

                    if (portResult.Status != PortStatus.IsRunning)
                    {
                        try
                        {
                            List<int> dynamicPort;

                            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3))) // ? Timeout setzen
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
                            Console.WriteLine($"?? Fehler beim Abrufen des dynamischen SQL-Ports für {ipAddress}: {ex.Message}");
                        }
                    }
                    break;
                case ServiceType.PostgreSQL:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.MySQL:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.MariaDB:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.OracleDB:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.MongoDB:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.InfluxDB2:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.OPCUA:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.ModBus:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                case ServiceType.S7:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
                default:
                    portResult = await ScanPortAsync(ipAddress, port, detectionPacket).WaitAsync(_cts.Token);
                    break;
            }
            if (_cts.Token.IsCancellationRequested) return;

            lock (serviceResult.Ports) // Schutz vor parallelem Zugriff
            {
                serviceResult.Ports.Add(portResult);
            }
        }
        catch (OperationCanceledException)
        {
            return; // Falls ein Task abgebrochen wurde, sauber zurückkehren
        }
        finally
        {
            semaphore.Release();
        }
    }
















    //public async Task<IPToScan> FindServicePortAsync(IPToScan ipToScan, ServiceType service)
    //{
    //    current = 0;
    //    responded = 0;
    //    total = 65536;

    //    ipToScan.UsedScanMethod = ScanMethod.Services;

    //    ServiceResult serviceResult = new ServiceResult { Service = service };
    //    ipToScan.Services.Services.Add(serviceResult);

    //    //PortResult defaultPortResult = new PortResult { Port = -1, Status = PortStatus.NoResponse };
    //    //ipToScan.Services.Services[0].Ports.Add(defaultPortResult);

    //    var semaphore = new SemaphoreSlim(100);
    //    var cts = new CancellationTokenSource(); // Abbruch-Token

    //    List<int> ports = Enumerable.Range(0, 65536).ToList(); // Alle Ports (0 bis 65535)
    //    //ports.Clear();
    //    //ports.Add(1880);



    //    foreach (int port in ports)
    //    {
    //        int currentValue = Interlocked.Increment(ref current);
    //        FindServicePortProgressUpdated?.Invoke(current, responded, total);

    //        try
    //        {
    //            await semaphore.WaitAsync(cts.Token); // Warten auf freien Slot
    //        }
    //        catch (OperationCanceledException)
    //        {
    //            break; // Abbruch bei Token-Auslösung
    //        }


    //        List<Task> portCheckTasks = new List<Task>();


    //        if (service == ServiceType.WebServices)
    //        {
    //            // Füge jede Aufgabe zur Liste hinzu
    //            portCheckTasks.Add(Task.Run(async () =>
    //            {
    //                PortResult portResult = await CheckWebServicePortAsync(ipToScan.IPorHostname, port);

    //                if (portResult.Status == PortStatus.IsRunning)
    //                {
    //                    int responsedValue = Interlocked.Increment(ref responded);
    //                    FindServicePortProgressUpdated?.Invoke(current, responded, total);

    //                    lock (serviceResult.Ports)
    //                    {
    //                        serviceResult.Ports.Add(portResult);  // Thread-sicher hinzufügen
    //                    }
    //                }
    //            }));
    //        }
    //        else
    //        {              

    //            _ = Task.Run(async () =>
    //            {
    //                try
    //                {
    //                    using TcpClient client = new TcpClient();
    //                    var connectTask = client.ConnectAsync(IPAddress.Parse(ipToScan.IPorHostname), port);
    //                    var delayTask = Task.Delay(1000); // Timeout auf 1 Sekunde

    //                    if (await Task.WhenAny(connectTask, delayTask) == connectTask && client.Connected)
    //                    {
    //                        using NetworkStream stream = client.GetStream();
    //                        await stream.WriteAsync(GetDetectionPacket(service), 0, GetDetectionPacket(service).Length);

    //                        // ?? Direkte Paket-Sammlung im Code:
    //                        using MemoryStream memoryStream = new MemoryStream();
    //                        byte[] buffer = new byte[1024];
    //                        DateTime startTime = DateTime.Now;

    //                        while ((DateTime.Now - startTime).TotalMilliseconds < 2000) // 2 Sekunden Daten sammeln
    //                        {
    //                            if (stream.DataAvailable)
    //                            {
    //                                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
    //                                if (bytesRead > 0)
    //                                {
    //                                    memoryStream.Write(buffer, 0, bytesRead);
    //                                    startTime = DateTime.Now; // Timeout zurücksetzen
    //                                }
    //                                else
    //                                {
    //                                    break; // Keine weiteren Daten verfügbar
    //                                }
    //                            }
    //                            else
    //                            {
    //                                await Task.Delay(50); // Kurze Pause zur Entlastung der CPU
    //                            }
    //                        }

    //                        // die anzeige des bytes in visual studio ist in dezimal, verarbeitet wird sie aber als hex, wenn der erste Hex wert 17 ist steht im 1. byte 23   
    //                        byte[] response = memoryStream.ToArray(); // Gesamte gesammelte Antwort in ein Array konvertieren
    //                                                                  //zur überprüfung
    //                                                                  //Debug.WriteLine(BitConverter.ToString(response));
    //                        string hexBytes = BitConverter.ToString(response);

    //                        // **Service-Erkennung durchführen**
    //                        if (response.Length > 0)
    //                        {
    //                            bool serviceMatched = IdentifyServices(response, service);

    //                            int responsedValue = Interlocked.Increment(ref responded);
    //                            FindServicePortProgressUpdated?.Invoke(current, responded, total);

    //                            if (serviceMatched)
    //                            {
    //                                lock (ipToScan.Services.Services[0].Ports)
    //                                {
    //                                    ipToScan.Services.Services[0].Ports[0].Status = PortStatus.IsRunning;
    //                                    ipToScan.Services.Services[0].Ports[0].Port = port;
    //                                }

    //                                //FindServicePortFinished?.Invoke(ipToScan);
    //                                cts.Cancel(); // Abbruch, wenn der Service erkannt wurde
    //                            }
    //                        }
    //                    }
    //                }
    //                catch (Exception ex)
    //                {
    //                    Console.WriteLine($"Fehler beim Scannen von Port {port}: {ex.Message}");
    //                }
    //                finally
    //                {
    //                    semaphore.Release();
    //                }
    //            });                
    //        }            
    //    }

    //    await Task.WhenAll(Enumerable.Range(0, semaphore.CurrentCount).Select(_ => semaphore.WaitAsync()).ToArray());

    //    FindServicePortFinished?.Invoke(ipToScan);
    //    return ipToScan;
    //}


    public async Task<IPToScan> FindServicePortAsync(IPToScan ipToScan, ServiceType service)
    {
        StartNewScan();

        current = 0;
        responded = 0;
        total = 65536;

        ipToScan.UsedScanMethod = ScanMethod.Services;

        ServiceResult serviceResult = new ServiceResult { Service = service };
        ipToScan.Services.Services.Add(serviceResult);

        var semaphore = new SemaphoreSlim(200); // Maximal 100 parallele Tasks
        
        List<int> ports = Enumerable.Range(0, 65536).ToList(); // Alle Ports von 0 bis 65535
        //List<int> ports = Enumerable.Range(1880, 8087).ToList(); // Alle Ports von 0 bis 65535

        // Liste für alle Tasks
        List<Task> tasks = new List<Task>();


        //ports.Clear();
        //ports.Add(3306);

        foreach (int port in ports)
        {
            if (_cts.Token.IsCancellationRequested) break; // 🔹 Falls der Scan gestoppt wurde, Schleife sofort beenden

            int currentValue = Interlocked.Increment(ref current);
            FindServicePortProgressUpdated?.Invoke(port, responded, total);

            try
            {
                await semaphore.WaitAsync(_cts.Token); // Warten auf freien Slot
            }
            catch (OperationCanceledException)
            {
                break; // Abbruch bei Token-Auslösung
            }

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    if (service == ServiceType.WebServices)
                    {
                        // WebService-Port-Check
                        PortResult portResult = await CheckWebServicePortAsync(ipToScan.IPorHostname, port);
                        if (portResult.Status == PortStatus.IsRunning)
                        {
                            int responsedValue = Interlocked.Increment(ref responded);
                            FindServicePortProgressUpdated?.Invoke(current, responsedValue, total);

                            lock (serviceResult.Ports)
                            {
                                serviceResult.Ports.Add(portResult);
                            }
                        }
                    }
                    else
                    {
                        // TCP-Verbindung prüfen
                        using TcpClient client = new TcpClient();
                        var connectTask = client.ConnectAsync(IPAddress.Parse(ipToScan.IPorHostname), port);
                        var delayTask = Task.Delay(1000); // Timeout auf 1 Sekunde

                        if (await Task.WhenAny(connectTask, delayTask) == connectTask && client.Connected)
                        {
                            using NetworkStream stream = client.GetStream();
                            await stream.WriteAsync(GetDetectionPacket(service), 0, GetDetectionPacket(service).Length);

                            using MemoryStream memoryStream = new MemoryStream();
                            byte[] buffer = new byte[1024];
                            DateTime startTime = DateTime.Now;

                            while ((DateTime.Now - startTime).TotalMilliseconds < 2000)
                            {
                                if (_cts.Token.IsCancellationRequested) break; // 🔹 Falls der Scan gestoppt wurde, Schleife sofort beenden

                                if (stream.DataAvailable)
                                {
                                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                                    if (bytesRead > 0)
                                    {
                                        memoryStream.Write(buffer, 0, bytesRead);
                                        startTime = DateTime.Now;
                                    }
                                    else break;
                                }
                                else
                                {
                                    await Task.Delay(50);
                                }
                            }

                            byte[] response = memoryStream.ToArray();
                            if (response.Length > 0 && IdentifyServices(response, service))
                            {
                                int responsedValue = Interlocked.Increment(ref responded);
                                FindServicePortProgressUpdated?.Invoke(current, responsedValue, total);

                                lock (ipToScan.Services.Services[0].Ports)
                                {
                                    ipToScan.Services.Services[0].Ports.Add(new PortResult { Port = port, Status = PortStatus.IsRunning });
                                }

                                _cts.Cancel(); // Abbruch, wenn der 1. [erste] Service erkannt wurde
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Fehler beim Scannen von Port {port}: {ex.Message}");
                }
                finally
                {
                    semaphore.Release();
                }
            }));
        }

        try
        {
            //await Task.WhenAll(tasks.Where(t => !t.IsCanceled));

            // Zusätzliche Sicherheit: Warte, bis alle Semaphore-Slots zurückgesetzt wurden
            await Task.WhenAll(Enumerable.Range(0, semaphore.CurrentCount).Select(_ => semaphore.WaitAsync()).ToArray());
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Scan abgebrochen.");
        }
        finally
        {
            FindServicePortFinished?.Invoke(ipToScan);  // Stelle sicher, dass das Event ausgelöst wird
        }
        return ipToScan;
    }
















    private bool IdentifyServices(byte[] response, ServiceType service)
    {
        bool serviceMatched = false;
        string str_serviceResponse = Encoding.ASCII.GetString(response);

        // ?? FTP
        if (service == ServiceType.FTP)
        {
            if (str_serviceResponse.StartsWith("220 "))
            {
                serviceMatched = true;
            }
        }

        // ?? SSH / SFTP
        if (service == ServiceType.SSH)
        {
            string sshResponse = Encoding.ASCII.GetString(response);

            // Prüfen, ob die Antwort das typische "SSH-2.0" enthält
            if (sshResponse.StartsWith("SSH-2.0"))
            {
                serviceMatched = true;

                // Optional: Version und Software extrahieren
                int versionIndex = sshResponse.IndexOf("-");
                if (versionIndex >= 0)
                {
                    string sftpVersion = sshResponse.Substring(versionIndex + 1).Trim();
                    Console.WriteLine($"SFTP Detected: {sftpVersion}");
                }
            }
        }


        // ?? UltraVNC-Erkennung        
        if (service == ServiceType.UltraVNC)
        {
            //UlraVNC Header RFB als hex
            byte[] ultraVncHeader = { 0x52, 0x46, 0x42 };

            if (response.Take(ultraVncHeader.Length).SequenceEqual(ultraVncHeader))
            {
                serviceMatched = true;
            }
        }

        // ?? TeamViewer-Erkennung
        if (service == ServiceType.TeamViewer)
        {
            byte[] teamViewerHeader1 = { 0x17, 0x24, 0x0A, 0x20 };  // Header 1
            byte[] teamViewerHeader2 = { 0x11, 0x30, 0x36, 0x00 };  // Header 2

            bool match1 = response.Take(4).SequenceEqual(teamViewerHeader1);
            bool match2 = response.Skip(37).Take(4).SequenceEqual(teamViewerHeader2);
            if (match1 && match2)
            {
                serviceMatched = true;
            }
        }


        // BigFix Remote Control
        if (service == ServiceType.BigFixRemote)
        {
            // BigFix Antwort-Paket 1: 04-2B-B4-90-05-02 / Paket 2: 00-00-00-00-00-00   antwort in c# wegen tcpclient in einem array
            byte[] bigFixHeader = { 0x04, 0x2B, 0xB4, 0x90, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            if (response.Length == 12)
            {
                bool match = response.SequenceEqual(bigFixHeader);

                if (match)
                {
                    serviceMatched = true;
                }
            }
        }


        // ?? AnyDesk
        if (service == ServiceType.Anydesk)
        {
            string tada2 = Encoding.ASCII.GetString(response);
            if (tada2.ToLower().Contains("anydesk client")) serviceMatched = true;
        }

        // ?? Microsoft SQL Server
        if (service == ServiceType.MSSQLServer)
        {
            // MSSQL-TDS-Erkennung (Pre-Login-Paket)
            if (response.Length > 8 && response[0] == 0x04 && response[1] == 0x01)
            {
                // Mindestlänge und typische Struktur prüfen
                int packetLength = response[2] << 8 | response[3]; // Paketlänge aus Byte 2 und 3
                if (packetLength > 8 && packetLength < 512)
                {
                    serviceMatched = true;
                }
            }
        }


        // ?? PostgreSQL-Erkennung
        if (service == ServiceType.PostgreSQL)
        {
            if (response.Length == 1)
            {
                // Überprüfung auf PostgreSQL-"Ready for Query"-Antwort ("R" + 7 weitere Bytes)
                if (response[0] == 0x4e)
                {
                    serviceMatched = true;
                }
            }
            if (response.Length >= 8)
            {
                // Überprüfung auf PostgreSQL-"Ready for Query"-Antwort ("R" + 7 weitere Bytes)
                if (response[0] == 0x52 && response[1] == 0x00 && response[2] == 0x00)
                {
                    serviceMatched = true;
                }
            }
        }

        // ?? MariaDB
        if (service == ServiceType.MariaDB)
        {
            if (str_serviceResponse.ToLower().Contains("mariadb"))
            {
                serviceMatched = true;
            }
        }


        if (service == ServiceType.MongoDB)
        {
            // Typischer MongoDB-Header in der Antwort
            byte[] bjsonHeader = { 0x49, 0x01, 0x00, 0x00 };  // BJSON format beginnt so

            bool bjsonHeaderMatched = response.Take(4).SequenceEqual(bjsonHeader);
            bool str_ContainsHelloOK = str_serviceResponse.ToLower().Contains("hellook");
            bool str_Contains_topologyVersion = str_serviceResponse.ToLower().Contains("topologyversion");

            if (bjsonHeaderMatched && str_ContainsHelloOK && str_Contains_topologyVersion)
            {
                serviceMatched = true;
            }
        }


        // ?? InfluxDB 2
        if (service == ServiceType.InfluxDB2)
        {
            if (str_serviceResponse.ToLower().Contains("influxdb"))
            {
                serviceMatched = true;
            }
        }


        // ?? OPC UA
        if (service == ServiceType.OPCUA)
        {
            if (response.Length >= 4)
            {
                byte[] opcUaHelloHeader = { 0x48, 0x45, 0x4C, 0x46 }; // HELF
                byte[] opcUaAckHeader = { 0x41, 0x43, 0x4B, 0x46 };   // ACKF

                if (response.Take(4).SequenceEqual(opcUaHelloHeader))
                {
                    //OPC UA Hello Frame erkannt
                    serviceMatched = true;
                }
                else if (response.Take(4).SequenceEqual(opcUaAckHeader))
                {
                    //OPC UA Acknowledge Frame erkannt
                    serviceMatched = true;
                }
            }
        }

        // ?? Modbus TCP-Erkennung
        if (service == ServiceType.ModBus)
        {
            // Modbus TCP Header besteht mindestens aus 7 Bytes:
            // [0-1] Transaction Identifier (2 Bytes)
            // [2-3] Protocol Identifier (immer 0x00 0x00 für Modbus TCP)
            // [4-5] Length Field (Länge der nachfolgenden Daten)
            // [6]   Unit Identifier
            // [7+]  Function Code + Payload
            if (response.Length >= 7)
            {
                // Protokollkennung überprüfen (muss 0x00 0x00 für Modbus TCP sein)
                bool isModbusTcp = response[2] == 0x00 && response[3] == 0x00;

                // Funktioncode prüfen: Gültige Modbus-Funktionscodes liegen zwischen 0x01 und 0x10
                // Beispiele:
                // 0x01 - Read Coils
                // 0x02 - Read Discrete Inputs
                // 0x03 - Read Holding Registers
                // 0x04 - Read Input Registers
                // 0x05 - Write Single Coil
                // 0x06 - Write Single Register
                // 0x10 - Write Multiple Registers
                byte functionCode = response[7];
                bool validFunctionCode = functionCode >= 0x01 && functionCode <= 0x10;

                // Wenn sowohl das Protokoll als auch der Funktionscode stimmen, erkennen wir Modbus TCP
                if (isModbusTcp && validFunctionCode)
                {
                    serviceMatched = true;
                }
            }
        }


        return serviceMatched;
    }






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
                                logBuilder.AppendLine("? AnyDesk in Serverantwort gefunden.");
                            }
                            else
                            {
                                logBuilder.AppendLine("? Server hat geantwortet, aber AnyDesk nicht gefunden.");
                            }
                        }
                        else
                        {
                            portResult.Status = PortStatus.NoResponse;
                            logBuilder.AppendLine("?? Port ist offen, aber keine Antwort von einer Anwendung.");
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        logBuilder.AppendLine("? Antwort vom Server dauerte zu lange.");
                    }
                    catch (Exception ex)
                    {
                        logBuilder.AppendLine($"? Fehler beim Lesen der Antwort: {ex.Message}");
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
                    logBuilder.AppendLine($"?? Fehler nach {RetryCount} Versuchen: {ex.Message}");
                }
            }
        }

        portResult.PortLog = logBuilder.ToString();
        return portResult;
    }

    


    public async Task<List<string>> SendDhcpDiscoverAsync(byte[] dhcpDiscoverPacket)
    {
        List<string> dhcpServers = new List<string>();

        try
        {

            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
                //socket.Bind(new IPEndPoint(IPAddress.Any, 68));  // Lausche auf Port 68 für eingehende Broadcasts
                socket.Bind(new IPEndPoint(SupportMethods.SelectedNetworkInterfaceInfos.IPv4, 68));  // Lausche auf Port 68 für eingehende Broadcasts

                IPEndPoint dhcpServerEndPoint = new IPEndPoint(IPAddress.Broadcast, 67);
                Console.WriteLine($"?? Sende DHCP DISCOVER...");

                // Sende DHCP DISCOVER
                socket.SendTo(dhcpDiscoverPacket, dhcpServerEndPoint);

                DateTime startTime = DateTime.Now;
                int timeout = 2000;  // 2 Sekunden Timeout

                try
                {
                    while ((DateTime.Now - startTime).TotalMilliseconds < timeout)
                    {
                        if (socket.Poll(100000, SelectMode.SelectRead))  // 100 ms warten, ob Daten verfügbar sind
                        {
                            byte[] buffer = new byte[1024];
                            //EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                            EndPoint remoteEndPoint = new IPEndPoint(SupportMethods.SelectedNetworkInterfaceInfos.IPv4, 0);
                            int receivedBytes = socket.ReceiveFrom(buffer, ref remoteEndPoint);

                            if (receivedBytes >= 28)
                            {
                                string dhcpServerIp = GetDhcpServerIp(buffer);
                                if (!string.IsNullOrEmpty(dhcpServerIp) && !dhcpServers.Contains(dhcpServerIp))
                                {
                                    dhcpServers.Add(dhcpServerIp);
                                    Console.WriteLine($"? DHCP-Server gefunden: {dhcpServerIp}");
                                }
                            }
                        }
                    }
                }
                catch (SocketException ex)
                {
                    Console.WriteLine($"? Fehler beim Empfang: {ex.Message}");
                }

                return dhcpServers;
            }
        }
        catch
        {

        }
        return dhcpServers;
    }





    string GetDhcpServerIp(byte[] response)
    {
        // 1 Prüfe Option 54 (beste Methode)
        int index = Array.IndexOf(response, (byte)54);
        if (index > 0)
            return new IPAddress(response.Skip(index + 2).Take(4).ToArray()).ToString();

        // 2 Prüfe GIADDR (nur falls vorhanden)
        string relayAgentIp = new IPAddress(response.Skip(24).Take(4).ToArray()).ToString();
        if (relayAgentIp != "0.0.0.0")
            return relayAgentIp;

        // 3 Prüfe SIADDR (nur als letzte Option)
        return new IPAddress(response.Skip(16).Take(4).ToArray()).ToString();
    }







    private async Task<List<int>> GetMSSQLDynamicPortsAsync(string serverIP)
    {
        const int MaxRetries = 3; // ?? Anzahl der Wiederholungen
        const int TimeoutMilliseconds = 2000; // ? Timeout pro Versuch (3 Sekunden)
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

                        Console.WriteLine($"?? SQL Browser Antwort (Versuch {attempt}): {responseText}");

                        // ?? Alle "tcp;" Ports suchen (nicht nur den ersten!)
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
                            return foundPorts; // ? Erfolgreich gefundene Ports zurückgeben
                        }
                    }
                    else
                    {
                        Console.WriteLine($"?? Versuch {attempt}: Timeout - Keine Antwort vom SQL Browser-Dienst.");
                    }
                }
                catch (SocketException ex)
                {
                    Console.WriteLine($"?? Versuch {attempt}: Fehler beim Abrufen des SQL-Ports: {ex.Message}");
                }
            }
        }

        Console.WriteLine($"? Keine MSSQL-Dynamikports gefunden nach {MaxRetries} Versuchen.");
        return foundPorts; // ? Leere Liste, falls nichts gefunden wurde
    }

    //private async Task<PortResult> CheckWebServicePortAsync(string ipAddress, int port)
    //{
    //    PortResult portResult = new PortResult { Port = port, PortLog = "" };

    //    using (var tcpClient = new TcpClient())
    //    {
    //        try
    //        {
    //            // ?? Versuche, eine Verbindung herzustellen
    //            var connectTask = tcpClient.ConnectAsync(ipAddress, port);
    //            var delayTask = Task.Delay(500); // Timeout nach 2 Sekunden

    //            if (await Task.WhenAny(connectTask, delayTask) != connectTask)
    //            {
    //                // ? Verbindung hat zu lange gedauert ? Port ist gefiltert
    //                portResult.Status = PortStatus.Filtered;
    //                return portResult;
    //            }

    //            if (!tcpClient.Connected)
    //            {
    //                // ? Verbindung fehlgeschlagen
    //                portResult.Status = PortStatus.NoResponse;
    //                return portResult;
    //            }

    //            // ? Verbindung erfolgreich ? Stream verwenden
    //            using (NetworkStream stream = tcpClient.GetStream())
    //            {
    //                byte[] requestBytes = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: " + ipAddress + "\r\n\r\n");
    //                await stream.WriteAsync(requestBytes, 0, requestBytes.Length);

    //                // ?? Antwort empfangen
    //                byte[] buffer = new byte[1024];

    //                try
    //                {
    //                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
    //                    if (bytesRead > 0)
    //                    {
    //                        string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
    //                        portResult.PortLog += response;

    //                        //if (!string.IsNullOrEmpty(response))
    //                        //    portResult.Status = PortStatus.IsRunning;

    //                        if (response.Contains("HTTP/1.1") && (response.Contains("200 OK") || response.Contains("301") || response.Contains("302")))
    //                        {
    //                            portResult.Status = PortStatus.IsRunning;
    //                        }
    //                        else if (response.Contains("<html") || response.Contains("<body") || response.Contains("<head"))
    //                        {
    //                            portResult.Status = PortStatus.IsRunning;
    //                        }                            
    //                    }
    //                }
    //                catch (IOException ex)
    //                {
    //                    portResult.Status = PortStatus.Closed;
    //                    portResult.PortLog += "? Verbindung wurde vom Remotehost geschlossen: " + ex.Message;
    //                }
    //                catch (ObjectDisposedException)
    //                {
    //                    portResult.Status = PortStatus.Closed;
    //                    portResult.PortLog += "?? Die Verbindung wurde unerwartet beendet.";
    //                }
    //            }
    //        }
    //        catch (SocketException ex)
    //        {
    //            switch (ex.SocketErrorCode)
    //            {
    //                case SocketError.ConnectionRefused:
    //                    portResult.Status = PortStatus.Closed;
    //                    break;
    //                case SocketError.TimedOut:
    //                    portResult.Status = PortStatus.Filtered;
    //                    break;
    //                default:
    //                    portResult.Status = PortStatus.UnknownResponse;
    //                    break;
    //            }
    //        }
    //    }
    //    return portResult;
    //}



    private async Task<PortResult> CheckWebServicePortAsync(string ipAddress, int port)
    {
        PortResult portResult = new PortResult { Port = port, Status = PortStatus.NoResponse };

        // **1?? Temporäre Status-Werte für HTTP & HTTPS**
        PortStatus httpStatus = PortStatus.NoResponse;
        PortStatus httpsStatus = PortStatus.NoResponse;

        // **2?? Prüfe HTTP**
        bool httpSuccess = await CheckHttpAsync(ipAddress, port, portResult);
        httpStatus = portResult.Status; // Speichere HTTP-Ergebnis

        // **3?? Prüfe HTTPS**
        bool httpsSuccess = await CheckHttpsAsync(ipAddress, port, portResult);
        httpsStatus = portResult.Status; // Speichere HTTPS-Ergebnis

        // **4?? Priorisierung der Status-Werte**
        if (httpSuccess || httpsSuccess)
        {
            portResult.Status = PortStatus.IsRunning;  // Höchste Priorität
        }
        else if (httpStatus == PortStatus.Error || httpsStatus == PortStatus.Error)
        {
            portResult.Status = PortStatus.Error;  // Fehler geht nicht verloren
        }
        else if (httpStatus == PortStatus.Open || httpsStatus == PortStatus.Open)
        {
            portResult.Status = PortStatus.Open;
        }
        else if (httpStatus == PortStatus.Filtered || httpsStatus == PortStatus.Filtered)
        {
            portResult.Status = PortStatus.Filtered;
        }
        else
        {
            portResult.Status = PortStatus.NoResponse;
        }

        return portResult;
    }

    //private async Task<bool> CheckHttpAsync(string ipAddress, int port, PortResult portResult)
    //{
    //    using (var tcpClient = new TcpClient())
    //    using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1))) // Timeout von 1 Sekunde
    //    {
    //        try
    //        {
    //            Task connectTask = tcpClient.ConnectAsync(ipAddress, port);
    //            if (await Task.WhenAny(connectTask, Task.Delay(1000, cts.Token)) != connectTask)
    //            {
    //                portResult.Status = PortStatus.NoResponse; // Keine Antwort vom Port (Timeout).
    //                return false;
    //            }

    //            if (!tcpClient.Connected)
    //            {
    //                portResult.Status = PortStatus.Filtered; // Verbindung verweigert (z. B. durch Firewall).
    //                return false;
    //            }

    //            using (NetworkStream stream = tcpClient.GetStream())
    //            {
    //                byte[] requestBytes = Encoding.UTF8.GetBytes("GET / HTTP/1.1\r\nHost: " + ipAddress + "\r\nConnection: close\r\n\r\n");
    //                await stream.WriteAsync(requestBytes, 0, requestBytes.Length, cts.Token);

    //                byte[] buffer = new byte[4096];
    //                var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
    //                if (await Task.WhenAny(readTask, Task.Delay(1000, cts.Token)) != readTask)
    //                {
    //                    portResult.Status = PortStatus.NoResponse; // Antwort kam nicht rechtzeitig.
    //                    return false;
    //                }

    //                int bytesRead = await readTask;
    //                if (bytesRead > 0)
    //                {
    //                    string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

    //                    if (response.Contains("HTTP/1.1") && (response.Contains("200 OK") || response.Contains("<html")))
    //                    {
    //                        portResult.Status = PortStatus.IsRunning; // Webseite erkannt.
    //                        return true;
    //                    }

    //                    portResult.Status = PortStatus.Open; // Verbindung offen, aber keine Webseite.
    //                    return false;
    //                }
    //            }
    //        }
    //        catch (SocketException ex)
    //        {
    //            if (ex.SocketErrorCode == SocketError.ConnectionRefused)
    //            {
    //                portResult.Status = PortStatus.Filtered; // Verbindung aktiv verweigert ? Firewall?
    //            }
    //            else
    //            {
    //                portResult.Status = PortStatus.Error; // Sonstiger Netzwerkfehler.
    //            }
    //        }
    //    }
    //    return false;
    //}

    //private async Task<bool> CheckHttpAsync(string ipAddress, int port, PortResult portResult)
    //{
    //    using (var tcpClient = new TcpClient())
    //    using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2))) // 2 Sekunden Timeout
    //    {
    //        try
    //        {
    //            // Starte Verbindungsversuch
    //            Task connectTask = tcpClient.ConnectAsync(ipAddress, port);
    //            if (await Task.WhenAny(connectTask, Task.Delay(2000, cts.Token)) != connectTask)
    //            {
    //                portResult.Status = PortStatus.NoResponse; // Timeout erreicht
    //                return false;
    //            }

    //            if (!tcpClient.Connected)
    //            {
    //                portResult.Status = PortStatus.Filtered; // Verbindung verweigert (z. B. durch Firewall)
    //                return false;
    //            }

    //            using (NetworkStream stream = tcpClient.GetStream())
    //            using (var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true))
    //            using (var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true))
    //            {
    //                writer.NewLine = "\r\n"; // HTTP erfordert CRLF
    //                writer.AutoFlush = true;

    //                // **HTTP-Header mit User-Agent senden (verhindert Blockierung)**
    //                await writer.WriteLineAsync($"GET / HTTP/1.1");
    //                await writer.WriteLineAsync($"Host: {ipAddress}");
    //                await writer.WriteLineAsync("Connection: close");
    //                await writer.WriteLineAsync("User-Agent: Mozilla/5.0 (compatible; MyScanner/1.0)");
    //                await writer.WriteLineAsync(""); // Leere Zeile, um Header zu beenden

    //                // **Lese Antwort mit Timeout**
    //                Task<string> readTask = reader.ReadToEndAsync();
    //                if (await Task.WhenAny(readTask, Task.Delay(2000, cts.Token)) != readTask)
    //                {
    //                    portResult.Status = PortStatus.NoResponse; // Antwort zu lange gebraucht
    //                    return false;
    //                }

    //                string response = await readTask;

    //                // **Überprüfe, ob Server antwortet**
    //                if (response.Contains("HTTP/1.1") && (response.Contains("200 OK") || response.Contains("<html")))
    //                {
    //                    portResult.Status = PortStatus.IsRunning; // Webseite erkannt
    //                    return true;
    //                }

    //                portResult.Status = PortStatus.Open; // Verbindung offen, aber kein Webserver erkannt
    //                return false;
    //            }
    //        }
    //        catch (SocketException ex)
    //        {
    //            if (ex.SocketErrorCode == SocketError.ConnectionRefused)
    //            {
    //                portResult.Status = PortStatus.Filtered; // Firewall oder kein Service aktiv
    //            }
    //            else
    //            {
    //                portResult.Status = PortStatus.Error; // Allgemeiner Netzwerkfehler
    //            }
    //        }
    //        catch (IOException ex)
    //        {
    //            portResult.Status = PortStatus.Error; // Verbindung wurde unerwartet geschlossen
    //        }
    //        catch (OperationCanceledException)
    //        {
    //            portResult.Status = PortStatus.NoResponse; // Timeout erreicht
    //        }
    //    }
    //    return false;
    //}

    private async Task<bool> CheckHttpAsync(string ipAddress, int port, PortResult portResult)
    {
        using (var tcpClient = new TcpClient())
        using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2))) // 2s Timeout
        {
            try
            {
                // Starte Verbindungsversuch
                Task connectTask = tcpClient.ConnectAsync(ipAddress, port);
                if (await Task.WhenAny(connectTask, Task.Delay(2000, cts.Token)) != connectTask)
                {
                    portResult.Status = PortStatus.NoResponse; // Timeout erreicht
                    return false;
                }

                if (!tcpClient.Connected)
                {
                    portResult.Status = PortStatus.Filtered; // Verbindung verweigert
                    return false;
                }

                using (NetworkStream stream = tcpClient.GetStream())
                using (var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true))
                using (var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true))
                {
                    writer.NewLine = "\r\n"; // HTTP erfordert CRLF
                    writer.AutoFlush = true;

                    // **HTTP-Header korrekt setzen**
                    await writer.WriteLineAsync($"GET / HTTP/1.1");
                    await writer.WriteLineAsync($"Host: {ipAddress}");
                    await writer.WriteLineAsync("Connection: close");
                    await writer.WriteLineAsync("User-Agent: Mozilla/5.0 (compatible; MyScanner/1.0)");
                    await writer.WriteLineAsync("Accept: */*"); // Erlaubt alle Antworten
                    await writer.WriteLineAsync("Accept-Encoding: identity"); // Verhindert GZIP-Probleme
                    await writer.WriteLineAsync(""); // Leere Zeile für HTTP-Protokollkonformität

                    // **Lese Antwort mit Timeout**
                    Task<string> readTask = reader.ReadToEndAsync();
                    if (await Task.WhenAny(readTask, Task.Delay(2000, cts.Token)) != readTask)
                    {
                        portResult.Status = PortStatus.NoResponse; // Antwort zu lange gebraucht
                        return false;
                    }

                    string response = await readTask;

                    // **Überprüfe, ob Server antwortet**
                    //if (response.Contains("HTTP/1.1") || response.Contains("302 Redirect") || (response.Contains("200 OK") || response.Contains("<html")))

                    // [2345] → Erfasst alle wichtigen HTTP-Statuscodes:
                    // 2xx = Erfolg
                    // 3xx = Weiterleitung
                    // 4xx = Client - Fehler(z.B.falsche Anfrage, aber Gerät antwortet)
                    // 5xx = Server - Fehler

                    if (Regex.IsMatch(response, @"^HTTP/\d\.\d [2345]\d{2}") || response.ToLower().Contains("<html"))
                    {
                        portResult.Status = PortStatus.IsRunning; // Webseite erkannt
                        return true;
                    }

                    portResult.Status = PortStatus.Open; // Verbindung offen, aber kein Webserver erkannt
                    return false;
                }
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    portResult.Status = PortStatus.Filtered; // Firewall oder kein Service aktiv
                }
                else
                {
                    portResult.Status = PortStatus.Error; // Netzwerkfehler
                }
            }
            catch (IOException ex)
            {
                portResult.Status = PortStatus.Error; // Verbindung wurde unerwartet geschlossen
            }
            catch (OperationCanceledException)
            {
                portResult.Status = PortStatus.NoResponse; // Timeout erreicht
            }
        }
        return false;
    }





    private async Task<bool> CheckHttpsAsync(string ipAddress, int port, PortResult portResult)
    {
        using (var tcpClient = new TcpClient())
        using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1))) // Timeout von 1 Sekunde für Verbindung
        {
            try
            {
                Task connectTask = tcpClient.ConnectAsync(ipAddress, port);
                if (await Task.WhenAny(connectTask, Task.Delay(1000, cts.Token)) != connectTask)
                {
                    portResult.Status = PortStatus.NoResponse; // Keine Antwort vom Port.
                    return false;
                }

                if (!tcpClient.Connected)
                {
                    portResult.Status = PortStatus.Filtered; // Verbindung verweigert ? Firewall.
                    return false;
                }

                using (SslStream sslStream = new SslStream(tcpClient.GetStream(), false, (sender, cert, chain, sslPolicyErrors) => true))
                using (var sslCts = new CancellationTokenSource(TimeSpan.FromSeconds(2))) // Timeout für SSL-Handshake
                {
                    var sslTask = sslStream.AuthenticateAsClientAsync(ipAddress);
                    if (await Task.WhenAny(sslTask, Task.Delay(2000, sslCts.Token)) != sslTask)
                    {
                        portResult.Status = PortStatus.NoResponse; // SSL-Timeout ? Server antwortet nicht.
                        return false;
                    }

                    // **WICHTIG**: Prüfen, ob der SSL-Handshake wirklich erfolgreich war
                    if (!sslStream.IsAuthenticated)
                    {
                        portResult.Status = PortStatus.Error; // SSL-Fehler
                        return false;
                    }

                    // **Nur jetzt darf die Anfrage gesendet werden**
                    byte[] requestBytes = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: " + ipAddress + "\r\nConnection: close\r\n\r\n");
                    await sslStream.WriteAsync(requestBytes, 0, requestBytes.Length, sslCts.Token);

                    byte[] buffer = new byte[4096];
                    var readTask = sslStream.ReadAsync(buffer, 0, buffer.Length, sslCts.Token);
                    if (await Task.WhenAny(readTask, Task.Delay(2000, sslCts.Token)) != readTask)
                    {
                        portResult.Status = PortStatus.NoResponse; // Antwort nicht erhalten.
                        return false;
                    }

                    int bytesRead = await readTask;
                    if (bytesRead > 0)
                    {
                        string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                        //if (response.Contains("HTTP/1.1") && (response.Contains("200 OK") || response.Contains("<html")))

                        // [2345] → Erfasst alle wichtigen HTTP-Statuscodes:
                        // 2xx = Erfolg
                        // 3xx = Weiterleitung
                        // 4xx = Client - Fehler(z.B.falsche Anfrage, aber Gerät antwortet)
                        // 5xx = Server - Fehler

                        if (Regex.IsMatch(response, @"^HTTP/\d\.\d [2345]\d{2}") || response.ToLower().Contains("<html"))
                        {
                            portResult.Status = PortStatus.IsRunning; // Webseite erkannt.
                            return true;
                        }

                        portResult.Status = PortStatus.Open; // Port ist offen, aber keine Webseite.
                        return false;
                    }
                }
            }
            catch (InvalidOperationException ex)
            {
                portResult.Status = PortStatus.Error; // SSL-Verbindung konnte nicht hergestellt werden.
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                portResult.Status = PortStatus.Filtered; // Verbindung verweigert.
            }
            catch (Exception ex)
            {
                portResult.Status = PortStatus.Error; // Sonstiger Fehler.
            }
        }
        return false;
    }





































    static async Task<PortResult> SendTcpDnsQuery(string dnsServer, byte[] query, int port)
    {
        PortResult portResult = new PortResult { Port = port, Status = PortStatus.NoResponse };

        for (int attempt = 1; attempt <= 3; attempt++) // Maximal 3 Wiederholungen
        {
            try
            {
                using TcpClient client = new TcpClient();
                var connectTask = client.ConnectAsync(dnsServer, port);
                var timeoutTask = Task.Delay(2000); // 2 Sekunden Timeout für Verbindung

                if (await Task.WhenAny(connectTask, timeoutTask) != connectTask)
                {
                    portResult.Status = PortStatus.Filtered; // Verbindung zu lange ? Port gefiltert
                    return portResult;
                }

                if (!client.Connected)
                {
                    portResult.Status = PortStatus.NoResponse; // Verbindung nicht erfolgreich
                    return portResult;
                }

                portResult.Status = PortStatus.Open;
                using NetworkStream stream = client.GetStream();

                // DNS-Anfrage mit Längenpräfix
                byte[] tcpQuery = new byte[query.Length + 2];
                tcpQuery[0] = (byte)(query.Length >> 8);
                tcpQuery[1] = (byte)(query.Length & 0xFF);
                Buffer.BlockCopy(query, 0, tcpQuery, 2, query.Length);

                await stream.WriteAsync(tcpQuery, 0, tcpQuery.Length);

                // Antwort-Längenfeld zuerst lesen (mit Timeout)
                byte[] lengthBuffer = new byte[2];
                var cts = new CancellationTokenSource(2000); // Antwort-Timeout (2s)
                int lengthRead = await stream.ReadAsync(lengthBuffer, 0, 2, cts.Token);

                if (lengthRead < 2)
                {
                    portResult.Status = PortStatus.NoResponse;
                    continue; // Erneut versuchen
                }

                int responseLength = (lengthBuffer[0] << 8) | lengthBuffer[1];

                // Antwortdaten lesen (mit Timeout)
                byte[] responseBuffer = new byte[responseLength];
                int bytesRead = await stream.ReadAsync(responseBuffer, 0, responseLength, cts.Token);

                if (bytesRead > 0)
                {
                    portResult.Status = PortStatus.IsRunning;
                    portResult.PortLog = Encoding.ASCII.GetString(responseBuffer);
                    return portResult; // Erfolgreich!
                }
            }
            catch (OperationCanceledException)
            {
                portResult.Status = PortStatus.NoResponse;
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"?? Versuch {attempt}: Fehler beim DNS-Request - {ex.Message}");
            }

            await Task.Delay(200); // Kürzere Pause vor nächstem Versuch
        }

        return portResult; // Keine Antwort nach 3 Versuchen
    }


   
    static async Task<PortResult> SendUdpDnsQuery(string dnsServer, byte[] query, int port = 53)
    {
        PortResult portResult = new PortResult { Port = port, Status = PortStatus.NoResponse };

        using UdpClient udpClient = new UdpClient();
        udpClient.Connect(dnsServer, port);       


        for (int attempt = 1; attempt <= 3; attempt++) // Maximal 3 Wiederholungen
        {
            try
            {
                await udpClient.SendAsync(query, query.Length);

                using var cts = new CancellationTokenSource(1000); // 1 Sekunde Timeout
                var receiveTask = udpClient.ReceiveAsync();

                if (await Task.WhenAny(receiveTask, Task.Delay(1000, cts.Token)) == receiveTask)
                {
                    // ? Antwort erhalten
                    portResult.Status = PortStatus.IsRunning;
                    portResult.PortLog = Encoding.ASCII.GetString(receiveTask.Result.Buffer);
                    return portResult;
                }
            }
            catch (OperationCanceledException)
            {
                portResult.Status = PortStatus.NoResponse;
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"?? Versuch {attempt}: Fehler beim DNS-Request - {ex.Message}");
            }

            if (attempt < 3) await Task.Delay(200); // Schnellere Wiederholungen (200ms)
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


    private DataTable _dt_Servives = new DataTable();
    public DataTable Services 
    {
        get { return _dt_Servives; }
        set { _dt_Servives = value; } 
    }
    
    private  void SetServicePorts(string ServiceFilePath)
    {
        _dt_Servives.TableName = "ServicesToScan";
        _dt_Servives.Columns.Add("toScan", typeof(bool));
        _dt_Servives.Columns.Add("Service", typeof(string));
        _dt_Servives.Columns.Add("Ports", typeof(string));
        _dt_Servives.Columns.Add("HelloBytePackage", typeof(string));
        _dt_Servives.Columns.Add("ResponsedBytePackagePart", typeof(string));
        _dt_Servives.Columns.Add("ResponsedContainsString", typeof(string));
        _dt_Servives.Columns.Add("ServiceGroup", typeof(string)); // Gruppierungs-Spalte


        foreach (ServiceType serviceType in Enum.GetValues(typeof(ServiceType)))
        {
            DataRow row = _dt_Servives.NewRow();
            row["toScan"] = false;
            row["Service"] = serviceType.ToString();
            row["Ports"] = string.Join(", ", GetDefaultServicePorts(serviceType));
            row["HelloBytePackage"] = GetDetectionPackageString(serviceType);  // Optional: Hier kannst du Hex-Strings einfügen
            row["ResponsedBytePackagePart"] = "";
            row["ResponsedContainsString"] = "";
            row["ServiceGroup"] = GetServiceGroup(serviceType);

            _dt_Servives.Rows.Add(row);
        }


        if (File.Exists(ServiceFilePath))
        {
            try
            {
                DataTable tempTable = new DataTable();
                tempTable.ReadXml(ServiceFilePath);

                foreach (DataRow tempRow in tempTable.Rows)
                {
                    DataRow existingRow = _dt_Servives.Rows
                        .Cast<DataRow>()
                        .FirstOrDefault(r => r["Service"].ToString() == tempRow["Service"].ToString());

                    if (existingRow != null)
                    {
                        // Ports vergleichen
                        if (existingRow["Ports"].ToString() != tempRow["Ports"].ToString())
                        {
                            existingRow["Ports"] = tempRow["Ports"];
                            Console.WriteLine($"Ports für {existingRow["Service"]} aktualisiert: {existingRow["Ports"]}");
                        }

                        // HelloBytePackage vergleichen
                        if (existingRow["HelloBytePackage"].ToString() != tempRow["HelloBytePackage"].ToString())
                        {
                            existingRow["HelloBytePackage"] = tempRow["HelloBytePackage"];
                        }

                        // ResponsedBytePackagePart vergleichen
                        if (existingRow["ResponsedBytePackagePart"].ToString() != tempRow["ResponsedBytePackagePart"].ToString())
                        {
                            existingRow["ResponsedBytePackagePart"] = tempRow["ResponsedBytePackagePart"];
                        }

                        // ResponsedContainsString vergleichen
                        if (existingRow["ResponsedContainsString"].ToString() != tempRow["ResponsedContainsString"].ToString())
                        {
                            existingRow["ResponsedContainsString"] = tempRow["ResponsedContainsString"];
                        }

                        // ToScan aktualisieren
                        existingRow["toScan"] = tempRow["toScan"];
                    }
                }
            }
            catch { }
        }
    }

    public void SaveServiceSettingsToXML()
    {
        try
        {
            foreach (DataRow row in _dt_Servives.Rows)
            {
                // Ports formatieren: "53,46" ? "53, 46"
                if (row["Ports"] != DBNull.Value)
                {
                    row["Ports"] = string.Join(", ", row["Ports"].ToString().Split(',').Select(p => p.Trim()));
                }

                // HelloBytePackage formatieren
                if (row["HelloBytePackage"] != DBNull.Value)
                {
                    row["HelloBytePackage"] = string.Join(", ", row["HelloBytePackage"].ToString().Split(',').Select(p => p.Trim()));
                }

                // ResponsedBytePackagePart formatieren
                if (row["ResponsedBytePackagePart"] != DBNull.Value)
                {
                    row["ResponsedBytePackagePart"] = string.Join(", ", row["ResponsedBytePackagePart"].ToString().Split(',').Select(p => p.Trim()));
                }
            }

            _dt_Servives.WriteXml(_serviceXMLPath, XmlWriteMode.WriteSchema);
            Console.WriteLine("? XML-Datei erfolgreich gespeichert (mit formatierter Ports-, Hello- und Response-Spalte).");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"? Fehler beim Speichern der XML-Datei: {ex.Message}");
        }
    }







    public static List<int> GetDefaultServicePorts(ServiceType service)
    {
        return service switch
        {
            // ?? Netzwerk-Dienste
            ServiceType.WebServices => new List<int> { 80, 443, 1880, 3000, 5000, 5001, 8080, 8086, 8443 }, // HTTP/S
            ServiceType.DNS_TCP => new List<int> { 53 },  // Domain Name Service
            ServiceType.DNS_UDP => new List<int> { 53 },  // Domain Name Service
            ServiceType.DHCP => new List<int> { 67 },  // Dynamic Host Configuration Protocol
            ServiceType.SSH => new List<int> { 22 },  // Secure Shell
            ServiceType.FTP => new List<int> { 21 },  // File Transfer Protocol

            // ??? Remote-Desktop & Fernwartung
            ServiceType.RDP => new List<int> { 3389 },  // Microsoft Remote Desktop
            ServiceType.UltraVNC => new List<int> { 5900, 5901, 5902, 5903 }, // VNC
            ServiceType.TeamViewer => new List<int> { 5938 },  // Teamviewer
            ServiceType.BigFixRemote => new List<int> { 888 },  // BigFix Remote
            ServiceType.Anydesk => new List<int> { 7070 },  // AnyDesk
            ServiceType.RustdeskServer => new List<int> { 5900 },  // Rustdesk Server
            ServiceType.RustdeskClient => new List<int> { 21118}, // Rustdesk Remote

            // ??? Datenbanken
            ServiceType.MSSQLServer => new List<int> { 1433 }, // Microsoft SQL Server
            ServiceType.PostgreSQL => new List<int> { 5432 }, // PostgreSQL
            ServiceType.MongoDB => new List<int> { 27017 }, // MongoDB
            ServiceType.MariaDB => new List<int> { 3306 }, // MariaDB
            ServiceType.MySQL => new List<int> { 3306 }, // MySQL
            ServiceType.OracleDB => new List<int> { 1521 }, // Oracle DB
            ServiceType.InfluxDB2 => new List<int> { 8086},
            

            // ?? Industrieprotokolle (OT, Automatisierung)
            ServiceType.OPCUA => new List<int> { 4840 }, // OPC UA
            ServiceType.ModBus => new List<int> { 502 }, // ModBus TCP

            // ?? SPS / Industrielle Steuerungen
            ServiceType.S7 => new List<int> { 102, 1020 }, // Siemens S7 ISO-on-TCP

            _ => new List<int>()
        };

    }


    private string GetServiceGroup(ServiceType serviceType)
    {
        return serviceType switch
        {
            // Netzwerk-Dienste
            ServiceType.WebServices or ServiceType.DNS_TCP or ServiceType.DNS_UDP or ServiceType.DHCP or ServiceType.SSH or ServiceType.FTP
                => "🌍 Netzwerk-Dienste",

            // Remote-Desktop & Fernwartung
            ServiceType.RDP or ServiceType.UltraVNC or ServiceType.BigFixRemote or ServiceType.TeamViewer or ServiceType.Anydesk or ServiceType.RustdeskServer or ServiceType.RustdeskClient
                => "🖥️ Remote-Desktop & Fernwartung",

            // Datenbanken
            ServiceType.MSSQLServer or ServiceType.PostgreSQL or ServiceType.MariaDB or ServiceType.MySQL or ServiceType.OracleDB
                => "🗄️ SQL-Datenbanken",

            ServiceType.MongoDB or ServiceType.InfluxDB2
                => "📦 NoSQL-Datenbanken",

            // Industrieprotokolle
            ServiceType.OPCUA or ServiceType.ModBus or ServiceType.S7
                => "🏭 Industrieprotokolle",

            _ => "❓ Sonstige"
        };
    }


    public string GetDetectionPackageString(ServiceType serviceType)
    {
        byte[] packet = GetDetectionPacket(serviceType);

        if (packet == null || packet.Length == 0)
        {
            return string.Empty;
        }

        // Konvertiere jedes Byte in einen 2-stelligen Hex-Wert und verbinde sie mit Kommas
        return string.Join(", ", packet.Select(b => b.ToString("X2")));
    }


    public static byte[] GetDetectionPacket(ServiceType service)
    {
        return service switch
        {
            // ?? Netzwerk-Dienste

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





            // ??? Remote-Desktop & Fernwartung

            ServiceType.RDP => new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 },
            ServiceType.UltraVNC => new byte[] { 0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33 },
            ServiceType.BigFixRemote => new byte[] { 0x14, 0x2B, 0xB4, 0x91, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },

            ServiceType.RustdeskServer => new byte[] { 0x52, 0x44, 0x50 },

            ServiceType.RustdeskClient => new byte[] 
            {
                0x59, 0x01,                                                                 // Magic Number / ID
                0x3A, 0x54,                                                                 // Paketlänge (wahrscheinlich 84 Bytes)
                0x0A, 0x0C,                                                                 // Länge der folgenden IP-Adresse (12 Bytes)
                0x31, 0x30, 0x2E, 0x32, 0x34, 0x32, 0x2E, 0x37, 0x32, 0x2E, 0x32, 0x39,     // IP-Adresse (ASCII) → "10.242.72.29"
                0x22, 0x09,                                                                 // Länge der Client-ID (9 Bytes)
                0x32, 0x32, 0x36, 0x37, 0x36, 0x35, 0x38, 0x36, 0x31,                       // Client-ID → "226765861"
                0x2A, 0x06,                                                                 // Länge des Client-Keys (6 Bytes)
                0x66, 0x31, 0x33, 0x38, 0x38, 0x37, 0x32,                                   // Public Key (ASCII, evtl. Base64 kodiert)
                0x14, 0x48, 0x02,                                                           // Unbekannte Flags/Einstellungen
                0x52, 0x10,                                                                 // Versionsstring / Protokoll
                0x08, 0x01, 0x10, 0x01, 0x18, 0x01, 0x28, 0x01, 0x30, 0x01,                 // Verbindungsoptionen (z. B. Encryption, P2P)
                0x3A, 0x04, 0x10, 0x01, 0x18, 0x01,                                         // Verschlüsselungsparameter
                0x50, 0xFA, 0x8E, 0xF4, 0xBD, 0xDD, 0x8F, 0x88, 0xF0, 0x9F, 0x01,           // Wahrscheinlich eine Signatur oder ein Hash
                0x5A, 0x05, 0x31, 0x2E, 0x33, 0x2E, 0x37,                                   // RustDesk-Version "1.3.7"
                0x62, 0x00,                                                                 // Unbekannt (möglicherweise Terminator/Trennzeichen)
                0x6A, 0x07, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73,                       // Plattform (Windows)
                0x08,                                                                       // Typ des Pakets (Möglicherweise ACK oder Keep-Alive)
                0x2A,                                                                       // Möglicherweise ein Status-Code oder eine ID
                0x00                                                                        // Terminierung / Ende des Pakets
            },

            ////Teamviewer 11-15
            ServiceType.TeamViewer => new byte[]
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




            // ??? Datenbanken

            //ServiceType.MSSQLServer => new byte[]
            // {
            //    0x12, 0x01, 0x00, 0x66, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x06, 0x01, 0x00, 0x2a,
            //    0x00, 0x01, 0x02, 0x00, 0x2b, 0x00, 0x09, 0x03, 0x00, 0x34, 0x00, 0x04, 0x04, 0x00, 0x38, 0x00,
            //    0x01, 0x05, 0x00, 0x39, 0x00, 0x24, 0x06, 0x00, 0x5d, 0x00, 0x01, 0xff, 0x03, 0x0f, 0x5a, 0xfc,
            //    0x01, 0x00, 0x00, 0x6e, 0x65, 0x78, 0x65, 0x6e, 0x73, 0x6f, 0x73, 0x00, 0x00, 0x00, 0x2a, 0x60,
            //    0x00, 0xe9, 0xd5, 0x1f, 0xc3, 0x85, 0xa4, 0x0d, 0x46, 0x8b, 0xd1, 0x68, 0x48, 0x52, 0x80, 0x1d,
            //    0x28, 0xe2, 0xed, 0xe7, 0xba, 0xed, 0x5a, 0xaf, 0x49, 0xad, 0x3e, 0xb5, 0x19, 0xba, 0x6c, 0xcc,
            //    0xc6, 0x02, 0x00, 0x00, 0x00, 0x01
            // },
            ServiceType.MSSQLServer => new byte[]
            {
                0x12, 0x01, 0x00, 0x66, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x06, 0x01, 0x00, 0x2a,
                0x00, 0x01, 0x02, 0x00, 0x2b, 0x00, 0x09, 0x03, 0x00, 0x34, 0x00, 0x04, 0x04, 0x00, 0x38, 0x00,
                0x01, 0x05, 0x00, 0x39, 0x00, 0x24, 0x06, 0x00, 0x5d, 0x00, 0x01, 0xff, 0x03, 0x0f, 0x5a, 0xfc,
                0x01, 0x00, 0x00, 0x6e, 0x65, 0x78, 0x65, 0x6e, 0x73, 0x6f, 0x73, 0x00, 0x00, 0x00, 0x65, 0x00,
                0x00, 0xf2, 0x82, 0x2a, 0x72, 0x26, 0x01, 0x5c, 0x4b, 0xb8, 0x8d, 0xd4, 0x59, 0x35, 0xb5, 0x28,
                0xe7, 0xc3, 0xa9, 0x3e, 0x17, 0xbc, 0x75, 0xa4, 0x4a, 0x8e, 0x94, 0x7e, 0xfd, 0xcf, 0x33, 0x44,
                0x86, 0x02, 0x00, 0x00, 0x00, 0x01 
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
            //ServiceType.PostgreSQL => new byte[]
            //{
            //    0xC3, 0xA4, 0x15, 0x38, 0x68, 0x84, 0xA9, 0x3C,
            //    0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xFA, 0xF0,
            //    0xE5, 0xD7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4,
            //    0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02
            //},
            ServiceType.PostgreSQL => new byte[]
            {
                0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F
            },

            ServiceType.MongoDB => new byte[]
           {
                0x4C, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x07, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6D, 0x69, 0x6E, 0x2E, 0x24, 0x63, 0x6D, 0x64, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x25, 0x01, 0x00, 0x00, 0x10, 0x69, 0x73, 0x6D, 0x61,
                0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x4F,
                0x6B, 0x00, 0x01, 0x03, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x00, 0xE2, 0x00, 0x00, 0x00, 0x03,
                0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x1F, 0x00, 0x00, 0x00,
                0x02, 0x6E, 0x61, 0x6D, 0x65, 0x00, 0x10, 0x00, 0x00, 0x00, 0x4D, 0x6F, 0x6E, 0x67, 0x6F, 0x44,
                0x42, 0x20, 0x43, 0x6F, 0x6D, 0x70, 0x61, 0x73, 0x73, 0x00, 0x00, 0x03, 0x64, 0x72, 0x69, 0x76,
                0x65, 0x72, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x02, 0x6E, 0x61, 0x6D, 0x65, 0x00, 0x07, 0x00, 0x00,
                0x00, 0x6E, 0x6F, 0x64, 0x65, 0x6A, 0x73, 0x00, 0x02, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E,
                0x00, 0x07, 0x00, 0x00, 0x00, 0x36, 0x2E, 0x31, 0x32, 0x2E, 0x30, 0x00, 0x00, 0x02, 0x70, 0x6C,
                0x61, 0x74, 0x66, 0x6F, 0x72, 0x6D, 0x00, 0x15, 0x00, 0x00, 0x00, 0x4E, 0x6F, 0x64, 0x65, 0x2E,
                0x6A, 0x73, 0x20, 0x76, 0x32, 0x30, 0x2E, 0x31, 0x38, 0x2E, 0x31, 0x2C, 0x20, 0x4C, 0x45, 0x00,
                0x03, 0x6F, 0x73, 0x00, 0x58, 0x00, 0x00, 0x00, 0x02, 0x6E, 0x61, 0x6D, 0x65, 0x00, 0x06, 0x00,
                0x00, 0x00, 0x77, 0x69, 0x6E, 0x33, 0x32, 0x00, 0x02, 0x61, 0x72, 0x63, 0x68, 0x69, 0x74, 0x65,
                0x63, 0x74, 0x75, 0x72, 0x65, 0x00, 0x04, 0x00, 0x00, 0x00, 0x78, 0x36, 0x34, 0x00, 0x02, 0x76,
                0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x31, 0x30, 0x2E, 0x30, 0x2E,
                0x31, 0x39, 0x30, 0x34, 0x34, 0x00, 0x02, 0x74, 0x79, 0x70, 0x65, 0x00, 0x0B, 0x00, 0x00, 0x00,
                0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x5F, 0x4E, 0x54, 0x00, 0x00, 0x00, 0x04, 0x63, 0x6F,
                0x6D, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x11, 0x00, 0x00, 0x00, 0x02, 0x30,
                0x00, 0x05, 0x00, 0x00, 0x00, 0x6E, 0x6F, 0x6E, 0x65, 0x00, 0x00, 0x00
           },


            ServiceType.MariaDB => new byte[] 
            {
                0xC3, 0xBC, 0x0C, 0xEA, 0x1E, 0xF7, 0x13, 0x5D,
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

            ServiceType.OracleDB => new byte[]
           {
                0xC3, 0xC3, 0x05, 0xF1, 0xF2, 0x3C, 0x83, 0x34,
                0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xFA, 0xF0,
                0xE5, 0xD7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4,
                0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02
           },

            ServiceType.InfluxDB2 => new byte[]
           {
                0x50, 0x4F, 0x53, 0x54, 0x20, 0x2F, 0x61, 0x70, 0x69, 0x2F, 0x76, 0x32, 0x2F, 0x73, 0x69, 0x67,
                0x6E, 0x69, 0x6E, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x0D, 0x0A, 0x41, 0x75,
                0x74, 0x68, 0x6F, 0x72, 0x69, 0x7A, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x42, 0x61, 0x73,
                0x69, 0x63, 0x20, 0x55, 0x47, 0x6C, 0x75, 0x61, 0x33, 0x6B, 0x36, 0x4D, 0x51, 0x3D, 0x3D, 0x0D,
                0x0A, 0x55, 0x73, 0x65, 0x72, 0x2D, 0x41, 0x67, 0x65, 0x6E, 0x74, 0x3A, 0x20, 0x69, 0x6E, 0x66,
                0x6C, 0x75, 0x78, 0x64, 0x62, 0x2D, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x2D, 0x6A, 0x61, 0x76,
                0x61, 0x2F, 0x37, 0x2E, 0x31, 0x2E, 0x30, 0x0D, 0x0A, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2D,
                0x45, 0x6E, 0x63, 0x6F, 0x64, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0x69, 0x64, 0x65, 0x6E, 0x74, 0x69,
                0x74, 0x79, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2D, 0x4C, 0x65, 0x6E, 0x67,
                0x74, 0x68, 0x3A, 0x20, 0x31, 0x36, 0x0D, 0x0A, 0x48, 0x6F, 0x73, 0x74, 0x3A, 0x20, 0x31, 0x39,
                0x32, 0x2E, 0x31, 0x36, 0x38, 0x2E, 0x31, 0x37, 0x38, 0x2E, 0x35, 0x32, 0x3A, 0x38, 0x30, 0x38,
                0x36, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x4B,
                0x65, 0x65, 0x70, 0x2D, 0x41, 0x6C, 0x69, 0x76, 0x65, 0x0D, 0x0A, 0x0D, 0x0A, 0x61, 0x70, 0x70,
                0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x6A, 0x73, 0x6F, 0x6E
           },




            // ?? Industrieprotokolle (OT, Automatisierung)
            //ServiceType.OPCUA => new byte[] { 0x48, 0x45, 0x4c, 0x4c, 0x4f },
            ServiceType.OPCUA => new byte[] 
            {
                0x48, 0x45, 0x4C, 0x46, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
                0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00,
                0x6F, 0x70, 0x63, 0x2E, 0x74, 0x63, 0x70, 0x3A, 0x2F, 0x2F, 0x31, 0x37, 0x33, 0x2E, 0x31, 0x38,
                0x33, 0x2E, 0x31, 0x34, 0x37, 0x2E, 0x31, 0x30, 0x33, 0x3A, 0x34, 0x38, 0x34, 0x30, 0x2F

            },

            ServiceType.ModBus => new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 },



            // ?? SPS / Industrielle Steuerungen

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
