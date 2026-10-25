using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Threading.Tasks;
using System.Threading;
using System.Text;
using MyNetworkMonitor;
using MyNetworkMonitor.Core.Scanning.ServiceScans;
using System.Runtime.ConstrainedExecution;
using static MyNetworkMonitor.ServiceScanData;
using System.Data;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Collections.Concurrent;
using System.Reflection.Metadata;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Xml.Serialization;
using System.Text.RegularExpressions;
using System.Collections;
using System.Collections.Specialized;


/// <summary>
/// The result of probing one port for a service.
/// </summary>
public enum PortStatus
{
    /// <summary>The connection was established, but the answer did not prove the service.</summary>
    Open,

    /// <summary>The connection attempt timed out, possibly because of a firewall.</summary>
    Filtered,

    /// <summary>No answer after all attempts.</summary>
    NoResponse,

    /// <summary>The target refused the connection: no service listens on the port.</summary>
    Closed,

    /// <summary>The answer matches the protocol: the service runs on the port.</summary>
    IsRunning,

    /// <summary>An answer came back that matches no known pattern.</summary>
    UnknownResponse,

    /// <summary>The probe failed with an error, such as a broken connection or a TLS error.</summary>
    Error
}



/// <summary>
/// The services the service scan can detect.
/// </summary>
public enum ServiceType
{
    // Network services
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

    // Databases
    MSSQLServer,
    PostgreSQL,    
    MariaDB,
    MySQL,
    OracleDB,
    // NoSQL databases
    MongoDB,
    InfluxDB2,

    // Industrial protocols
    OPCUA,
    ModBus,
    S7,
    BacNet,
    Wago,
    SecsGem
}



/// <summary>
/// Detects services on the targets with protocol-specific probes and manages the service
/// settings stored in services.xml.
/// </summary>
public class ScanningMethod_Services
{
    /// <summary>
    /// Creates the service scan and loads the service settings.
    /// </summary>
    /// <param name="ServiceXMLPath">The path of the stored service settings; a missing file leaves the defaults.</param>
    public ScanningMethod_Services(string ServiceXMLPath)
    {
        SetServicePorts(ServiceXMLPath);
        _serviceXMLPath = ServiceXMLPath;
    }

    private int current = 0;
    private int responded = 0;
    private int total = 0;

    private CancellationTokenSource _cts = new CancellationTokenSource();

    /// <summary>
    /// Cancels the running scan and reports <see cref="ScanStatus.stopped"/>.
    /// </summary>
    public void StopScan()
    {
        if (_cts != null && !_cts.IsCancellationRequested)
        {
            _cts.Cancel();
            // Do NOT dispose and replace the source here: the loops read _cts through the
            // field. A fresh source at this point would report "not cancelled" to them and
            // the run would continue instead of ending. StartNewScan resets it for the next run.
        }
        scanStatus = ScanStatus.stopped;
        ScanStatusUpdated?.Invoke(scanStatus);
        ProgressUpdated?.Invoke(current, responded, total); // Resets the progress display.
    }

    ScanStatus scanStatus = ScanStatus.running;

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

        // Reset the counters.
        current = 0;
        responded = 0;
        total = 0;
    }




    private string _serviceXMLPath = string.Empty;

    /// <summary>Time limit per port in the full scan, in milliseconds.</summary>
    private const int Timeout = 2000;

    /// <summary>Attempts per port in the full scan.</summary>
    private const int RetryCount = 3;

    /// <summary>
    /// Ports checked in parallel by the search over all 65536 ports; far more than in the full
    /// scan, because there one target gets many services and here one service gets very many
    /// ports.
    /// </summary>
    private const int MaxParallelPortSearch = 200;

    /// <summary>Raised once per target with findings, after the whole scan.</summary>
    public event Action<IPToScan> ServiceIPScanFinished;
  
    /// <summary>Raised when the scan is stopped.</summary>
    public event Action<ScanStatus> ScanStatusUpdated;

    /// <summary>Reports progress of the full scan as (checks done, responded, total checks).</summary>
    public event Action<int, int, int> ProgressUpdated;

    /// <summary>Raised when the full scan has finished.</summary>
    public event Action ServiceScanFinished;

    /// <summary>Reports progress of the port search as (ports started, ports with the service, 65536).</summary>
    public event Action<int, int, int> FindServicePortProgressUpdated;

    /// <summary>Raised when the port search has finished.</summary>
    public event Action<IPToScan> FindServicePortFinished;

    /// <summary>
    /// Checks the selected services on the selected targets.
    /// <para>
    /// The sequence itself is in <see cref="ServiceScanRunner"/>: one service after the other,
    /// all targets of a service in parallel. This method connects it to the user interface.
    /// </para>
    /// <para>
    /// <c>ProgressUpdated</c> counts checks, not targets, that is services times targets. That is
    /// how the runner counts, and only this way does the display show that a slow service is
    /// currently running.
    /// </para>
    /// </summary>
    /// <param name="IPsToScan">The targets.</param>
    /// <param name="services">The services to check.</param>
    /// <param name="extraPorts">Additional ports per service; <see langword="null"/> for none.</param>
    public async Task ScanIPsAsync(List<IPToScan> IPsToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts = null)
    {
        StartNewScan();
        scanStatus = ScanStatus.running;

        ProgressUpdated?.Invoke(current, responded, total);

        // Collect what the individual services report per target and report each target once
        // at the end: the user interface expects one target with all its services, not 24
        // partial reports.
        Dictionary<string, IPToScan> byAddress = new();
        foreach (IPToScan target in IPsToScan)
        {
            if (!string.IsNullOrEmpty(target.IPorHostname))
                byAddress[target.IPorHostname] = target;
        }

        if (byAddress.Count == 0)
        {
            ServiceScanFinished?.Invoke();
            return;
        }

        ServiceScanRunner runner = new()
        {
            Context = new ProbeContext { TimeoutMs = Timeout, RetryCount = RetryCount }
        };

        HashSet<string> withFindings = new();

        void OnProgress(ServiceScanProgress p)
        {
            current = p.Current;
            responded = p.Responded;
            total = p.Total;

            ProgressUpdated?.Invoke(p.Current, p.Responded, p.Total);
        }

        void OnFound(ServiceFinding finding)
        {
            if (!byAddress.TryGetValue(finding.Address, out IPToScan? target)) return;

            lock (target.Services.Services)
            {
                target.Services.Services.Add(finding.Result);
            }

            lock (withFindings) withFindings.Add(finding.Address);
        }

        runner.ProgressUpdated += OnProgress;
        runner.Found += OnFound;

        try
        {
            await runner.RunAsync(
                [.. byAddress.Keys],
                services,
                extraPorts ?? new Dictionary<ServiceType, List<int>>(),
                _cts.Token);
        }
        catch (OperationCanceledException)
        {
            // A cancellation is an intended end, not a failure: what was found until then is
            // still reported.
        }
        finally
        {
            runner.ProgressUpdated -= OnProgress;
            runner.Found -= OnFound;
        }

        foreach (IPToScan target in IPsToScan)
        {
            // Report every target with at least one result from a probe: "checked, nothing open"
            // is a result and belongs in the inventory, otherwise a device would stay at "never
            // checked" for good. Targets without any result were not reached at all.
            if (!withFindings.Contains(target.IPorHostname ?? string.Empty)) continue;

            target.UsedScanMethod = ScanMethod.Services;
            ServiceIPScanFinished?.Invoke(target);
        }

        ServiceScanFinished?.Invoke();
    }


    /// <summary>
    /// Searches for a single service on <b>all</b> 65536 ports of a target.
    /// <para>
    /// The probe is the same as in the full scan, with tighter settings: one second of
    /// patience and one attempt per port; with 65536 ports every additional retry adds
    /// noticeable waiting time.
    /// </para>
    /// <para>
    /// Only what the probe reports as <c>IsRunning</c> is taken, that is an answer that matches
    /// the protocol. An open port alone is no finding here: the search is for a specific service,
    /// and that is not found by something answering.
    /// </para>
    /// <para>
    /// The run covers all ports and does not stop at the first hit: a service can listen on
    /// several ports, and a search over all ports is meant to show them all.
    /// </para>
    /// </summary>
    /// <param name="ipToScan">The target.</param>
    /// <param name="service">The service to search for.</param>
    /// <returns>The target with a service result that lists the ports found.</returns>
    public async Task<IPToScan> FindServicePortAsync(IPToScan ipToScan, ServiceType service)
    {
        StartNewScan();

        current = 0;
        responded = 0;
        total = 65536;

        ipToScan.UsedScanMethod = ScanMethod.Services;

        ServiceResult serviceResult = new ServiceResult { Service = service };
        ipToScan.Services.Services.Add(serviceResult);

        if (!ServiceProbes.Has(service))
        {
            // No probe for this service: nothing to search, but the event must still be
            // raised, otherwise the user interface keeps waiting.
            FindServicePortFinished?.Invoke(ipToScan);
            return ipToScan;
        }

        IServiceProbe probe = ServiceProbes.Create(service);
        ProbeContext context = new() { TimeoutMs = 1000, RetryCount = 1 };

        using SemaphoreSlim slots = new(MaxParallelPortSearch);

        List<Task> tasks = new List<Task>();

        foreach (int port in Enumerable.Range(0, 65536))
        {
            if (_cts.Token.IsCancellationRequested) break;

            // Report the counter, not the port number: over all 65536 ports both look almost the
            // same, but the meaning is "how many ports so far", which differs on a cancellation
            // or for a section of the port list.
            int currentValue = Interlocked.Increment(ref current);
            FindServicePortProgressUpdated?.Invoke(currentValue, Volatile.Read(ref responded), total);

            try
            {
                await slots.WaitAsync(_cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    PortResult portResult = await probe.ProbeAsync(context, ipToScan.IPorHostname, port, _cts.Token);

                    if (portResult.Status == PortStatus.IsRunning)
                    {
                        int respondedValue = Interlocked.Increment(ref responded);
                        FindServicePortProgressUpdated?.Invoke(Volatile.Read(ref current), respondedValue, total);

                        lock (serviceResult.Ports)
                        {
                            serviceResult.Ports.Add(portResult);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    // A cancellation is no failure of this port.
                }
                catch (Exception)
                {
                    // A single port that cannot be checked must not end the run over the
                    // remaining 65535.
                }
                finally
                {
                    slots.Release();
                }
            }));
        }

        try
        {
            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            // A cancellation is no failure, see above.
        }
        finally
        {
            FindServicePortFinished?.Invoke(ipToScan);
        }

        return ipToScan;
    }





    private DataTable _dt_Servives = new DataTable();

    /// <summary>
    /// The service settings: one row per service with selection, ports, hello packet, expected
    /// answer, group and the switch for active inquiries.
    /// </summary>
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
        _dt_Servives.Columns.Add("ServiceGroup", typeof(string)); // Grouping column

    // Only for services whose information needs a request that changes the state of the
    // remote side; for SECS/GEM that is S1F13. The default is off and stays off: it is to be
    // switched on only by someone who knows the equipment in the network.
    _dt_Servives.Columns.Add("ActiveInquiry", typeof(bool));


        foreach (ServiceType serviceType in Enum.GetValues(typeof(ServiceType)))
        {
            DataRow row = _dt_Servives.NewRow();
            row["toScan"] = false;
            row["Service"] = serviceType.ToString();
            row["Ports"] = string.Join(", ", GetDefaultServicePorts(serviceType));
            row["HelloBytePackage"] = GetDetectionPackageString(serviceType);  // Hex text of the hello packet
            row["ResponsedBytePackagePart"] = "";
            row["ResponsedContainsString"] = "";
            row["ServiceGroup"] = GetServiceGroup(serviceType);
        row["ActiveInquiry"] = false;

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
                        string service = existingRow["Service"].ToString() ?? string.Empty;

                        // Compare ports.
                        if (existingRow["Ports"].ToString() != tempRow["Ports"].ToString())
                        {
                            if (IsSupersededDefault(service, "Ports", tempRow["Ports"].ToString()))
                            {
                                Console.WriteLine(
                                    $"Ports für {service}: veraltete Vorgabe verworfen, es gilt {existingRow["Ports"]}");
                            }
                            else
                            {
                                existingRow["Ports"] = tempRow["Ports"];
                                Console.WriteLine($"Ports für {service} aktualisiert: {existingRow["Ports"]}");
                            }
                        }

                        // Compare HelloBytePackage.
                        if (existingRow["HelloBytePackage"].ToString() != tempRow["HelloBytePackage"].ToString())
                        {
                            if (!IsSupersededDefault(service, "HelloBytePackage", tempRow["HelloBytePackage"].ToString()))
                            {
                                existingRow["HelloBytePackage"] = tempRow["HelloBytePackage"];
                            }
                        }

                        // Compare ResponsedBytePackagePart.
                        if (existingRow["ResponsedBytePackagePart"].ToString() != tempRow["ResponsedBytePackagePart"].ToString())
                        {
                            existingRow["ResponsedBytePackagePart"] = tempRow["ResponsedBytePackagePart"];
                        }

                        // Compare ResponsedContainsString.
                        if (existingRow["ResponsedContainsString"].ToString() != tempRow["ResponsedContainsString"].ToString())
                        {
                            existingRow["ResponsedContainsString"] = tempRow["ResponsedContainsString"];
                        }

                        // Take the selection.
                        existingRow["toScan"] = tempRow["toScan"];

                        // The active inquiry, if the file has the column. Files without it keep
                        // the default "off".
                        if (tempTable.Columns.Contains("ActiveInquiry") && tempRow["ActiveInquiry"] is bool wanted)
                        {
                            existingRow["ActiveInquiry"] = wanted;
                        }
                    }
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Defaults that were shipped once and are wrong by now.
    /// <para>
    /// The stored XML takes precedence over the code, by design, so that ports and packets can
    /// be adjusted without rebuilding the application. The downside: a file, once created,
    /// freezes the default of that time, and a later correction in the code never reaches that
    /// computer without any visible reason.
    /// </para>
    /// <para>
    /// Hence this list: if the file contains <em>exactly</em> an old default value, the current
    /// default applies. Anything else is a deliberate adjustment and stays untouched, so the
    /// purpose of the file is preserved.
    /// </para>
    /// </summary>
    /// <remarks>
    /// Matching uses a checksum, not the value itself. An old client packet carried an internal
    /// address, a device ID and a user name as ASCII bytes; in plain text here, exactly that would
    /// be in the public project again, only disguised as hex and therefore easier to overlook. The
    /// checksum is enough: it recognises the old value without revealing it.
    /// </remarks>
    private static readonly (string Service, string Column, string Sha256)[] SupersededDefaults =
    [
        // Default before 6.0.0.5: the RustDesk server was on 5900, the same port as UltraVNC, so
        // every VNC computer also counted as a RustDesk server. Without this entry an existing
        // services.xml keeps the old port.
        ("RustdeskServer", "Ports", "B0A1CAFD46C582F82B4CD19B94D6E1DCE4305E3536EFB5949E3FC1193496D802"),

        // Default before 7.1: the three ASCII fields of the client packet came from a capture and
        // named a real computer. The code uses placeholders; without this entry an existing file
        // keeps sending the old values.
        ("RustdeskClient", "HelloBytePackage", "D58106E650361454C362FD3FA4832D840E08493C4C36C50620243A8EB417FA46"),

        // Defaults before 7.3.0.17: packets taken from network captures that named a real SQL Server instance, the
        // program and operating system of the capturing computer, and the address of a foreign OPC UA server; the code
        // uses neutral packets. See docs/FEHLERGEDAECHTNIS.md, No. 14.
        ("MSSQLServer", "HelloBytePackage", "884815CC8494B604E9E916384D941B5B55684CB125E646F7D246B31D8BFFF1DC"),
        ("MongoDB", "HelloBytePackage", "90DCFBF16467625E757858845C4E5AD45E0DF8DAFF0BCED97223C6F5882DF545"),
        ("OPCUA", "HelloBytePackage", "B4A94C948BDCFEF7219FC5276AC78AC44B2499A057923F323DB28ADE194BBB97")
    ];

    /// <summary>
    /// Whether the stored value matches exactly one superseded default.
    /// <para>
    /// The checksum of the value is compared, ignoring white space and letter case: the file
    /// may be edited by hand, and that must not defeat the check.
    /// </para>
    /// </summary>
    private static bool IsSupersededDefault(string service, string column, string? stored)
    {
        if (string.IsNullOrWhiteSpace(stored)) return false;

        string digest = Fingerprint(stored);

        return SupersededDefaults.Any(d =>
            string.Equals(d.Service, service, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(d.Column, column, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(d.Sha256, digest, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>SHA-256 checksum of a value, insensitive to white space and letter case.</summary>
    private static string Fingerprint(string value)
    {
        string normalised = new(value.Where(c => !char.IsWhiteSpace(c))
                                     .Select(char.ToUpperInvariant)
                                     .ToArray());

        byte[] hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(normalised));

        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// Normalises the list columns and saves the service settings with schema to the path given
    /// at construction. Errors are written to the console.
    /// </summary>
    public void SaveServiceSettingsToXML()
    {
        try
        {
            foreach (DataRow row in _dt_Servives.Rows)
            {
                // Format ports: "53,46" becomes "53, 46"
                if (row["Ports"] != DBNull.Value)
                {
                    row["Ports"] = string.Join(", ", row["Ports"].ToString().Split(',').Select(p => p.Trim()));
                }

                // Format HelloBytePackage.
                if (row["HelloBytePackage"] != DBNull.Value)
                {
                    row["HelloBytePackage"] = string.Join(", ", row["HelloBytePackage"].ToString().Split(',').Select(p => p.Trim()));
                }

                // Format ResponsedBytePackagePart.
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







    /// <summary>
    /// The default ports of a service. They are defined with its probe under
    /// Scanning/ServiceScans, one file per service with ports, hello packet and answer check
    /// together. This is the access point for the service settings and the user interface.
    /// </summary>
    /// <param name="service">The service.</param>
    /// <returns>The default ports; empty if there is no probe for the service.</returns>
    public static List<int> GetDefaultServicePorts(ServiceType service) =>
        ServiceProbes.Has(service)
            ? [.. ServiceProbes.For(service).DefaultPorts]
            : [];


    private string GetServiceGroup(ServiceType serviceType)
    {
        return serviceType switch
        {
            // Network services
            ServiceType.WebServices or ServiceType.DNS_TCP or ServiceType.DNS_UDP or ServiceType.DHCP or ServiceType.SSH or ServiceType.FTP
                => "🌍 Netzwerk-Dienste",

            // Remote desktop and remote maintenance
            ServiceType.RDP or ServiceType.UltraVNC or ServiceType.BigFixRemote or ServiceType.TeamViewer or ServiceType.Anydesk or ServiceType.RustdeskServer or ServiceType.RustdeskClient
                => "🖥️ Remote-Desktop & Fernwartung",

            // Databases
            ServiceType.MSSQLServer or ServiceType.PostgreSQL or ServiceType.MariaDB or ServiceType.MySQL or ServiceType.OracleDB
                => "🗄️ SQL-Datenbanken",

            ServiceType.MongoDB or ServiceType.InfluxDB2
                => "📦 NoSQL-Datenbanken",

            // Industrial protocols
            ServiceType.OPCUA or ServiceType.ModBus or ServiceType.S7 or ServiceType.BacNet or ServiceType.Wago or ServiceType.SecsGem
                => "🏭 Industrieprotokolle",

            _ => "❓ Sonstige"
        };
    }


    /// <summary>
    /// The hello packet as hex text for the "HelloBytePackage" column of the service settings.
    /// The packets themselves are defined with the probes under Scanning/ServiceScans, one file
    /// per service.
    /// </summary>
    /// <param name="serviceType">The service.</param>
    /// <returns>The bytes as two-digit hex values separated by ", "; empty if there is no packet.</returns>
    public string GetDetectionPackageString(ServiceType serviceType)
    {
        byte[] packet = ServiceProbes.Has(serviceType)
            ? ServiceProbes.For(serviceType).Hello
            : [];

        if (packet == null || packet.Length == 0)
        {
            return string.Empty;
        }

        // Convert each byte into a two-digit hex value and join them with commas.
        return string.Join(", ", packet.Select(b => b.ToString("X2")));
    }

}
