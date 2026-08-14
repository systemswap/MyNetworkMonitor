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
    S7,
    BacNet,
    Wago
}



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

    private CancellationTokenSource _cts = new CancellationTokenSource();

    public void StopScan()
    {
        if (_cts != null && !_cts.IsCancellationRequested)
        {
            _cts.Cancel(); // 🔹 Scan abbrechen
            // Hier NICHT aufraeumen und ersetzen: die Schleifen lesen _cts ueber
            // das Feld. Ein frisches CTS an dieser Stelle meldet ihnen wieder
            // "nicht abgebrochen", und der Lauf geht weiter, statt zu enden.
            // Das Zuruecksetzen erledigt StartNewScan beim naechsten Lauf.
        }
        scanStatus = ScanStatus.stopped;
        ScanStatusUpdated?.Invoke(scanStatus);
        ProgressUpdated?.Invoke(current, responded, total); // 🔹 UI auf 0 setzen
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

        // 🔹 Zähler zurücksetzen
        current = 0;
        responded = 0;
        total = 0;
    }




    private string _serviceXMLPath = string.Empty;

    /// <summary>Zeitlimit je Port im grossen Lauf, in Millisekunden.</summary>
    private const int Timeout = 2000;

    /// <summary>Versuche je Port im grossen Lauf.</summary>
    private const int RetryCount = 3;

    /// <summary>
    /// Ports nebeneinander bei der Suche ueber alle 65536 - deutlich mehr als
    /// im grossen Lauf, weil dort ein Ziel viele Dienste bekommt und hier ein
    /// Dienst sehr viele Ports.
    /// </summary>
    private const int MaxParallelPortSearch = 200;

    public event Action<IPToScan> ServiceIPScanFinished;
  
    public event Action<ScanStatus> ScanStatusUpdated;
    public event Action<int, int, int> ProgressUpdated;
    public event Action ServiceScanFinished;

    public event Action<int, int, int> FindServicePortProgressUpdated;
    public event Action<IPToScan> FindServicePortFinished;

    /// <summary>
    /// Prueft die gewaehlten Dienste an den gewaehlten Zielen.
    /// <para>
    /// Der Ablauf selbst liegt in <see cref="ServiceScanRunner"/>: ein Dienst
    /// nach dem anderen, innerhalb eines Dienstes alle Ziele nebeneinander.
    /// Hier steht nur noch die Anbindung fuer die beiden Oberflaechen -
    /// Signatur und Ereignisse bleiben unveraendert.
    /// </para>
    /// <para>
    /// Ein Unterschied ist sichtbar: <c>ProgressUpdated</c> zaehlt jetzt
    /// Pruefungen statt Ziele, also Dienst mal Ziel. So zaehlt der Ablauf
    /// ohnehin schon, und nur so laesst sich ablesen, dass gerade ein
    /// langsamer Dienst an der Reihe ist.
    /// </para>
    /// </summary>
    public async Task ScanIPsAsync(List<IPToScan> IPsToScan, List<ServiceType> services, Dictionary<ServiceType, List<int>> extraPorts = null)
    {
        StartNewScan();
        scanStatus = ScanStatus.running;

        ProgressUpdated?.Invoke(current, responded, total);

        // Je Ziel wird gesammelt, was die einzelnen Dienste melden, und erst
        // am Ende einmal gemeldet: die Oberflaechen erwarten ein Ziel mit all
        // seinen Diensten, nicht 24 Teilmeldungen.
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
            // Ein Abbruch ist ein gewolltes Ende und kein Fehlschlag: was bis
            // dahin gefunden wurde, wird trotzdem gemeldet.
        }
        finally
        {
            runner.ProgressUpdated -= OnProgress;
            runner.Found -= OnFound;
        }

        foreach (IPToScan target in IPsToScan)
        {
            // Gemeldet wird jedes gepruefte Ziel, auch ohne Fund: "geprueft,
            // nichts offen" ist ein Ergebnis und gehoert in den Bestand -
            // sonst stuende ein Geraet dauerhaft auf "nie geprueft". Ziele
            // ohne jede Meldung sind dagegen gar nicht erst drangekommen.
            if (!withFindings.Contains(target.IPorHostname ?? string.Empty)) continue;

            target.UsedScanMethod = ScanMethod.Services;
            ServiceIPScanFinished?.Invoke(target);
        }

        ServiceScanFinished?.Invoke();
    }


    /// <summary>
    /// Sucht einen einzelnen Dienst an <b>allen</b> 65536 Ports eines Ziels.
    /// <para>
    /// Gefragt wird mit derselben Sonde wie im grossen Lauf, nur knapper
    /// eingestellt: eine Sekunde Geduld und ein Versuch je Port - bei 65536
    /// Ports faellt jede zusaetzliche Wiederholung als Wartezeit ins Gewicht.
    /// </para>
    /// <para>
    /// Uebernommen wird nur, was die Sonde als <c>IsRunning</c> meldet, also
    /// eine Antwort, die zum Protokoll passt. Ein offener Port allein ist
    /// hier kein Fund - gesucht ist ein bestimmter Dienst, und den findet man
    /// nicht daran, dass irgendetwas antwortet.
    /// </para>
    /// <para>
    /// Der Lauf geht ueber alle Ports durch. Frueher hielt er beim ersten
    /// Treffer an; ein Dienst kann aber auf mehreren Ports sitzen, und genau
    /// die will man sehen, wenn man schon alle Ports absucht.
    /// </para>
    /// </summary>
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
            // Kein Verfahren fuer diesen Dienst - nichts zu suchen, aber das
            // Ereignis muss trotzdem kommen, sonst wartet die Oberflaeche.
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

            // Gemeldet wird der Zaehler, nicht die Portnummer: bei einem Lauf
            // ueber alle 65536 Ports sehen beide fast gleich aus, gemeint ist
            // aber "der wievielte Port" - und das ist bei einem Abbruch oder
            // einem Ausschnitt der Portliste etwas anderes.
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
                    // Abbruch ist kein Fehlschlag dieses Ports.
                }
                catch (Exception)
                {
                    // Ein einzelner Port, der sich nicht pruefen laesst, darf
                    // den Lauf ueber die uebrigen 65535 nicht beenden.
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
            // siehe oben
        }
        finally
        {
            FindServicePortFinished?.Invoke(ipToScan);
        }

        return ipToScan;
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
                        string service = existingRow["Service"].ToString() ?? string.Empty;

                        // Ports vergleichen
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

                        // HelloBytePackage vergleichen
                        if (existingRow["HelloBytePackage"].ToString() != tempRow["HelloBytePackage"].ToString())
                        {
                            if (!IsSupersededDefault(service, "HelloBytePackage", tempRow["HelloBytePackage"].ToString()))
                            {
                                existingRow["HelloBytePackage"] = tempRow["HelloBytePackage"];
                            }
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

    /// <summary>
    /// Vorgaben, die einmal ausgeliefert wurden und inzwischen falsch sind.
    /// <para>
    /// Die gespeicherte XML sticht den Code - so ist sie gedacht, damit sich
    /// Ports und Pakete anpassen lassen, ohne die Anwendung neu zu bauen. Die
    /// Kehrseite: eine Datei, die einmal angelegt wurde, friert die damalige
    /// Vorgabe ein. Eine spaetere Korrektur im Code erreicht diesen Rechner
    /// nie, und niemand sieht, woran es liegt.
    /// </para>
    /// <para>
    /// Darum diese Liste: steht in der Datei <em>genau</em> der alte
    /// Vorgabewert, gilt der neue. Alles, was davon abweicht, ist eine eigene
    /// Anpassung und bleibt unangetastet - der Zweck der Datei bleibt also
    /// erhalten.
    /// </para>
    /// </summary>
    /// <remarks>
    /// Erkannt wird ueber die Pruefsumme und nicht ueber den Wert selbst. Das
    /// alte Client-Paket trug eine interne Adresse, eine Geraetekennung und
    /// einen Benutzernamen als ASCII-Bytes; stuende es hier im Klartext, waere
    /// genau das wieder im oeffentlichen Projekt - nur als Hex getarnt und
    /// damit umso leichter zu uebersehen. Die Pruefsumme genuegt: sie erkennt
    /// den alten Wert, gibt ihn aber nicht preis.
    /// </remarks>
    private static readonly (string Service, string Column, string Sha256)[] SupersededDefaults =
    [
        // Stand vor 6.0.0.5: der RustDesk-Server lag auf 5900, demselben Port
        // wie UltraVNC. Jeder VNC-Rechner galt dadurch zusaetzlich als
        // RustDesk-Server. Die Korrektur im Code lief bei allen ins Leere, die
        // schon eine services.xml hatten.
        ("RustdeskServer", "Ports", "B0A1CAFD46C582F82B4CD19B94D6E1DCE4305E3536EFB5949E3FC1193496D802"),

        // Stand vor 7.1: die drei ASCII-Felder des Client-Pakets stammten aus
        // einem Mitschnitt und benannten damit einen echten Rechner. Im Code
        // stehen laengst Platzhalter; ohne diesen Eintrag verschickte eine
        // bestehende Datei weiterhin die alten Werte.
        ("RustdeskClient", "HelloBytePackage", "D58106E650361454C362FD3FA4832D840E08493C4C36C50620243A8EB417FA46")
    ];

    /// <summary>
    /// Ob der gespeicherte Wert genau einer ueberholten Vorgabe entspricht.
    /// <para>
    /// Verglichen wird die Pruefsumme des Wertes, ohne Ruecksicht auf
    /// Leerzeichen und Gross-/Kleinschreibung: die Datei wird von Hand
    /// bearbeitet, und daran soll es nicht scheitern.
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

    /// <summary>Pruefsumme eines Wertes, gegen Leerzeichen und Schreibweise unempfindlich.</summary>
    private static string Fingerprint(string value)
    {
        string normalised = new(value.Where(c => !char.IsWhiteSpace(c))
                                     .Select(char.ToUpperInvariant)
                                     .ToArray());

        byte[] hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(normalised));

        return Convert.ToHexString(hash);
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







    /// <summary>
    /// Die Standardports eines Dienstes. Sie stehen bei seiner Sonde unter
    /// Scanning/ServiceScans - je Dienst eine Datei, in der Ports, Hello-Paket
    /// und Antwortpruefung beieinander liegen. Hier steht nur noch der Zugang
    /// fuer die Dienstverwaltung und die beiden Oberflaechen.
    /// </summary>
    public static List<int> GetDefaultServicePorts(ServiceType service) =>
        ServiceProbes.Has(service)
            ? [.. ServiceProbes.For(service).DefaultPorts]
            : [];


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
            ServiceType.OPCUA or ServiceType.ModBus or ServiceType.S7 or ServiceType.BacNet or ServiceType.Wago
                => "🏭 Industrieprotokolle",

            _ => "❓ Sonstige"
        };
    }


    /// <summary>
    /// Das Hello-Paket als Hex-Text fuer die Spalte "HelloBytePackage" der
    /// Dienstverwaltung. Die Pakete selbst liegen bei den Sonden unter
    /// Scanning/ServiceScans - je Dienst eine Datei.
    /// </summary>
    public string GetDetectionPackageString(ServiceType serviceType)
    {
        byte[] packet = ServiceProbes.Has(serviceType)
            ? ServiceProbes.For(serviceType).Hello
            : [];

        if (packet == null || packet.Length == 0)
        {
            return string.Empty;
        }

        // Konvertiere jedes Byte in einen 2-stelligen Hex-Wert und verbinde sie mit Kommas
        return string.Join(", ", packet.Select(b => b.ToString("X2")));
    }

}
