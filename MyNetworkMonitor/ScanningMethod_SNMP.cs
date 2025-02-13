//using System;
//using System.Collections.Generic;
//using System.IO.Pipes;
//using System.Linq;
//using System.Net;
//using System.Net.NetworkInformation;
//using System.Net.Sockets;
//using System.Text;
//using System.Text.RegularExpressions;
//using System.Threading;
//using System.Threading.Tasks;
//using SnmpSharpNet;

//namespace MyNetworkMonitor
//{
//    class ScanningMethod_SNMP
//    {
//        public ScanningMethod_SNMP()
//        {

//        }

//        public class CounterEventArgs : EventArgs
//        {
//            public int Value { get; }

//            public CounterEventArgs(int value)
//            {
//                Value = value;
//            }
//        }

//        public event EventHandler<CounterEventArgs>? SNMP_SendRequest;
//        public event EventHandler<ScanTask_Finished_EventArgs>? SNMP_Task_Finished;
//        public event EventHandler<Method_Finished_EventArgs>? SNMPFinished;

//        int IPs = 0;

//        /// <summary>
//        /// to get the SNMP Infos of the IP
//        /// </summary>
//        /// <param name="IPsToRefresh"></param>
//        /// <returns></returns>
//        public async Task ScanAsync(List<IPToScan> IPsToRefresh)
//        {
//            var tasks = new List<Task>();

//            Parallel.ForEach(IPsToRefresh, ip =>
//            {
//                if (SNMP_SendRequest != null)
//                {
//                    SNMP_SendRequest?.Invoke(this, new CounterEventArgs(++IPs));
//                }

//                var task = SNMPTask(ip);
//                if (task != null) tasks.Add(task);
//            });

//            await Task.WhenAll(tasks.Where(t => t != null));
//            if (SNMPFinished != null)
//            {
//                SNMPFinished(this, new Method_Finished_EventArgs());
//            }
//        }

//        private async Task SNMPTask(IPToScan ipToScan)
//        {
//            if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname)) return;

//            try
//            {
//                if (SNMP_Task_Finished != null)
//                {
//                    // Geben Sie die IP-Adresse des Druckers ein
//                    string printerIp = ipToScan.IPorHostname;
//                    string community = "public"; // Standard-SNMP-Community-String

//                    // SNMP-Session erstellen
//                    SimpleSnmp snmp = new SimpleSnmp(printerIp);//, community);                    
//                    snmp.Timeout = 10000; //Millisekunden

//                    if (!snmp.Valid)
//                    {
//                        //Console.WriteLine("SNMP-Session ist ungültig.");
//                        return;
//                    }

//                    ipToScan.UsedScanMethod = ScanMethod.SNMP;

//                    // OIDs  

//                    string sysName = "1.3.6.1.2.1.1.5.0"; // SNMP-OID für sysName (Hostname) bei Canon: Geräteverwaltung -> Einstellungen Geräte-Information

//                    string sysDescr = "1.3.6.1.2.1.1.1.0"; // bei Canon: Netzwerk -> Einstellungen Computername / Name Arbeitsgruppe
//                    string ptrLocation = "1.3.6.1.2.1.1.6.0";
//                    string prtName = "1.3.6.1.2.1.43.5.1.1.1.1"; // prtGeneralPrinterName: Name des Druckers.
//                    string sysContact = "1.3.6.1.2.1.1.4.0"; // sysContact: Kontaktinformationen des Administrators.


//                    // abfrage mit walk
//                    //string ptrCurrentIP = "1.3.6.1.2.1.4.22.1.2";
//                    //string prtModelDesc = "1.3.6.1.2.1.43.5.1.1.17.1";
//                    //string prtDeviceName = "1.3.6.1.2.1.25.3.2.1.3";



//                    //string ZebraSysName = string.Empty;
//                    //try
//                    //{
//                    //    // Zebra SysNameOid
//                    //    Oid ZebraSysNameOid = new Oid("1.3.6.1.4.1.10642.20.3.5.0");

//                    //    // Erstelle das IPAddress-Objekt
//                    //    IPAddress ip = IPAddress.Parse(printerIp);

//                    //    // Erstelle das UdpTarget-Objekt mit IP-Adresse und Port 161 (Standardport für SNMP)
//                    //    UdpTarget target = new UdpTarget(ip, 161, 2000, 1); // Timeout 2000ms

//                    //    // Erstelle das Pdu-Objekt (PduType.Get für eine GET-Anfrage)
//                    //    Pdu pdu = new Pdu(PduType.Get);
//                    //    pdu.VbList.Add(ZebraSysNameOid);  // Füge die OID der Anfrage hinzu

//                    //    // Erstelle AgentParameters mit dem Community-String und der SNMP-Version
//                    //    AgentParameters parameters = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));

//                    //    // Sende die SNMP-GET-Anfrage und erhalte die Antwort
//                    //    SnmpV2Packet response = (SnmpV2Packet)target.Request(pdu, parameters);

//                    //    if (response.Pdu.ErrorStatus == 0)  // Fehlerstatus 0 bedeutet Erfolg
//                    //    {
//                    //        ZebraSysName = response.Pdu.VbList[0].Value.ToString();
//                    //    }
//                    //}
//                    //catch (Exception)
//                    //{

//                    //    //throw;
//                    //}










//                    // SNMP-Abfrage
//                    Dictionary<Oid, AsnType> result = new Dictionary<Oid, AsnType>();
//                    for (int i = 0; i < 6; i++)
//                    {
//                        result = snmp.Get(SnmpVersion.Ver1, new[] { sysName, sysDescr, ptrLocation });
//                        if (result == null) continue;

//                        if (result.Count >= 1)
//                        {
//                            break;
//                        }
//                    }


//                    //var ZebraNameResult = snmp.Walk(SnmpVersion.Ver1, ZebraSNMP_Name);
//                    //var prtIP = snmp.Walk(SnmpVersion.Ver1, ptrCurrentIP);
//                    //var prtModel = snmp.Walk(SnmpVersion.Ver1, prtModelDesc);
//                    //var prtDevice = snmp.Walk(SnmpVersion.Ver1, prtDeviceName);

//                    //if (result == null)
//                    //{
//                    //result = snmp.Get(SnmpVersion.Ver2, new[] { sysName, sysDescr, ptrLocation});

//                    //prtIP = snmp.Walk(SnmpVersion.Ver2, ptrCurrentIP);
//                    //prtModel = snmp.Walk(SnmpVersion.Ver2, prtModelDesc);
//                    //prtDevice = snmp.Walk(SnmpVersion.Ver2, prtDeviceName);
//                    //}

//                    //if (result == null)
//                    //{
//                    //result = snmp.Get(SnmpVersion.Ver3, new[] { sysName, sysDescr, ptrLocation });

//                    //prtIP = snmp.Walk(SnmpVersion.Ver3, ptrCurrentIP);
//                    //prtModel = snmp.Walk(SnmpVersion.Ver3, prtModelDesc);
//                    //prtDevice = snmp.Walk(SnmpVersion.Ver3, prtDeviceName);
//                    //}

//                    ipToScan.SNMPSysName = result.ElementAt(0).Value.ToString();
//                    ipToScan.SNMPSysDesc = result.ElementAt(1).Value.ToString();
//                    ipToScan.SNMPLocation = result.ElementAt(2).Value.ToString();


//                    if (Regex.IsMatch(ipToScan.SNMPLocation, @"\A\b[0-9a-fA-F\s]+\b\Z"))
//                    {
//                        byte[] bytes = ipToScan.SNMPLocation.Split(' ').Select(hex => Convert.ToByte(hex, 16)).ToArray();
//                        ipToScan.SNMPLocation = Encoding.ASCII.GetString(bytes);
//                    }


//                    if (ipToScan.SNMPSysDesc.Contains("Zebra Technologies"))
//                    {
//                        try
//                        {
//                            // Zebra SysNameOid
//                            Oid ZebraSysNameOid = new Oid("1.3.6.1.4.1.10642.20.3.5.0");

//                            // Erstelle das IPAddress-Objekt
//                            IPAddress ip = IPAddress.Parse(printerIp);

//                            // Erstelle das UdpTarget-Objekt mit IP-Adresse und Port 161 (Standardport für SNMP)
//                            UdpTarget target = new UdpTarget(ip, 161, 2000, 1); // Timeout 2000ms

//                            // Erstelle das Pdu-Objekt (PduType.Get für eine GET-Anfrage)
//                            Pdu pdu = new Pdu(PduType.Get);
//                            pdu.VbList.Add(ZebraSysNameOid);  // Füge die OID der Anfrage hinzu

//                            // Erstelle AgentParameters mit dem Community-String und der SNMP-Version
//                            AgentParameters parameters = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));

//                            // Sende die SNMP-GET-Anfrage und erhalte die Antwort
//                            SnmpV2Packet response;
//                            for (int i = 0; i < 6; i++)
//                            {
//                                response = (SnmpV2Packet)target.Request(pdu, parameters);
//                                if (response.Pdu.ErrorStatus == 0)  // Fehlerstatus 0 bedeutet Erfolg
//                                {
//                                    ipToScan.SNMPSysName = response.Pdu.VbList[0].Value.ToString();
//                                    break;
//                                }
//                            }
//                        }
//                        catch (Exception)
//                        {
//                            //throw;
//                        }
//                    }




//                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
//                    scanTask_Finished.ipToScan = ipToScan;

//                    SNMP_Task_Finished(this, scanTask_Finished);
//                }
//            }
//            catch (Exception ex)
//            {
//                //throw;
//            }
//        }
//    }
//}









//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Net;
//using System.Text;
//using System.Text.RegularExpressions;
//using System.Threading;
//using System.Threading.Tasks;
//using SnmpSharpNet;

//namespace MyNetworkMonitor
//{
//    /// <summary>
//    /// Führt SNMP-Scans durch und begrenzt die Anzahl der gleichzeitig laufenden Scans auf 50.
//    /// </summary>
//    public class ScanningMethod_SNMP
//    {
//        public ScanningMethod_SNMP() { }

//        #region Event-Argumente und Events

//        public event Action<IPToScan> SNMB_Task_Finished;
//        public event Action<int, int, int> ProgressUpdated;
//        public event Action<bool> SNMBFinished;

//        private int current = 0;
//        private int responded = 0;
//        private int total = 0;

//        #endregion

//        // Thread-sicherer Zähler für abgearbeitete IPs
//        private int _ipCounter = 0;

//        // Semaphore, um maximal 50 gleichzeitige Scans zuzulassen
//        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(50, 50);

//        /// <summary>
//        /// Startet den asynchronen SNMP-Scan für alle IPs in der übergebenen Liste.
//        /// </summary>
//        /// <param name="IPsToRefresh">Liste der zu scannenden IPs/Hostnamen</param>
//        public async Task ScanAsync(List<IPToScan> IPsToRefresh)
//        {
//            current = 0;
//            responded = 0;
//            total = IPsToRefresh.Count;

//            // Erstelle für jede IP einen Task, der sich zunächst die Semaphore holt.
//            var tasks = IPsToRefresh.Select(async ip =>
//            {
//                await _semaphore.WaitAsync();
//                try
//                {
//                    // Erhöhe den Zähler thread-sicher
//                    int currentValue = Interlocked.Increment(ref current);
//                    ProgressUpdated?.Invoke(current, responded, total);
//                    await SNMPTask(ip);

//                }
//                finally
//                {
//                    _semaphore.Release();
//                }
//            }).ToArray();

//            // Warten, bis alle Tasks abgeschlossen sind
//            await Task.WhenAll(tasks);

//            // Gesamt-Event auslösen
//            SNMBFinished?.Invoke(true);
//        }

//        /// <summary>
//        /// Führt die SNMP-Abfrage für eine einzelne IP aus. Blockierende Aufrufe werden in einem separaten Task ausgeführt.
//        /// </summary>
//        /// <param name="ipToScan">Die zu scannende IP bzw. der Hostname</param>
//        private async Task SNMPTask(IPToScan ipToScan)
//        {
//            await Task.Run(() =>
//            {
//                // Gültigkeitsprüfung der IP (oder des Hostnamens)
//                if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname))
//                    return;

//                try
//                {
//                    string printerIp = ipToScan.IPorHostname;
//                    string community = "public"; // Standard-Community

//                    // SNMP-Session erstellen und Timeout konfigurieren
//                    SimpleSnmp snmp = new SimpleSnmp(printerIp);
//                    snmp.Timeout = 10000; // 10 Sekunden

//                    if (!snmp.Valid)
//                        return;

//                    // Scan-Methode setzen
//                    ipToScan.UsedScanMethod = ScanMethod.SNMP;

//                    // OIDs definieren
//                    var oidSysName = "1.3.6.1.2.1.1.5.0";
//                    var oidSysDescr = "1.3.6.1.2.1.1.1.0";
//                    var oidLocation = "1.3.6.1.2.1.1.6.0";

//                    Dictionary<Oid, AsnType>? result = null;
//                    // Mehrfache Versuche (bis zu 6) zum Abrufen der SNMP-Daten
//                    for (int i = 0; i < 6; i++)
//                    {
//                        result = snmp.Get(SnmpVersion.Ver1, new[] { oidSysName, oidSysDescr, oidLocation });
//                        if (result != null && result.Count >= 3)
//                            break;
//                        Thread.Sleep(100);
//                    }

//                    if (result == null || result.Count < 3)
//                        return;

//                    // Werte anhand der OIDs extrahieren (Fallback: Reihenfolge im Dictionary)
//                    ipToScan.SNMPSysName = result.ContainsKey(new Oid(oidSysName))
//                        ? result[new Oid(oidSysName)].ToString()
//                        : result.ElementAt(0).Value.ToString();
//                    ipToScan.SNMPSysDesc = result.ContainsKey(new Oid(oidSysDescr))
//                        ? result[new Oid(oidSysDescr)].ToString()
//                        : result.ElementAt(1).Value.ToString();
//                    ipToScan.SNMPLocation = result.ContainsKey(new Oid(oidLocation))
//                        ? result[new Oid(oidLocation)].ToString()
//                        : result.ElementAt(2).Value.ToString();

//                    // Falls der Standort als hexadezimale Zeichenfolge vorliegt, konvertieren
//                    if (Regex.IsMatch(ipToScan.SNMPLocation, @"\A\b[0-9a-fA-F\s]+\b\Z"))
//                    {
//                        try
//                        {
//                            byte[] bytes = ipToScan.SNMPLocation
//                                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
//                                .Select(hex => Convert.ToByte(hex, 16))
//                                .ToArray();
//                            ipToScan.SNMPLocation = Encoding.ASCII.GetString(bytes);
//                        }
//                        catch (Exception)
//                        {
//                            // Bei der Konvertierung weitermachen
//                        }
//                    }

//                    // Falls es sich um einen Zebra-Drucker handelt, zusätzliche Abfrage zur Ermittlung des korrekten SNMPSysName
//                    if (ipToScan.SNMPSysDesc.Contains("Zebra Technologies", StringComparison.OrdinalIgnoreCase))
//                    {
//                        try
//                        {
//                            Oid zebraOid = new Oid("1.3.6.1.4.1.10642.20.3.5.0");
//                            IPAddress ipAddr = IPAddress.Parse(printerIp);
//                            UdpTarget target = new UdpTarget(ipAddr, 161, 2000, 1);

//                            Pdu pdu = new Pdu(PduType.Get);
//                            pdu.VbList.Add(zebraOid);

//                            AgentParameters parameters = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));
//                            for (int i = 0; i < 6; i++)
//                            {
//                                SnmpV2Packet response = (SnmpV2Packet)target.Request(pdu, parameters);
//                                if (response.Pdu.ErrorStatus == 0)
//                                {
//                                    ipToScan.SNMPSysName = response.Pdu.VbList[0].Value.ToString();
//                                    break;
//                                }
//                                Thread.Sleep(100);
//                            }
//                        }
//                        catch (Exception)
//                        {
//                            // Fehler bei der Zebra-Abfrage ignorieren
//                        }
//                    }

//                    // Für diese IP den Abschluss des Scan-Tasks melden
//                    SNMB_Task_Finished?.Invoke(ipToScan);

//                    ++responded;
//                    ProgressUpdated?.Invoke(current, responded, total);


//                }
//                catch (Exception)
//                {
//                    // Fehler können hier geloggt werden, falls benötigt.
//                }
//            });
//        }
//    }
//}







using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using SnmpSharpNet;

namespace MyNetworkMonitor
{
    public class ScanningMethod_SNMP
    {


        public ScanningMethod_SNMP() { }

        #region Event-Argumente und Events
        public event Action<IPToScan> SNMB_Task_Finished;
        public event Action<int, int, int> ProgressUpdated;
        public event Action<bool> SNMBFinished;

        private int current = 0;
        private int responded = 0;
        private int total = 0;
        #endregion

        private static readonly int MaxParallelTasks = 100; // Erhöht für schnellere Scans
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(MaxParallelTasks, MaxParallelTasks);
        private readonly ConcurrentBag<string> FailedIPs = new ConcurrentBag<string>();

        public async Task ScanAsync(List<IPToScan> IPsToRefresh)
        {
            current = 0;
            responded = 0;
            total = IPsToRefresh.Count;

            var tasks = new List<Task>();

            foreach (var ip in IPsToRefresh)
            {
                await _semaphore.WaitAsync();
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        await ScanSingleIPAsync(ip);
                    }
                    finally
                    {
                        _semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);
            SNMBFinished?.Invoke(true);
        }

        private async Task ScanSingleIPAsync(IPToScan ipToScan)
        {
            Interlocked.Increment(ref current);
            ProgressUpdated?.Invoke(current, responded, total);

            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2))) // Kürzerer Timeout
            {
                await SNMPTask(ipToScan, cts.Token);
            }
        }

        private async Task SNMPTask(IPToScan ipToScan, CancellationToken cancellationToken)
        {
            if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname))
                return;

            try
            {
                string printerIp = ipToScan.IPorHostname;
                string community = "public";

                var snmp = new SimpleSnmp(printerIp) { Timeout = 2000 }; // Kürzerer Timeout

                if (!snmp.Valid)
                    return;

                ipToScan.UsedScanMethod = ScanMethod.SNMP;

                var oids = new[] { "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.6.0" };
                Dictionary<Oid, AsnType>? result = null;

                // **Optimierung: SNMP-Requests parallel anfordern**
                for (int i = 0; i < 2; i++)
                {
                    result = await Task.Run(() => snmp.Get(SnmpVersion.Ver1, oids));
                    if (result != null && result.Count == 3)
                        break;

                    await Task.Delay(30, cancellationToken);
                }

                if (result == null || result.Count < 3)
                    return;

                ipToScan.SNMPSysName = result.TryGetValue(new Oid(oids[0]), out var sysName) ? sysName.ToString() : "N/A";
                ipToScan.SNMPSysDesc = result.TryGetValue(new Oid(oids[1]), out var sysDescr) ? sysDescr.ToString() : "N/A";
                ipToScan.SNMPLocation = result.TryGetValue(new Oid(oids[2]), out var location) ? location.ToString() : "N/A";

                // **Optimierung: Hex-String zu ASCII nur, wenn nötig**
                if (Regex.IsMatch(ipToScan.SNMPLocation, @"\A\b[0-9a-fA-F\s]+\b\Z"))
                {
                    try
                    {
                        byte[] bytes = ipToScan.SNMPLocation
                            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                            .Select(hex => Convert.ToByte(hex, 16))
                            .ToArray();
                        ipToScan.SNMPLocation = Encoding.UTF8.GetString(bytes);
                    }
                    catch { }
                }

                // **Optimierung: Zebra-Printer sofort erkennen**
                if (ipToScan.SNMPSysDesc.Contains("Zebra Technologies", StringComparison.OrdinalIgnoreCase))
                {
                    await QueryZebraPrinter(ipToScan, community, cancellationToken);
                }

                SNMB_Task_Finished?.Invoke(ipToScan);
                Interlocked.Increment(ref responded);
                ProgressUpdated?.Invoke(current, responded, total);
            }
            catch (OperationCanceledException)
            {
                FailedIPs.Add(ipToScan.IPorHostname);
            }
            catch (Exception ex)
            {
                FailedIPs.Add(ipToScan.IPorHostname);
            }
        }

        private async Task QueryZebraPrinter(IPToScan ipToScan, string community, CancellationToken cancellationToken)
        {
            try
            {
                Oid zebraOid = new Oid("1.3.6.1.4.1.10642.20.3.5.0");
                IPAddress ipAddr = IPAddress.Parse(ipToScan.IPorHostname);
                UdpTarget target = new UdpTarget(ipAddr, 161, 1000, 1); // **Schnellere Response-Zeit**

                Pdu pdu = new Pdu(PduType.Get);
                pdu.VbList.Add(zebraOid);
                AgentParameters parameters = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));

                for (int i = 0; i < 2; i++)
                {
                    SnmpV2Packet response = await Task.Run(() => (SnmpV2Packet)target.Request(pdu, parameters));

                    if (response.Pdu.ErrorStatus == 0)
                    {
                        ipToScan.SNMPSysName = response.Pdu.VbList[0].Value.ToString();
                        break;
                    }
                    await Task.Delay(30, cancellationToken);
                }
            }
            catch { }
        }
    }
}
