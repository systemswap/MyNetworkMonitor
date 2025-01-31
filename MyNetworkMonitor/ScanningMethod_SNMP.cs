using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using SnmpSharpNet;

namespace MyNetworkMonitor
{
    class ScanningMethod_SNMP
    {
        public ScanningMethod_SNMP()
        {
            
        }

        public class CounterEventArgs : EventArgs
        {
            public int Value { get; }

            public CounterEventArgs(int value)
            {
                Value = value;
            }
        }

        public event EventHandler<CounterEventArgs>? SNMP_SendRequest;
        public event EventHandler<ScanTask_Finished_EventArgs>? SNMP_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? SNMPFinished;

        int IPs = 0;

        /// <summary>
        /// to get the SNMP Infos of the IP
        /// </summary>
        /// <param name="IPsToRefresh"></param>
        /// <returns></returns>
        public async Task ScanAsync(List<IPToScan> IPsToRefresh)
        {
            var tasks = new List<Task>();

            Parallel.ForEach(IPsToRefresh, ip =>
            {
                if (SNMP_SendRequest != null)
                {
                    SNMP_SendRequest?.Invoke(this, new CounterEventArgs(++IPs));
                }

                var task = SNMPTask(ip);
                if (task != null) tasks.Add(task);
            });

            await Task.WhenAll(tasks.Where(t => t != null));
            if (SNMPFinished != null)
            {
                SNMPFinished(this, new Method_Finished_EventArgs());
            }
        }

        private async Task SNMPTask(IPToScan ipToScan)
        {
            if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname)) return;

            try
            {
                if (SNMP_Task_Finished != null)
                {
                    // Geben Sie die IP-Adresse des Druckers ein
                    string printerIp = ipToScan.IPorHostname;
                    string community = "public"; // Standard-SNMP-Community-String

                    // SNMP-Session erstellen
                    SimpleSnmp snmp = new SimpleSnmp(printerIp);//, community);                    
                    snmp.Timeout = 10000; //Millisekunden

                    if (!snmp.Valid)
                    {
                        //Console.WriteLine("SNMP-Session ist ungültig.");
                        return;
                    }

                    ipToScan.UsedScanMethod = ScanMethod.SNMP;

                    // OIDs  
                   
                    string sysName = "1.3.6.1.2.1.1.5.0"; // SNMP-OID für sysName (Hostname) bei Canon: Geräteverwaltung -> Einstellungen Geräte-Information

                    string sysDescr = "1.3.6.1.2.1.1.1.0"; // bei Canon: Netzwerk -> Einstellungen Computername / Name Arbeitsgruppe
                    string ptrLocation = "1.3.6.1.2.1.1.6.0";
                    string prtName = "1.3.6.1.2.1.43.5.1.1.1.1"; // prtGeneralPrinterName: Name des Druckers.
                    string sysContact = "1.3.6.1.2.1.1.4.0"; // sysContact: Kontaktinformationen des Administrators.


                    // abfrage mit walk
                    //string ptrCurrentIP = "1.3.6.1.2.1.4.22.1.2";
                    //string prtModelDesc = "1.3.6.1.2.1.43.5.1.1.17.1";
                    //string prtDeviceName = "1.3.6.1.2.1.25.3.2.1.3";



                    //string ZebraSysName = string.Empty;
                    //try
                    //{
                    //    // Zebra SysNameOid
                    //    Oid ZebraSysNameOid = new Oid("1.3.6.1.4.1.10642.20.3.5.0");

                    //    // Erstelle das IPAddress-Objekt
                    //    IPAddress ip = IPAddress.Parse(printerIp);

                    //    // Erstelle das UdpTarget-Objekt mit IP-Adresse und Port 161 (Standardport für SNMP)
                    //    UdpTarget target = new UdpTarget(ip, 161, 2000, 1); // Timeout 2000ms

                    //    // Erstelle das Pdu-Objekt (PduType.Get für eine GET-Anfrage)
                    //    Pdu pdu = new Pdu(PduType.Get);
                    //    pdu.VbList.Add(ZebraSysNameOid);  // Füge die OID der Anfrage hinzu

                    //    // Erstelle AgentParameters mit dem Community-String und der SNMP-Version
                    //    AgentParameters parameters = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));

                    //    // Sende die SNMP-GET-Anfrage und erhalte die Antwort
                    //    SnmpV2Packet response = (SnmpV2Packet)target.Request(pdu, parameters);

                    //    if (response.Pdu.ErrorStatus == 0)  // Fehlerstatus 0 bedeutet Erfolg
                    //    {
                    //        ZebraSysName = response.Pdu.VbList[0].Value.ToString();
                    //    }
                    //}
                    //catch (Exception)
                    //{

                    //    //throw;
                    //}










                    // SNMP-Abfrage
                    Dictionary<Oid, AsnType> result = new Dictionary<Oid, AsnType>();
                    for (int i = 0; i < 6; i++)
                    {
                        result = snmp.Get(SnmpVersion.Ver1, new[] { sysName, sysDescr, ptrLocation });
                        if (result == null) continue;                        

                        if (result.Count >= 1)
                        {
                            break;
                        }
                    } 
                    

                    //var ZebraNameResult = snmp.Walk(SnmpVersion.Ver1, ZebraSNMP_Name);
                    //var prtIP = snmp.Walk(SnmpVersion.Ver1, ptrCurrentIP);
                    //var prtModel = snmp.Walk(SnmpVersion.Ver1, prtModelDesc);
                    //var prtDevice = snmp.Walk(SnmpVersion.Ver1, prtDeviceName);

                    //if (result == null)
                    //{
                        //result = snmp.Get(SnmpVersion.Ver2, new[] { sysName, sysDescr, ptrLocation});

                        //prtIP = snmp.Walk(SnmpVersion.Ver2, ptrCurrentIP);
                        //prtModel = snmp.Walk(SnmpVersion.Ver2, prtModelDesc);
                        //prtDevice = snmp.Walk(SnmpVersion.Ver2, prtDeviceName);
                    //}

                    //if (result == null)
                    //{
                        //result = snmp.Get(SnmpVersion.Ver3, new[] { sysName, sysDescr, ptrLocation });

                        //prtIP = snmp.Walk(SnmpVersion.Ver3, ptrCurrentIP);
                        //prtModel = snmp.Walk(SnmpVersion.Ver3, prtModelDesc);
                        //prtDevice = snmp.Walk(SnmpVersion.Ver3, prtDeviceName);
                    //}

                    ipToScan.SNMPSysName = result.ElementAt(0).Value.ToString();
                    ipToScan.SNMPSysDesc = result.ElementAt(1).Value.ToString();
                    ipToScan.SNMPLocation = result.ElementAt(2).Value.ToString();


                    if (Regex.IsMatch(ipToScan.SNMPLocation, @"\A\b[0-9a-fA-F\s]+\b\Z"))
                    {
                        byte[] bytes = ipToScan.SNMPLocation.Split(' ').Select(hex => Convert.ToByte(hex, 16)).ToArray();
                        ipToScan.SNMPLocation = Encoding.ASCII.GetString(bytes);                        
                    }


                    if (ipToScan.SNMPSysDesc.Contains("Zebra Technologies"))
                    {
                        try
                        {
                            // Zebra SysNameOid
                            Oid ZebraSysNameOid = new Oid("1.3.6.1.4.1.10642.20.3.5.0");

                            // Erstelle das IPAddress-Objekt
                            IPAddress ip = IPAddress.Parse(printerIp);

                            // Erstelle das UdpTarget-Objekt mit IP-Adresse und Port 161 (Standardport für SNMP)
                            UdpTarget target = new UdpTarget(ip, 161, 2000, 1); // Timeout 2000ms

                            // Erstelle das Pdu-Objekt (PduType.Get für eine GET-Anfrage)
                            Pdu pdu = new Pdu(PduType.Get);
                            pdu.VbList.Add(ZebraSysNameOid);  // Füge die OID der Anfrage hinzu

                            // Erstelle AgentParameters mit dem Community-String und der SNMP-Version
                            AgentParameters parameters = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));

                            // Sende die SNMP-GET-Anfrage und erhalte die Antwort
                            SnmpV2Packet response;
                            for (int i = 0; i < 6; i++)
                            {                                
                                response = (SnmpV2Packet)target.Request(pdu, parameters);
                                if (response.Pdu.ErrorStatus == 0)  // Fehlerstatus 0 bedeutet Erfolg
                                {
                                    ipToScan.SNMPSysName = response.Pdu.VbList[0].Value.ToString();
                                    break;
                                }
                            }
                        }
                        catch (Exception)
                        {
                            //throw;
                        }
                    }

                    


                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan = ipToScan;

                    SNMP_Task_Finished(this, scanTask_Finished);
                }
            }
            catch (Exception ex)
            {
                //throw;
            }
        }
    }
}







//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Net;
//using System.Net.Sockets;
//using System.Text;
//using System.Text.RegularExpressions;
//using System.Threading;
//using System.Threading.Tasks;

//namespace MyNetworkMonitor
//{
//    class ScanningMethod_SNMP
//    {
//        public ScanningMethod_SNMP(string community = "public", int maxParallelScans = 10)
//        {
//            _community = community;
//            _maxParallelScans = maxParallelScans;
//            _semaphore = new SemaphoreSlim(_maxParallelScans);
//        }

//        public class CounterEventArgs : EventArgs
//        {
//            public int Value { get; }
//            public CounterEventArgs(int value) { Value = value; }
//        }

//        public event EventHandler<CounterEventArgs>? SNMP_SendRequest;
//        public event EventHandler<ScanTask_Finished_EventArgs>? SNMP_Task_Finished;
//        public event EventHandler<Method_Finished_EventArgs>? SNMPFinished;

//        private readonly string _community;
//        private readonly int _maxParallelScans;
//        private int _IPs = 0;
//        private readonly SemaphoreSlim _semaphore;

//        public async Task ScanAsync(List<IPToScan> IPsToRefresh)
//        {
//            var tasks = new List<Task>();

//            foreach (var ip in IPsToRefresh)
//            {
//                await _semaphore.WaitAsync();
//                tasks.Add(Task.Run(async () =>
//                {
//                    try
//                    {
//                        SNMP_SendRequest?.Invoke(this, new CounterEventArgs(++_IPs));
//                        await SNMPTask(ip);
//                    }
//                    catch (Exception ex)
//                    {
//                        Console.WriteLine($"Fehler bei {ip.IPorHostname}: {ex.Message}");
//                    }
//                    finally
//                    {
//                        _semaphore.Release();
//                    }
//                }));
//            }

//            try
//            {
//                await Task.WhenAll(tasks);
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine($"Fehler im SNMP-Scan: {ex.Message}");
//            }
//            finally
//            {
//                SNMPFinished?.Invoke(this, new Method_Finished_EventArgs());
//            }
//        }

//        private async Task SNMPTask(IPToScan ipToScan)
//        {
//            if (!IPAddress.TryParse(ipToScan.IPorHostname, out _))
//                return;

//            try
//            {
//                ipToScan.UsedScanMethod = ScanMethod.SNMP;

//                // Standard SNMP OIDs
//                var oidList = new List<string>
//                {
//                    "1.3.6.1.2.1.1.5.0",  // sysName (Hostname)
//                    "1.3.6.1.2.1.1.1.0",  // sysDescr (Gerätebeschreibung)
//                    "1.3.6.1.2.1.1.6.0",  // sysLocation (Standort)
//                    "1.3.6.1.2.1.1.4.0"   // sysContact (Admin)
//                };

//                Dictionary<string, string> results = await SnmpGet(ipToScan.IPorHostname, oidList);

//                ipToScan.SNMPSysName = results.ContainsKey(oidList[0]) ? results[oidList[0]] : "Unknown";
//                ipToScan.SNMPSysDesc = results.ContainsKey(oidList[1]) ? results[oidList[1]] : "Unknown";
//                ipToScan.SNMPLocation = results.ContainsKey(oidList[2]) ? results[oidList[2]] : "Unknown";

//                // Zebra Drucker-Check (SNMP Walk)
//                if (ipToScan.SNMPSysDesc.Contains("Zebra Technologies"))
//                {
//                    ipToScan.SNMPSysName = await SnmpWalk(ipToScan.IPorHostname, "1.3.6.1.4.1.10642.20.3.5.0");
//                }

//                ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs { ipToScan = ipToScan };
//                SNMP_Task_Finished?.Invoke(this, scanTask_Finished);
//            }
//            catch (Exception)
//            {
//                // Fehler ignorieren, einfach weitermachen
//            }
//        }

//        private async Task<Dictionary<string, string>> SnmpGet(string ip, List<string> oids)
//        {
//            var results = new Dictionary<string, string>();

//            using (UdpClient udpClient = new UdpClient())
//            {
//                udpClient.Client.ReceiveTimeout = 5000;
//                IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse(ip), 161);

//                foreach (var oid in oids)
//                {
//                    try
//                    {
//                        byte[] request = CreateSnmpGetRequest(oid);
//                        await udpClient.SendAsync(request, request.Length, endPoint);

//                        UdpReceiveResult response = await udpClient.ReceiveAsync();
//                        string value = ParseSnmpResponse(response.Buffer);
//                        results[oid] = value;
//                    }
//                    catch
//                    {
//                        results[oid] = "N/A";
//                    }
//                }
//            }
//            return results;
//        }

//        private async Task<string> SnmpWalk(string ip, string baseOid, int maxIterations = 20, int maxTimeoutMs = 5000)
//        {
//            using (UdpClient udpClient = new UdpClient())
//            {
//                udpClient.Client.ReceiveTimeout = 2000;
//                IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse(ip), 161);
//                string lastOid = baseOid;
//                int iteration = 0;
//                var stopwatch = System.Diagnostics.Stopwatch.StartNew();

//                try
//                {
//                    while (iteration < maxIterations && stopwatch.ElapsedMilliseconds < maxTimeoutMs)
//                    {
//                        byte[] request = CreateSnmpGetRequest(lastOid);
//                        await udpClient.SendAsync(request, request.Length, endPoint);
//                        UdpReceiveResult response = await udpClient.ReceiveAsync();
//                        string value = ParseSnmpResponse(response.Buffer);

//                        if (string.IsNullOrEmpty(value) || value == "END" || !value.StartsWith(baseOid))
//                            break;

//                        lastOid = value;
//                        iteration++;
//                    }
//                }
//                catch
//                {
//                    return "Unknown";
//                }
//            }
//            return "Unknown";
//        }

//        private byte[] CreateSnmpGetRequest(string oid)
//        {
//            List<byte> snmpPacket = new List<byte>
//            {
//                0x30, 0x26, 0x02, 0x01, 0x00, // SNMP Header
//                0x04, (byte)_community.Length
//            };
//            snmpPacket.AddRange(Encoding.ASCII.GetBytes(_community));
//            snmpPacket.AddRange(new byte[] { 0xA0, 0x19, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0F, 0x30, 0x0D });
//            snmpPacket.Add(0x06);
//            snmpPacket.Add((byte)oid.Length);
//            snmpPacket.AddRange(Encoding.ASCII.GetBytes(oid));
//            snmpPacket.AddRange(new byte[] { 0x05, 0x00 });
//            return snmpPacket.ToArray();
//        }

//        private string ParseSnmpResponse(byte[] response)
//        {
//            if (response.Length < 2) return "N/A";
//            return Encoding.ASCII.GetString(response.Skip(response.Length - 10).ToArray());
//        }
//    }
//}
