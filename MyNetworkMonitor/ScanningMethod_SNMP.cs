using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
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


        private int current = 0;
        private int responded = 0;
        private int total = 0;

        private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen

        //int currentValue = Interlocked.Increment(ref current);
        //Task.Run(() => ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running));

        //int respondedValue = Interlocked.Increment(ref responded);
        //Task.Run(() => ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running));

        //Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished));

        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel(); // 🔹 Scan abbrechen
                _cts.Dispose();
                _cts = new CancellationTokenSource();
            }

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped);
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




        #region Event-Argumente und Events
        public event Action<int, int, int, ScanStatus> ProgressUpdated;
        public event Action<IPToScan> SNMB_Task_Finished;        
        public event Action<bool> SNMBFinished;
      
        #endregion

        private static readonly int MaxParallelTasks = 100; // Erhöht für schnellere Scans
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(MaxParallelTasks, MaxParallelTasks);
        private readonly ConcurrentBag<string> FailedIPs = new ConcurrentBag<string>();

        public async Task ScanAsync(List<IPToScan> IPsToRefresh)
        {
            StartNewScan();

            current = 0;
            responded = 0;
            total = IPsToRefresh.Count;

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            var tasks = new List<Task>();

            //foreach (var ip in IPsToRefresh)
            //{
            //    if (_cts.Token.IsCancellationRequested) break; // 🔹 Abbruchprüfung

            //    await _semaphore.WaitAsync();
            //    tasks.Add(Task.Run(async () =>
            //    {
            //        try
            //        {
            //            await ScanSingleIPAsync(ip);
            //        }
            //        finally
            //        {
            //            _semaphore.Release();
            //        }
            //    }));
            //}

            foreach (var ip in IPsToRefresh)
            {
                if (_cts.Token.IsCancellationRequested) break;

                try
                {
                    await _semaphore.WaitAsync(_cts.Token);
                }
                catch (OperationCanceledException)
                {
                    Debug.WriteLine($"Scan für {ip.IPorHostname} wurde abgebrochen.");
                    return; // ⛔ Sauber beenden, falls der gesamte Scan gestoppt wurde
                }

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        await ScanSingleIPAsync(ip);
                    }
                    catch (OperationCanceledException)
                    {
                        FailedIPs.Add(ip.IPorHostname);
                    }
                    finally
                    {
                        _semaphore.Release();
                    }
                }, _cts.Token)); // 🔹 CancellationToken übergeben
            }

            await Task.WhenAll(tasks);
            SNMBFinished?.Invoke(true);
        }

        private async Task ScanSingleIPAsync(IPToScan ipToScan)
        {
            int currentValue = Interlocked.Increment(ref current);
            ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);

            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
            {
                await SNMPTask(ipToScan, cts.Token);
            }
        }

        private async Task SNMPTask(IPToScan ipToScan, CancellationToken cancellationToken)
        {
            if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname))
                return;

            if (cancellationToken.IsCancellationRequested)
                return; // 🔹 Abbruch vor SNMP-Request prüfen

            try
            {
                string printerIp = ipToScan.IPorHostname;
                string community = "public";

                var snmp = new SimpleSnmp(printerIp) { Timeout = 2000 }; // Kürzerer Timeout

                if (!snmp.Valid)
                    return;

                ipToScan.UsedScanMethod = ScanMethod.SNMP;

                var oids = new[]
                {
                    "1.3.6.1.2.1.1.5.0",    // System Name                    
                    "1.3.6.1.2.1.1.1.0",    // System Description                   
                    "1.3.6.1.2.1.1.6.0",    // System Location
                    "1.3.6.1.2.1.1.4.0",      // System Contact                    
                };
                Dictionary<Oid, AsnType>? result = null;

                result = snmp.Get(SnmpVersion.Ver1, oids);

                if (result == null || cancellationToken.IsCancellationRequested)
                    return;

                
                string str_serialNumber = string.Empty;
                string str_MacAddress = string.Empty;

                Dictionary<Oid, AsnType>? result_Serial = null;
                Dictionary<Oid, AsnType>? result_MAC = null;
                try
                {
                    result_Serial = (snmp.Get(SnmpVersion.Ver1, new[] { "1.3.6.1.2.1.43.5.1.1.17.1" }));
                    if(result_Serial != null) str_serialNumber = result_Serial.Values.ToList()[0].ToString();
                }
                catch
                {

                }

                List<string> macs = new List<string>();
                try
                {                    
                    for (int i = 1; i < 51; i++)
                    {
                        try
                        {
                            result_MAC = snmp.Get(SnmpVersion.Ver1, new[] { "1.3.6.1.2.1.2.2.1.6." + i.ToString() });

                            if (result_MAC != null && !string.IsNullOrEmpty(result_MAC.Values.ToList()[0].ToString()) && result_MAC.Values.ToList()[0].ToString() != "00 00 00 00 00 00")
                            {
                                macs.Add(result_MAC.Values.ToList()[0].ToString().Replace(" ", "-"));
                            }
                        }
                        catch { }
                    }   
                    
                }
                catch
                {

                }

                //if (cancellationToken.IsCancellationRequested) return;

                string str_SysName = result.TryGetValue(new Oid(oids[0]), out var sysName) ? sysName.ToString() : string.Empty; ;

                string str_sysDescribtion = result.TryGetValue(new Oid(oids[1]), out var sysDescr) ? sysDescr.ToString() : string.Empty; 

                string str_location = result.TryGetValue(new Oid(oids[2]), out var location) ? location.ToString() : string.Empty;

                string str_contact = result.TryGetValue(new Oid(oids[3]), out var contact) ? contact.ToString() : string.Empty;

                str_MacAddress = string.Join(" / ", macs.Distinct());
                



                str_SysName = ConvertHexToAscii(str_SysName).Replace("\t", " ");
                str_sysDescribtion = ConvertHexToAscii(str_sysDescribtion).Replace("\t", " ");
                str_contact = ConvertHexToAscii(str_contact).Replace("\t", " ");
                str_location = ConvertHexToAscii(str_location).Replace("\t", " ");
                str_serialNumber = ConvertHexToAscii(str_serialNumber).Replace("\t", " ");
                str_MacAddress = ConvertHexToAscii(str_MacAddress).Replace("\t", " ");


                ipToScan.SNMP_SysName = str_SysName;
                ipToScan.SNMP_Serial = str_serialNumber;
                ipToScan.SNMP_SysDesc = str_sysDescribtion;
                ipToScan.SNMP_Location = str_location;
                ipToScan.SNMP_Contact = str_contact;
                ipToScan.SNMP_MAC = str_MacAddress;

                //ipToScan.SNMP_SysDesc = string.Join("\t", lst_SNMPSysDesc);
                //ipToScan.SNMP_Location = string.Join("\t", lst_SNMPLocation);





                // **Optimierung: Zebra-Printer sofort erkennen**
                if (ipToScan.SNMP_SysDesc.Contains("Zebra Technologies", StringComparison.OrdinalIgnoreCase))
                {
                    await QueryZebraPrinter(ipToScan, community, cancellationToken);
                }


                if (ipToScan.SNMP_SysDesc.ToLower().Contains("wago", StringComparison.OrdinalIgnoreCase))
                {
                    await QueryWago(ipToScan, community, cancellationToken);
                }

                SNMB_Task_Finished?.Invoke(ipToScan);

                int respondedValue = Interlocked.Increment(ref responded);
                ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);
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


        // **Optimierung: Hex-String zu UTF8 nur, wenn nötig**
        string ConvertHexToAscii(string hexString)
        {
            if (!Regex.IsMatch(hexString, @"\A\b[0-9a-fA-F\s]+\b\Z"))
                return hexString;

            try
            {
                byte[] bytes = hexString
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Select(hex => Convert.ToByte(hex, 16))
                    .ToArray();
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return hexString;
            }
        }


        private async Task QueryZebraPrinter(IPToScan ipToScan, string community, CancellationToken cancellationToken)
        {
            try
            {
                Oid zebraOid_Hostname = new Oid("1.3.6.1.4.1.10642.20.3.5.0");
                Oid zebraOid_Serial = new Oid("1.3.6.1.4.1.10642.1.9.0");
                IPAddress ipAddr = IPAddress.Parse(ipToScan.IPorHostname);
                UdpTarget target = new UdpTarget(ipAddr, 161, 1000, 1); // **Schnellere Response-Zeit**

                Pdu pdu = new Pdu(PduType.Get);
                pdu.VbList.Add(zebraOid_Hostname);
                pdu.VbList.Add(zebraOid_Serial);
                AgentParameters parameters = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));

                for (int i = 0; i < 2; i++)
                {
                    if (cancellationToken.IsCancellationRequested) return;

                    SnmpV2Packet response = await Task.Run(() => (SnmpV2Packet)target.Request(pdu, parameters));

                    if (response.Pdu.ErrorStatus == 0)
                    {
                        ipToScan.SNMP_SysName = response.Pdu.VbList[0].Value.ToString();
                        ipToScan.SNMP_Serial = response.Pdu.VbList[1].Value.ToString();
                        break;
                    }
                    await Task.Delay(30, cancellationToken);
                }
            }
            catch { }
        }

        private async Task QueryWago(IPToScan ipToScan, string community, CancellationToken cancellationToken)
        {
            try
            {
                Oid WagoSerial = new Oid("1.3.6.1.4.1.13576.10.1.3.0");
                
                IPAddress ipAddr = IPAddress.Parse(ipToScan.IPorHostname);
                UdpTarget target = new UdpTarget(ipAddr, 161, 1000, 1); // **Schnellere Response-Zeit**

                Pdu pdu = new Pdu(PduType.Get);
                pdu.VbList.Add(WagoSerial);
                
                AgentParameters parameters = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));

                for (int i = 0; i < 2; i++)
                {
                    if (cancellationToken.IsCancellationRequested) return;

                    SnmpV2Packet response = await Task.Run(() => (SnmpV2Packet)target.Request(pdu, parameters));

                    if (response.Pdu.ErrorStatus == 0)
                    {                       
                        ipToScan.SNMP_Serial = response.Pdu.VbList[0].Value.ToString();

                        break;
                    }
                    await Task.Delay(30, cancellationToken);
                }
            }
            catch { }
        }
    }
}