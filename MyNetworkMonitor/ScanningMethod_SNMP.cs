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


        private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen

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

            //ProgressUpdated?.Invoke(current, responded, total); // 🔹 UI auf 0 setzen
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
            StartNewScan();

            current = 0;
            responded = 0;
            total = IPsToRefresh.Count;
            ProgressUpdated?.Invoke(current, responded, total);

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
                Dictionary<Oid, AsnType>? result_Serial = null;
                try
                {
                    result_Serial = (snmp.Get(SnmpVersion.Ver1, new[] { "1.3.6.1.2.1.43.5.1.1.17.1" }));
                    if(result_Serial != null) str_serialNumber = result_Serial.Values.ToList()[0].ToString();
                }
                catch
                {

                }

                if (cancellationToken.IsCancellationRequested) return;

                string str_SysName = result.TryGetValue(new Oid(oids[0]), out var sysName) ? sysName.ToString() : string.Empty; ;

                string str_sysDescribtion = result.TryGetValue(new Oid(oids[1]), out var sysDescr) ? sysDescr.ToString() : string.Empty; 

                string str_location = result.TryGetValue(new Oid(oids[2]), out var location) ? location.ToString() : string.Empty;

                string str_contact = result.TryGetValue(new Oid(oids[3]), out var contact) ? contact.ToString() : string.Empty;


                str_SysName = ConvertHexToAscii(str_SysName).Replace("\t", " ");
                str_sysDescribtion = ConvertHexToAscii(str_sysDescribtion).Replace("\t", " ");
                str_contact = ConvertHexToAscii(str_contact).Replace("\t", " ");
                str_location = ConvertHexToAscii(str_location).Replace("\t", " ");
                str_serialNumber = ConvertHexToAscii(str_serialNumber).Replace("\t", " ");



                List<string> lst_SNMPSysDesc = new List<string>();
                List<string> lst_SNMPLocation = new List<string>();

                if (!string.IsNullOrEmpty(str_serialNumber)) 
                { 
                    str_serialNumber = "Serial: " + str_serialNumber;
                    lst_SNMPSysDesc.Add(str_serialNumber);
                }


                if (!string.IsNullOrEmpty(str_sysDescribtion))
                {
                    str_sysDescribtion = "Descr: " + str_sysDescribtion;
                    lst_SNMPSysDesc.Add(str_sysDescribtion);

                    lst_SNMPSysDesc[0] = lst_SNMPSysDesc[0].PadRight(20);
                }


                if (!string.IsNullOrEmpty(str_location))
                {
                    str_location = "Location: " + str_location;
                    lst_SNMPLocation.Add(str_location);
                }


                if (!string.IsNullOrEmpty(str_contact))
                {
                    str_contact = "Contact: " + str_contact;
                    lst_SNMPLocation.Add(str_contact);

                    lst_SNMPLocation[0] = lst_SNMPLocation[0].PadRight(50);
                }




                ipToScan.SNMPSysName = str_SysName;
                ipToScan.SNMPSysDesc = string.Join("\t", lst_SNMPSysDesc);
                ipToScan.SNMPLocation = string.Join("\t", lst_SNMPLocation);

               



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
                Oid zebraOid = new Oid("1.3.6.1.4.1.10642.20.3.5.0");
                IPAddress ipAddr = IPAddress.Parse(ipToScan.IPorHostname);
                UdpTarget target = new UdpTarget(ipAddr, 161, 1000, 1); // **Schnellere Response-Zeit**

                Pdu pdu = new Pdu(PduType.Get);
                pdu.VbList.Add(zebraOid);
                AgentParameters parameters = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));

                for (int i = 0; i < 2; i++)
                {
                    if (cancellationToken.IsCancellationRequested) return;

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