// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
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
using Lextm.SharpSnmpLib;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Reads system information (name, description, location, contact), serial number and MAC
    /// addresses of the targets by SNMP with the community "public".
    /// </summary>
    public class ScanningMethod_SNMP
    {


        /// <summary>Creates the SNMP scanner.</summary>
        public ScanningMethod_SNMP() { }


        private int current = 0;
        private int responded = 0;
        private int total = 0;

        private CancellationTokenSource _cts = new CancellationTokenSource(); // Allows the scan to be cancelled.

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

            // Reset the counters.
            current = 0;
            responded = 0;
            total = 0;
        }




        #region Event-Argumente und Events
        /// <summary>Reports progress as (processed, responded, total, status).</summary>
        public event Action<int, int, int, ScanStatus> ProgressUpdated;

        /// <summary>Raised for every target that answered.</summary>
        public event Action<IPToScan> SNMB_Task_Finished;        

        /// <summary>Raised when all queries of a run have finished.</summary>
        public event Action<bool> SNMBFinished;
      
        #endregion

        private static readonly int MaxParallelTasks = 100; // Concurrent queries
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(MaxParallelTasks, MaxParallelTasks);
        private readonly ConcurrentBag<string> FailedIPs = new ConcurrentBag<string>();

        /// <summary>
        /// Queries every target that is a valid IP address, with a time limit of ten seconds per
        /// target.
        /// </summary>
        /// <param name="IPsToRefresh">The targets.</param>
        public async Task ScanAsync(List<IPToScan> IPsToRefresh)
        {
            StartNewScan();

            current = 0;
            responded = 0;
            total = IPsToRefresh.Count;

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            var tasks = new List<Task>();


            foreach (var ip in IPsToRefresh)
            {
                if (_cts.Token.IsCancellationRequested) break;

                try
                {
                    await _semaphore.WaitAsync(_cts.Token);
                }
                catch (OperationCanceledException)
                {
                    Debug.WriteLine($"Scan of {ip.IPorHostname} cancelled.");
                    return; // The whole scan was stopped.
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
                }, _cts.Token));
            }

            await Task.WhenAll(tasks);
            SNMBFinished?.Invoke(true);
        }

        private async Task ScanSingleIPAsync(IPToScan ipToScan)
        {
            try
            {
                using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
                {
                    await SNMPTask(ipToScan, cts.Token);
                }
            }
            finally
            {
                // Count only once the query has been answered or has timed out; counting on
                // sending would leave the progress bar full for minutes.
                int currentValue = Interlocked.Increment(ref current);
                ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);
            }
        }

        private async Task SNMPTask(IPToScan ipToScan, CancellationToken cancellationToken)
        {
            if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname))
                return;

            if (cancellationToken.IsCancellationRequested)
                return;

            try
            {
                string printerIp = ipToScan.IPorHostname;
                string community = "public";

                if (!SnmpHelper.TryGetEndpoint(printerIp, out _))
                    return;

                var oids = new[]
                {
                    "1.3.6.1.2.1.1.5.0",    // sysName (RFC 3418)
                    "1.3.6.1.2.1.1.1.0",    // sysDescr
                    "1.3.6.1.2.1.1.6.0",    // sysLocation
                    "1.3.6.1.2.1.1.4.0",      // sysContact
                };
                Dictionary<string, string>? result = null;

                result = SnmpHelper.Get(printerIp, VersionCode.V1, community, oids);

                if (result == null || cancellationToken.IsCancellationRequested)
                    return;

                ipToScan.UsedScanMethod = ScanMethod.SNMP;


                string str_serialNumber = string.Empty;
                string str_MacAddress = string.Empty;

                Dictionary<string, string>? result_Serial = null;
                Dictionary<string, string>? result_MAC = null;
                try
                {
                    result_Serial = SnmpHelper.Get(printerIp, VersionCode.V1, community, new[] { "1.3.6.1.2.1.43.5.1.1.17.1" });
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
                            result_MAC = SnmpHelper.Get(printerIp, VersionCode.V1, community, new[] { "1.3.6.1.2.1.2.2.1.6." + i.ToString() });

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


                string str_SysName = result.TryGetValue(oids[0], out var sysName) ? sysName : string.Empty; ;

                string str_sysDescribtion = result.TryGetValue(oids[1], out var sysDescr) ? sysDescr : string.Empty;

                string str_location = result.TryGetValue(oids[2], out var location) ? location : string.Empty;

                string str_contact = result.TryGetValue(oids[3], out var contact) ? contact : string.Empty;

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






                // Zebra printers report host name and serial number under their own OIDs.
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


        // Converts a hex string to UTF-8 text; any other value is returned unchanged.
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
                const string zebraOid_Hostname = "1.3.6.1.4.1.10642.20.3.5.0";
                const string zebraOid_Serial = "1.3.6.1.4.1.10642.1.9.0";

                for (int i = 0; i < 2; i++)
                {
                    if (cancellationToken.IsCancellationRequested) return;

                    var response = await Task.Run(() => SnmpHelper.Get(ipToScan.IPorHostname, VersionCode.V2, community,
                        new[] { zebraOid_Hostname, zebraOid_Serial }, 1000));

                    if (response != null)
                    {
                        if (response.TryGetValue(zebraOid_Hostname, out var host)) ipToScan.SNMP_SysName = host;
                        if (response.TryGetValue(zebraOid_Serial, out var serial)) ipToScan.SNMP_Serial = serial;
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
                const string WagoSerial = "1.3.6.1.4.1.13576.10.1.3.0";

                for (int i = 0; i < 2; i++)
                {
                    if (cancellationToken.IsCancellationRequested) return;

                    var response = await Task.Run(() => SnmpHelper.Get(ipToScan.IPorHostname, VersionCode.V2, community,
                        new[] { WagoSerial }, 1000));

                    if (response != null)
                    {
                        if (response.TryGetValue(WagoSerial, out var serial)) ipToScan.SNMP_Serial = serial;
                        break;
                    }
                    await Task.Delay(30, cancellationToken);
                }
            }
            catch { }
        }
    }
}