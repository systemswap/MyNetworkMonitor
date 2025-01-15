using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
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
                    // "1.3.6.1.2.1.1.5.0" // sysName
                    // "1.3.6.1.2.1.1.1.0" // sysDescr
                    // "1.3.6.1.2.1.1.4.0" // sysContact: Kontaktinformationen des Administrators.
                    // "1.3.6.1.2.1.43.5.1.1.1.1" // prtGeneralPrinterName: Name des Druckers.

                    
                    string sysName = "1.3.6.1.2.1.1.5.0"; // SNMP-OID für sysName (Hostname) bei Canon: Geräteverwaltung -> Einstellungen Geräte-Information
                    string sysDescr = "1.3.6.1.2.1.1.1.0"; // bei Canon: Netzwerk -> Einstellungen Computername / Name Arbeitsgruppe
                    string prtName = "1.3.6.1.2.1.43.5.1.1.1.1";
                    string sysContact = "1.3.6.1.2.1.1.4.0";
                    string ptrLocation = "1.3.6.1.2.1.1.6.0";

                    // abfrage mit walk
                    string ptrCurrentIP = "1.3.6.1.2.1.4.22.1.2";
                    string prtModelDesc = "1.3.6.1.2.1.43.5.1.1.17.1";
                    string prtDeviceName = "1.3.6.1.2.1.25.3.2.1.3";

                    // SNMP-Abfrage
                    var result = snmp.Get(SnmpVersion.Ver1, new[] { sysName, sysDescr, ptrLocation, prtName, sysContact });

                    var prtIP = snmp.Walk(SnmpVersion.Ver1, ptrCurrentIP);
                    var prtModel = snmp.Walk(SnmpVersion.Ver1, prtModelDesc);
                    var prtDevice = snmp.Walk(SnmpVersion.Ver1, prtDeviceName);

                    if (result == null)
                    {
                        result = snmp.Get(SnmpVersion.Ver2, new[] { sysName, sysDescr, ptrLocation, prtName, sysContact });

                        prtIP = snmp.Walk(SnmpVersion.Ver2, ptrCurrentIP);
                        prtModel = snmp.Walk(SnmpVersion.Ver2, prtModelDesc);
                        prtDevice = snmp.Walk(SnmpVersion.Ver2, prtDeviceName);
                    }

                    if (result == null)
                    {
                        result = snmp.Get(SnmpVersion.Ver3, new[] { sysName, sysDescr, ptrLocation, prtName, sysContact });

                        prtIP = snmp.Walk(SnmpVersion.Ver3, ptrCurrentIP);
                        prtModel = snmp.Walk(SnmpVersion.Ver3, prtModelDesc);
                        prtDevice = snmp.Walk(SnmpVersion.Ver3, prtDeviceName);
                    }                  


                    ipToScan.SNMPSysName = result.ElementAt(0).Value.ToString();
                    ipToScan.SNMPSysDesc = result.ElementAt(1).Value.ToString();
                    ipToScan.SNMPLocation = result.ElementAt(2).Value.ToString();


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
