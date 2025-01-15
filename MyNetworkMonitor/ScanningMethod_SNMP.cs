using System;
using System.Collections.Generic;
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

        public event EventHandler<ScanTask_Finished_EventArgs>? SNMP_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? SNMPFinished;

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

                    // SNMP-Abfrage
                    var result = snmp.Get(SnmpVersion.Ver1, new[] { sysName, sysDescr, prtName, sysContact });


                    ipToScan.SNMPSysName = result.ElementAt(0).Value.ToString();
                    ipToScan.SNMPSysDesc = result.ElementAt(1).Value.ToString();  
                    

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan = ipToScan;

                    SNMP_Task_Finished(this, scanTask_Finished);
                }
            }
            catch (Exception ex)
            {
                throw;
            }
        }
    }
}
