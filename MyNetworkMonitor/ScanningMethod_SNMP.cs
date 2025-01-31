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


