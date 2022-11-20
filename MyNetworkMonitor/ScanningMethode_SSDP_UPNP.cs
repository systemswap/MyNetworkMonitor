using Rssdp;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanningMethode_SSDP_UPNP
    {
        public ScanningMethode_SSDP_UPNP(ScanResults scanResults)
        {
            _scannResults = scanResults;
        }

        ScanResults _scannResults;

        public async void ScanForSSDP()
        {
            //https://blog.noser.com/geraetesuche-mit-ssdp-in-net-im-lokalen-netzwerk/

            //var ipAddresses = scanningMethods.NetworkResultsTable.AsEnumerable().Select(r => r.Field<string>("IPs")).ToList();

            //foreach (var netIf in NetworkInterface.GetAllNetworkInterfaces())
            //{
            //    if (netIf.NetworkInterfaceType.Equals(NetworkInterfaceType.Ethernet) &&
            //        netIf.OperationalStatus.Equals(OperationalStatus.Up) &&
            //        !netIf.Name.Contains("vEthernet"))
            //    {
            //        foreach (var ip in netIf.GetIPProperties().UnicastAddresses)
            //        {
            //            if (ip.Address.AddressFamily.Equals(AddressFamily.InterNetwork))
            //            {
            //                var ipAddress = ip.Address.ToString();
            //                Console.WriteLine($"{netIf.Name}: {ipAddress}'");
            //                ipAddresses.Add(ipAddress);
            //            }
            //        }
            //    }
            //}

            var searchTarget = "urn:schemas-upnp-org:device:WANDevice:1";
            var devices = new ConcurrentBag<Discovered​Ssdp​Device>();

            using (var deviceLocator = new SsdpDeviceLocator())
            {
                var foundDevices = await deviceLocator.SearchAsync();

                foreach (var foundDevice in foundDevices)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();
                    List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + foundDevice.DescriptionLocation.Host + "'").ToList();

                    if (rows.Count() == 0)
                    {
                        row["SendAlert"] = false;
                        row["SSDP"] = Properties.Resources.green_dot;
                        row["IP"] = foundDevice.DescriptionLocation.Host;
                        //row["Hostname"] = Dns.GetHostEntry(foundDevice.DescriptionLocation.Host).HostName;
                        //row["Aliases"] = string.Join("; ", Dns.GetHostEntry(foundDevice.DescriptionLocation.Host).Aliases);
                        row["ResponseTime"] = "";

                        _scannResults.ResultTable.Rows.Add(row);
                    }
                    else
                    {
                        _scannResults.ResultTable.Rows[_scannResults.ResultTable.Rows.IndexOf(rows[0])]["SSDP"] = Properties.Resources.green_dot;
                    }
                }
            }
        }
    }
}
