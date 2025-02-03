using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using SnmpSharpNet;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_VLANInfos
    {
        public static void DiscoverVLANs()
        {
            string switchIP = GetGatewayIP(); // Automatische Erkennung des Switches
            if (string.IsNullOrEmpty(switchIP))
            {
                Console.WriteLine("Kein Switch gefunden (Gateway nicht erkannt).");
                return;
            }

            string community = "public"; // Falls nötig, anpassen oder vom Admin erfragen

            Console.WriteLine($"Switch gefunden: {switchIP}");
            Console.WriteLine("Abfrage von VLAN-Informationen über SNMP...");

            // Standard (802.1Q) VLAN-OIDs
            string vlanOid = "1.3.6.1.2.1.17.7.1.4.3.1.1"; // VLAN-ID Tabelle
            string vlanNameOid = "1.3.6.1.2.1.17.7.1.4.3.1.2"; // VLAN-Namen (falls verfügbar)
            string vlanPortOid = "1.3.6.1.2.1.17.7.1.4.5.1.1"; // VLAN-Port-Mapping

            // Switch-Typ erkennen (Cisco oder Aruba)
            string switchType = DetectSwitchType(switchIP, community);

            if (switchType == "Cisco")
            {
                Console.WriteLine("Cisco-Switch erkannt. Verwende Cisco-spezifische OIDs.");
                vlanOid = "1.3.6.1.4.1.9.9.46.1.3.1.1.4";  // Cisco VLAN-Namen
                vlanPortOid = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"; // Cisco VLAN-Port-Tabelle
            }
            else if (switchType == "Aruba")
            {
                Console.WriteLine("Aruba-Switch erkannt. Verwende Aruba-spezifische OIDs.");
                vlanOid = "1.3.6.1.4.1.11.2.14.11.1.2.1.1.1"; // Aruba VLAN-IDs
                vlanNameOid = "1.3.6.1.4.1.11.2.14.11.1.2.1.1.2"; // Aruba VLAN-Namen
                vlanPortOid = "1.3.6.1.4.1.11.2.14.11.1.2.1.2.1"; // Aruba VLAN-Port-Zuordnung
            }
            else
            {
                Console.WriteLine("Unbekannter Switch-Typ. Verwende Standard-OIDs.");
            }

            // SNMP-Anfrage starten
            SimpleSnmp snmp = new SimpleSnmp(switchIP, community);
            if (!snmp.Valid)
            {
                Console.WriteLine("SNMP-Verbindung fehlgeschlagen!");
                return;
            }

            // VLAN-IDs abrufen
            Dictionary<Oid, AsnType> vlanResult = snmp.Walk(SnmpVersion.Ver2, vlanOid);
            if (vlanResult != null && vlanResult.Count > 0)
            {
                Console.WriteLine("Gefundene VLANs:");
                foreach (var entry in vlanResult)
                {
                    Console.WriteLine($"VLAN-ID: {entry.Key} → Wert: {entry.Value}");
                }
            }
            else
            {
                Console.WriteLine("Keine VLAN-Daten gefunden.");
            }

            // VLAN-Namen abrufen (falls unterstützt)
            Dictionary<Oid, AsnType> vlanNameResult = snmp.Walk(SnmpVersion.Ver2, vlanNameOid);
            if (vlanNameResult != null && vlanNameResult.Count > 0)
            {
                Console.WriteLine("\nVLAN-Namen:");
                foreach (var entry in vlanNameResult)
                {
                    Console.WriteLine($"VLAN {entry.Key} → Name: {entry.Value}");
                }
            }

            // VLAN-Port-Zuordnung abrufen
            Dictionary<Oid, AsnType> vlanPortResult = snmp.Walk(SnmpVersion.Ver2, vlanPortOid);
            if (vlanPortResult != null && vlanPortResult.Count > 0)
            {
                Console.WriteLine("\nPort-Zuordnungen:");
                foreach (var entry in vlanPortResult)
                {
                    Console.WriteLine($"Port {entry.Key} → VLAN {entry.Value}");
                }
            }
        }

        // 🟢 Automatische Erkennung des Switches (Gateway-IP)
        private static string GetGatewayIP()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (GatewayIPAddressInformation gateway in nic.GetIPProperties().GatewayAddresses)
                    {
                        return gateway.Address.ToString(); // Erste gefundene Gateway-IP zurückgeben (Switch)
                    }
                }
            }
            return null;
        }

        // 🔵 Prüft den Switch-Typ (Cisco, Aruba oder unbekannt)
        private static string DetectSwitchType(string switchIP, string community)
        {
            string sysObjectIdOid = "1.3.6.1.2.1.1.2.0"; // OID für Herstellerkennung
            SimpleSnmp snmp = new SimpleSnmp(switchIP, community);
            Dictionary<Oid, AsnType> result = snmp.Get(SnmpVersion.Ver2, new string[] { sysObjectIdOid });

            if (result != null && result.Count > 0)
            {
                string sysObjectId = result.First().Value.ToString();
                if (sysObjectId.StartsWith("1.3.6.1.4.1.9.")) return "Cisco";  // Cisco-Switch
                if (sysObjectId.StartsWith("1.3.6.1.4.1.11.")) return "Aruba"; // Aruba-Switch (HPE)
            }
            return "Unknown"; // Unbekannter Switch-Typ
        }
    }
}
