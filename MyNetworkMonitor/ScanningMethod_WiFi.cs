using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Net.NetworkInformation;
//Signal
namespace MyNetworkMonitor
{
    internal class ScanningMethod_WiFi
    {
        public event EventHandler<WiFiSignalResult> WiFiSignalStrengthUpdated;
        private CancellationTokenSource _cts;
        private bool _isScanning;
        private Guid _interfaceGuid;
        private IntPtr _clientHandle;

        public bool IsScanning => _isScanning;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WLAN_INTERFACE_INFO
        {
            public Guid InterfaceGuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strInterfaceDescription;
            public int isState;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WLAN_INTERFACE_INFO_LIST
        {
            public int dwNumberOfItems;
            public int dwIndex;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public WLAN_INTERFACE_INFO[] InterfaceInfo;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WLAN_AVAILABLE_NETWORK
        {
            public int dwFlags;
            public int SignalQuality;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] dot11Ssid;
        }

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern int WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern int WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern int WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern int WlanGetAvailableNetworkList(
            IntPtr hClientHandle,
            ref Guid pInterfaceGuid,
            uint dwFlags,
            IntPtr pReserved,
            out IntPtr ppAvailableNetworkList);

        public class WiFiSignalResult
        {
            public string SSID { get; set; }
            public int SignalStrength { get; set; }
            public int SignalStrengthDbm { get; set; }
            public DateTime Timestamp { get; set; }
        }

        public async Task StartScanningAsync(int intervalMs = 2000)
        {
            if (_isScanning) return;
            _cts = new CancellationTokenSource();
            _isScanning = true;

            Debug.WriteLine("📡 WLAN-Scan gestartet...");

            _interfaceGuid = GetActiveWirelessNIC();
            if (_interfaceGuid == Guid.Empty)
            {
                Debug.WriteLine("❌ Kein aktiver WLAN-Adapter gefunden.");
                _isScanning = false;
                return;
            }

            uint negotiatedVersion;
            int result = WlanOpenHandle(2, IntPtr.Zero, out negotiatedVersion, out _clientHandle);
            if (result != 0)
            {
                Debug.WriteLine("❌ Fehler beim Öffnen des WLAN-Handles.");
                _isScanning = false;
                return;
            }

            await Task.Run(async () =>
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        ScanNetwork();
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"❌ Fehler beim Scannen: {ex.Message}");
                    }
                    await Task.Delay(intervalMs, _cts.Token);
                }
            }, _cts.Token);
        }

        public void StopScanning()
        {
            if (!_isScanning) return;
            _cts?.Cancel();
            _isScanning = false;
            WlanCloseHandle(_clientHandle, IntPtr.Zero);
            Debug.WriteLine("📡 WLAN-Scan gestoppt.");
        }


        private void ScanNetwork()
        {
            IntPtr clientHandle;
            uint negotiatedVersion;
            int result = WlanOpenHandle(2, IntPtr.Zero, out negotiatedVersion, out clientHandle);
            if (result != 0)
            {
                Debug.WriteLine($"❌ Fehler beim Öffnen des WLAN-Handles: {result}");
                return;
            }

            IntPtr pAvailableNetworkList;
            result = WlanGetAvailableNetworkList(clientHandle, ref _interfaceGuid, 0, IntPtr.Zero, out pAvailableNetworkList);
            if (result != 0)
            {
                Debug.WriteLine("❌ Fehler beim Abrufen der SSID-Liste.");
                WlanCloseHandle(clientHandle, IntPtr.Zero);
                return;
            }

            WLAN_AVAILABLE_NETWORK network = Marshal.PtrToStructure<WLAN_AVAILABLE_NETWORK>(pAvailableNetworkList);
            string ssid = Encoding.ASCII.GetString(network.dot11Ssid).Replace("\0", string.Empty);
            int signalStrength = network.SignalQuality;
            int signalStrengthDbm = (signalStrength - 100) * 2;
            int offset = Marshal.SizeOf(typeof(WLAN_AVAILABLE_NETWORK));
            int networkCount = Marshal.ReadInt32(pAvailableNetworkList);

            for (int i = 0; i < networkCount; i++)
            {
                IntPtr networkPtr = new IntPtr(pAvailableNetworkList.ToInt64() + 8 + (i * offset));
                WLAN_AVAILABLE_NETWORK network2 = Marshal.PtrToStructure<WLAN_AVAILABLE_NETWORK>(networkPtr);


                WlanCloseHandle(clientHandle, IntPtr.Zero);


                signalStrength = network2.SignalQuality;
                signalStrengthDbm = (signalStrength - 100) * 2;

                var wifiResult = new WiFiSignalResult
                {
                    SSID = ssid,
                    SignalStrength = signalStrength,
                    SignalStrengthDbm = signalStrengthDbm,
                    Timestamp = DateTime.Now
                };

                

                Debug.WriteLine($"📶 SSID: {wifiResult.SSID}, Signalstärke: {wifiResult.SignalStrength}% ({wifiResult.SignalStrengthDbm} dBm)");
                WiFiSignalStrengthUpdated?.Invoke(this, wifiResult);
            }
        }
        private Guid GetActiveWirelessNIC()
        {
            IntPtr clientHandle;
            uint negotiatedVersion;
            int result = WlanOpenHandle(2, IntPtr.Zero, out negotiatedVersion, out clientHandle);
            if (result != 0)
                return Guid.Empty;

            IntPtr pInterfaceList;
            result = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out pInterfaceList);
            if (result != 0)
            {
                WlanCloseHandle(clientHandle, IntPtr.Zero);
                return Guid.Empty;
            }

            WLAN_INTERFACE_INFO_LIST interfaceList = Marshal.PtrToStructure<WLAN_INTERFACE_INFO_LIST>(pInterfaceList);
            WlanCloseHandle(clientHandle, IntPtr.Zero);
            return interfaceList.dwNumberOfItems > 0 ? interfaceList.InterfaceInfo[0].InterfaceGuid : Guid.Empty;
        }
    }
}

