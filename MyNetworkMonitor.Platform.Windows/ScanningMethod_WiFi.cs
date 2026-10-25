// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Windows implementation of <see cref="IWifiProvider"/> (native wlanapi.dll). Polls the connected Wi-Fi network at
    /// an interval and reports its signal quality and the strength in dBm
    /// (<see cref="WiFiSignalResult.WindowsQualityToDbm"/>).
    /// </summary>
    /// <remarks>
    /// The lists returned by wlanapi.dll are read field by field at the offsets of the structures in wlanapi.h and
    /// windot11.h, and freed with WlanFreeMemory. One client handle is opened per scan run and closed when the run ends.
    /// See docs/FEHLERGEDAECHTNIS.md, No. 24.
    /// </remarks>
    public class ScanningMethod_WiFi : IWifiProvider
    {
        /// <inheritdoc/>
        public event EventHandler<WiFiSignalResult>? WiFiSignalStrengthUpdated;

        private CancellationTokenSource? _cts;
        private bool _isScanning;

        /// <inheritdoc/>
        public bool IsScanning => _isScanning;

        // Client version 2: Windows Vista and later (WlanOpenHandle).
        private const uint ClientVersion = 2;

        // WLAN_INTERFACE_INFO_LIST and WLAN_AVAILABLE_NETWORK_LIST: dwNumberOfItems, dwIndex, then the entries.
        private const int ListHeaderSize = 8;

        // WLAN_INTERFACE_INFO: GUID InterfaceGuid (16), WCHAR strInterfaceDescription[256] (512), WLAN_INTERFACE_STATE isState (4).
        private const int InterfaceInfoSize = 532;
        private const int InterfaceStateOffset = 528;
        private const int InterfaceStateConnected = 1;   // wlan_interface_state_connected

        // WLAN_AVAILABLE_NETWORK: WCHAR strProfileName[256] (512), DOT11_SSID (ULONG uSSIDLength, UCHAR ucSSID[32]) at 512,
        // then nine 4-byte fields and DOT11_PHY_TYPE dot11PhyTypes[8]; wlanSignalQuality at 604, dwFlags at 620, 628 in all.
        private const int AvailableNetworkSize = 628;
        private const int SsidLengthOffset = 512;
        private const int SsidOffset = 516;
        private const int SsidMaxLength = 32;
        private const int SignalQualityOffset = 604;
        private const int FlagsOffset = 620;
        private const int FlagConnected = 0x1;           // WLAN_AVAILABLE_NETWORK_CONNECTED

        [DllImport("wlanapi.dll")]
        private static extern int WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

        [DllImport("wlanapi.dll")]
        private static extern int WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

        [DllImport("wlanapi.dll")]
        private static extern int WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

        [DllImport("wlanapi.dll")]
        private static extern int WlanGetAvailableNetworkList(IntPtr hClientHandle, ref Guid pInterfaceGuid, uint dwFlags, IntPtr pReserved, out IntPtr ppAvailableNetworkList);

        [DllImport("wlanapi.dll")]
        private static extern void WlanFreeMemory(IntPtr pMemory);

        /// <inheritdoc/>
        /// <remarks>Returns when the run ends: after <see cref="StopScanning"/>, or at once without a Wi-Fi adapter.</remarks>
        public async Task StartScanningAsync(int intervalMs = 2000)
        {
            if (_isScanning) return;
            _cts = new CancellationTokenSource();
            _isScanning = true;
            CancellationToken token = _cts.Token;

            if (WlanOpenHandle(ClientVersion, IntPtr.Zero, out _, out IntPtr client) != 0)
            {
                Debug.WriteLine("Wi-Fi: the WLAN service is not available.");
                _isScanning = false;
                return;
            }

            try
            {
                await Task.Run(async () =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        try
                        {
                            ScanOnce(client);
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Wi-Fi: scan failed: {ex.Message}");
                        }

                        try { await Task.Delay(intervalMs, token).ConfigureAwait(false); }
                        catch (OperationCanceledException) { break; }
                    }
                }, CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                // Closed only here, after the loop has ended: closing it from StopScanning could pull the handle away
                // from a scan that is still running.
                WlanCloseHandle(client, IntPtr.Zero);
                _isScanning = false;
            }
        }

        /// <inheritdoc/>
        public void StopScanning()
        {
            if (!_isScanning) return;
            _cts?.Cancel();
        }

        /// <summary>Reports the connected network of the first connected adapter, if there is one.</summary>
        private void ScanOnce(IntPtr client)
        {
            if (!TryGetConnectedInterface(client, out Guid adapter)) return;

            if (WlanGetAvailableNetworkList(client, ref adapter, 0, IntPtr.Zero, out IntPtr list) != 0) return;
            try
            {
                int count = Marshal.ReadInt32(list);
                for (int i = 0; i < count; i++)
                {
                    IntPtr entry = list + ListHeaderSize + i * AvailableNetworkSize;
                    if ((Marshal.ReadInt32(entry, FlagsOffset) & FlagConnected) == 0) continue;

                    int quality = Marshal.ReadInt32(entry, SignalQualityOffset);
                    WiFiSignalStrengthUpdated?.Invoke(this, new WiFiSignalResult
                    {
                        SSID = ReadSsid(entry),
                        SignalStrength = quality,
                        SignalStrengthDbm = WiFiSignalResult.WindowsQualityToDbm(quality),
                        Timestamp = DateTime.Now,
                    });

                    // The list holds one entry per profile; the connected network is reported once.
                    return;
                }
            }
            finally
            {
                WlanFreeMemory(list);
            }
        }

        /// <summary>The first adapter in the state "connected".</summary>
        private static bool TryGetConnectedInterface(IntPtr client, out Guid adapter)
        {
            adapter = Guid.Empty;
            if (WlanEnumInterfaces(client, IntPtr.Zero, out IntPtr list) != 0) return false;
            try
            {
                int count = Marshal.ReadInt32(list);
                for (int i = 0; i < count; i++)
                {
                    IntPtr entry = list + ListHeaderSize + i * InterfaceInfoSize;
                    if (Marshal.ReadInt32(entry, InterfaceStateOffset) != InterfaceStateConnected) continue;

                    adapter = Marshal.PtrToStructure<Guid>(entry);
                    return true;
                }
                return false;
            }
            finally
            {
                WlanFreeMemory(list);
            }
        }

        /// <summary>
        /// The network name from DOT11_SSID: exactly uSSIDLength bytes, as UTF-8 (the name is a byte string; current
        /// devices write UTF-8).
        /// </summary>
        private static string ReadSsid(IntPtr entry)
        {
            int length = Math.Clamp(Marshal.ReadInt32(entry, SsidLengthOffset), 0, SsidMaxLength);
            byte[] bytes = new byte[length];
            Marshal.Copy(entry + SsidOffset, bytes, 0, length);
            return Encoding.UTF8.GetString(bytes);
        }
    }
}
