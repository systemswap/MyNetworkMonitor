using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // Windows-Implementierungen fuer die plattformneutrale Scan-Engine in Core
            Core.Services.PlatformServices.RegisterArp(new Platform.Windows.WindowsArpProvider());
            Core.Services.PlatformServices.RegisterRouting(new Platform.Windows.WindowsRoutingProvider());
            Core.Services.PlatformServices.RegisterRegistry(new Platform.Windows.WindowsRegistryReader());
            Core.Services.PlatformServices.RegisterEnterprise(new Platform.Windows.WindowsEnterpriseEnvironment());
            Core.Services.PlatformServices.RegisterWifi(new ScanningMethod_WiFi());

            // Global Exception Handling registrieren
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            DispatcherUnhandledException += App_DispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;

            base.OnStartup(e);
        }

        private void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            MessageBox.Show("UI-Fehler:\n" + e.Exception.Message, "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
            LogException(e.Exception);
            e.Handled = true; // verhindert Crash
        }

        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex)
            {
                MessageBox.Show("Allgemeiner Fehler:\n" + ex.Message, "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
                LogException(ex);
            }
        }

        private void TaskScheduler_UnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
            MessageBox.Show("Async-Fehler:\n" + e.Exception.Message, "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
            LogException(e.Exception);
            e.SetObserved(); // verhindert Crash
        }

        private void LogException(Exception ex)
        {
            try
            {
                File.AppendAllText("errorlog.txt", DateTime.Now + "\n" + ex.ToString() + "\n\n");
            }
            catch
            {
                // Wenn Logging selbst fehlschlägt, ignorieren
            }
        }
    }
}
