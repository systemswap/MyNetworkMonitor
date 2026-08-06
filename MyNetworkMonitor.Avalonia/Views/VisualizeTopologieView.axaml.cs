using System.Data;
using Avalonia.Controls;
using MyNetworkMonitor.Avalonia.Platform;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Views
{
    /// <summary>
    /// Zeigt die 3D-Topologie der Ergebnistabelle. Die Seite wird erzeugt, in den
    /// Graph-Ordner geschrieben und ueber den lokalen Webserver geladen - ueber
    /// file:// verweigern die Web-Engines das Nachladen der Bibliothek.
    /// </summary>
    public partial class VisualizeTopologieView : Window
    {
        private readonly DataTable _resultTable;
        private readonly bool _useOnlineVersion;

        public VisualizeTopologieView() : this(new DataTable(), false)
        {
        }

        public VisualizeTopologieView(DataTable resultTable, bool useOnlineVersion)
        {
            InitializeComponent();

            _resultTable = resultTable;
            _useOnlineVersion = useOnlineVersion;

            // Erst wenn das Fenster steht, ist die Webansicht bereit zum Navigieren
            Opened += async (_, _) => await TopologyLauncher.ShowAsync(
                new NativeWebViewHost(webView), _resultTable, _useOnlineVersion);
        }
    }
}
