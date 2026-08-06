using System.Net;
using System.Text;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Kleiner statischer Dateiserver fuer die Topologie-Seite. Noetig, weil die
    /// eingebettete Webansicht die Seite ueber http laden muss - ueber file://
    /// verweigern Chromium-basierte Engines das Nachladen der Bibliothek.
    ///
    /// Der Server laeuft prozessweit nur einmal und bedient ausschliesslich
    /// Dateien unterhalb des Graph-Ordners.
    /// </summary>
    public static class TopologyWebServer
    {
        private static readonly object Sync = new();
        private static HttpListener? _listener;
        private static string _rootFolder = string.Empty;

        public const int DefaultPort = 8080;

        /// <summary>
        /// Startet den Server beim ersten Aufruf. Liefert die Basis-URL.
        /// </summary>
        public static string EnsureStarted(string rootFolder, int port = DefaultPort)
        {
            lock (Sync)
            {
                _rootFolder = Path.GetFullPath(rootFolder);

                if (_listener == null)
                {
                    _listener = new HttpListener();
                    _listener.Prefixes.Add($"http://localhost:{port}/");
                    _listener.Start();

                    var thread = new Thread(Serve) { IsBackground = true, Name = "TopologyWebServer" };
                    thread.Start();
                }
            }

            return $"http://localhost:{port}/";
        }

        private static void Serve()
        {
            while (_listener is { IsListening: true })
            {
                HttpListenerContext context;

                try { context = _listener.GetContext(); }
                catch (Exception) { return; /* Listener wurde beendet */ }

                using HttpListenerResponse response = context.Response;

                try
                {
                    string? filePath = ResolvePath(context.Request.Url?.AbsolutePath ?? "/");

                    if (filePath == null || !File.Exists(filePath))
                    {
                        response.StatusCode = (int)HttpStatusCode.NotFound;
                        continue;
                    }

                    byte[] buffer = File.ReadAllBytes(filePath);
                    response.ContentType = GetMimeType(filePath);
                    response.ContentLength64 = buffer.Length;
                    response.OutputStream.Write(buffer, 0, buffer.Length);
                }
                catch (Exception)
                {
                    try { response.StatusCode = (int)HttpStatusCode.InternalServerError; }
                    catch (Exception) { /* Verbindung bereits weg */ }
                }
            }
        }

        /// <summary>
        /// Loest den angefragten Pfad im Graph-Ordner auf. Gibt null zurueck,
        /// wenn er aus dem Ordner herausfuehrt (Directory Traversal).
        /// </summary>
        private static string? ResolvePath(string absolutePath)
        {
            string relative = Uri.UnescapeDataString(absolutePath).TrimStart('/');
            if (relative.Length == 0) return null;

            string candidate = Path.GetFullPath(Path.Combine(_rootFolder, relative));

            return candidate.StartsWith(_rootFolder, StringComparison.OrdinalIgnoreCase) ? candidate : null;
        }

        private static string GetMimeType(string filePath) => Path.GetExtension(filePath).ToLowerInvariant() switch
        {
            ".html" => "text/html; charset=UTF-8",
            ".json" => "application/json; charset=UTF-8",
            ".js" => "application/javascript; charset=UTF-8",
            ".css" => "text/css; charset=UTF-8",
            _ => "application/octet-stream"
        };
    }
}
