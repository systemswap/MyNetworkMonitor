using System.Net;
using System.Text;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Small static file server for the topology page. Required because the
    /// embedded web view must load the page via http - via file:// Chromium-based
    /// engines refuse to load the library.
    ///
    /// The server runs only once per process and serves only files below the
    /// graph folder.
    /// </summary>
    public static class TopologyWebServer
    {
        private static readonly object Sync = new();
        private static HttpListener? _listener;
        private static string _rootFolder = string.Empty;

        /// <summary>The port used when none is given.</summary>
        public const int DefaultPort = 8080;

        /// <summary>
        /// Starts the server on the first call.
        /// </summary>
        /// <param name="rootFolder">The folder whose files are served.</param>
        /// <param name="port">The local TCP port.</param>
        /// <returns>The base URL, for example <c>http://127.0.0.1:8080/</c>.</returns>
        public static string EnsureStarted(string rootFolder, int port = DefaultPort)
        {
            lock (Sync)
            {
                _rootFolder = Path.GetFullPath(rootFolder);

                if (_listener == null)
                {
                    _listener = new HttpListener();

                    // Not "localhost": on Linux, .NET binds that only to IPv6
                    // ([::1]), while the embedded web view connects via IPv4 -
                    // the request would go nowhere without any visible error.
                    // 127.0.0.1 is unambiguous.
                    _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
                    _listener.Start();

                    var thread = new Thread(Serve) { IsBackground = true, Name = "TopologyWebServer" };
                    thread.Start();
                }
            }

            return $"http://127.0.0.1:{port}/";
        }

        private static void Serve()
        {
            while (_listener is { IsListening: true })
            {
                HttpListenerContext context;

                try { context = _listener.GetContext(); }
                catch (Exception) { return; /* listener was stopped */ }

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
                    catch (Exception) { /* connection already closed */ }
                }
            }
        }

        /// <summary>
        /// Resolves the requested path within the graph folder. Returns null if
        /// it leads out of the folder (directory traversal).
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
