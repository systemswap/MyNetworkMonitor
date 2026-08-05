namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Plattformunabhängige Abstraktion für das Marshalling auf den UI-Thread.
    /// Ersetzt direkte Zugriffe auf Application.Current.Dispatcher (WPF) bzw.
    /// Dispatcher.UIThread (Avalonia) in der Logik-/ViewModel-Schicht.
    /// </summary>
    public interface IUiDispatcher
    {
        /// <summary>Aktion asynchron auf dem UI-Thread ausführen (nicht blockierend).</summary>
        void Post(Action action);

        /// <summary>Aktion auf dem UI-Thread ausführen und auf Abschluss warten.</summary>
        Task InvokeAsync(Action action);
    }
}
