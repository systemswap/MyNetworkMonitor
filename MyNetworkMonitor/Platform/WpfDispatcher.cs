using System;
using System.Threading.Tasks;
using System.Windows;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform
{
    /// <summary>WPF-Implementierung von <see cref="IUiDispatcher"/> über den Application-Dispatcher.</summary>
    public sealed class WpfDispatcher : IUiDispatcher
    {
        public void Post(Action action)
            => Application.Current.Dispatcher.BeginInvoke(action);

        public Task InvokeAsync(Action action)
            => Application.Current.Dispatcher.InvokeAsync(action).Task;
    }
}
