// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Platform-independent abstraction for marshalling onto the UI thread.
    /// Keeps the logic and view model layer free of direct access to
    /// Dispatcher.UIThread (Avalonia).
    /// </summary>
    public interface IUiDispatcher
    {
        /// <summary>Runs an action asynchronously on the UI thread (non-blocking).</summary>
        void Post(Action action);

        /// <summary>Runs an action on the UI thread and waits for completion.</summary>
        Task InvokeAsync(Action action);
    }
}
