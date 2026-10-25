namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Platform-independent abstraction for simple dialogs. Deliberately
    /// asynchronous because Avalonia shows modal dialogs only asynchronously.
    /// View models must not reference UI frameworks directly - they depend only
    /// on this interface.
    /// </summary>
    public interface IDialogService
    {
        /// <summary>Shows an informational message.</summary>
        Task ShowInfoAsync(string message, string title = "Information");

        /// <summary>Shows an error message.</summary>
        Task ShowErrorAsync(string message, string title = "Error");

        /// <summary>Asks a yes/no question.</summary>
        /// <returns><c>true</c> if confirmed.</returns>
        Task<bool> ConfirmAsync(string message, string title = "Please confirm");

        /// <summary>
        /// Asks a yes/no/cancel question - used by the export, which distinguishes
        /// "whole table", "selection only" and "cancel".
        /// </summary>
        Task<YesNoCancel> AskYesNoCancelAsync(string message, string title = "Question");
    }

    /// <summary>Answer to a yes/no/cancel question.</summary>
    public enum YesNoCancel
    {
        Yes,
        No,
        Cancel
    }
}
