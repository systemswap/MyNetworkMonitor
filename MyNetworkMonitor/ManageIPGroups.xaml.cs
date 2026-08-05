using System.Data;
using System.Windows;
using System.Windows.Controls;
using MyNetworkMonitor.Core.ViewModels;
using MyNetworkMonitor.Platform;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Interaction logic for ManageIPGroups.xaml.
    ///
    /// Bewusst minimal: die gesamte Logik liegt im plattformneutralen
    /// <see cref="ManageIPGroupsViewModel"/> (Projekt MyNetworkMonitor.Core).
    /// Dieses Fenster dient als Referenz/Vorlage dafür, wie die übrigen GUIs
    /// getrennt werden, damit die View später gegen eine Avalonia-View
    /// austauschbar ist.
    /// </summary>
    public partial class ManageIPGroups : Window
    {
        private readonly ManageIPGroupsViewModel _viewModel;

        public ManageIPGroups(DataTable IPGroupDT, string IPGroupsXMLFile)
        {
            InitializeComponent();

            _viewModel = new ManageIPGroupsViewModel(IPGroupDT, IPGroupsXMLFile, new WpfDialogService());
            _viewModel.CloseRequested += Close;
            DataContext = _viewModel;
        }

        // Einzige verbliebene View-Verantwortung: die WPF-spezifische
        // Spalten-Sortierung an das ViewModel delegieren (numerische IP-Sortierung).
        private void dg_IPGroups_Sorting(object sender, DataGridSortingEventArgs e)
        {
            if (_viewModel.SortBy(e.Column.SortMemberPath))
            {
                e.Handled = true;
                foreach (var col in dg_IPGroups.Columns)
                    col.SortDirection = null;
            }
        }
    }
}
