using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using Avalonia;
using Avalonia.Collections;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Styling;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Data.Converters;
using Avalonia.Media;
using Avalonia.Media.Imaging;

namespace MyNetworkMonitor.Avalonia.Controls
{
    /// <summary>
    /// Adapter zwischen ADO.NET-DataTables und Avalonias DataGrid.
    ///
    /// WPF bindet DataViews direkt (ueber ICustomTypeDescriptor auf DataRowView).
    /// Avalonia kennt das nicht: es reflektiert ueber die Item-Eigenschaften und
    /// scheitert am mehrdeutigen Indexer von DataRowView ([int] und [string]),
    /// weshalb Zeilen zwar erscheinen, die Zellen aber leer bleiben.
    /// Darum wird jede Zeile in einen <see cref="DataRowProxy"/> mit genau einem
    /// String-Indexer verpackt; gebunden wird dann auf "[Spaltenname]".
    /// </summary>
    public static class DataTableGridSource
    {
        /// <summary>
        /// Erzeugt die Spalten aus der DataTable und haengt die View als
        /// ItemsSource an. Nur-lesbare Spalten bleiben nur-lesbar.
        ///
        /// Gebunden wird ueber eine <see cref="DataGridCollectionView"/>, damit die
        /// Gruppierung spaeter zur Laufzeit ein- und ausgeschaltet werden kann
        /// (WPF: CollectionViewSource.GroupDescriptions) - siehe
        /// <see cref="SetGrouping"/>.
        /// </summary>
        /// <param name="hiddenColumns">
        /// Spalten, die im WPF-Original ueber AutoGeneratingColumn auf
        /// Visibility.Hidden gesetzt werden (z.B. IPGroupDescription, IPToSort).
        /// Sie werden erzeugt - die Gruppierung braucht ihre Werte - aber
        /// nicht angezeigt.
        /// </param>
        /// <param name="sortOverrides">
        /// Spalten, die nach dem Wert einer anderen Spalte sortieren sollen
        /// (WPF: dgv_Results_Sorting sortiert die Spalte "IP" ueber "IPToSort").
        /// </param>
        /// <param name="tabularColumns">
        /// Spalten, deren Werte mit Tabulatoren gegliedert sind und spaltenweise
        /// ausgerichtet dargestellt werden sollen (SNMPInfos, Dienste, LookUpIPs)
        /// - siehe <see cref="TabularTextPresenter"/>.
        /// </param>
        public static DataGridCollectionView Bind(DataGrid grid, DataView view,
                                                  IEnumerable<string>? hiddenColumns = null,
                                                  IReadOnlyDictionary<string, string>? sortOverrides = null,
                                                  IEnumerable<string>? tabularColumns = null)
        {
            var hidden = new HashSet<string>(hiddenColumns ?? Enumerable.Empty<string>(),
                                             StringComparer.OrdinalIgnoreCase);
            var tabular = new HashSet<string>(tabularColumns ?? Enumerable.Empty<string>(),
                                              StringComparer.OrdinalIgnoreCase);

            grid.AutoGenerateColumns = false;
            grid.Columns.Clear();

            // Bezugspunkt fuer die gemeinsamen Spaltenbreiten der Zellen aus
            // CreateTabularColumn - ohne einen solchen Bereich im Vorfahrenbaum
            // wirkt SharedSizeGroup nicht.
            if (tabular.Count > 0) grid.SetValue(Grid.IsSharedSizeScopeProperty, true);

            foreach (DataColumn column in view.Table!.Columns)
            {
                DataGridColumn gridColumn = tabular.Contains(column.ColumnName)
                    ? CreateTabularColumn(column.ColumnName)
                    : CreateColumn(column);
                gridColumn.IsVisible = !hidden.Contains(column.ColumnName);

                // Avalonia leitet den Sortierpfad aus der Bindung ab und kann mit
                // dem Indexer "[Spalte]" nichts anfangen - ohne eigenen Comparer
                // waeren die Spalten nicht sortierbar.
                string sortColumn = sortOverrides != null && sortOverrides.TryGetValue(column.ColumnName, out string? o)
                                  ? o : column.ColumnName;
                gridColumn.CustomSortComparer = new DataRowColumnComparer(sortColumn);

                // Auto = Maximum aus Kopfzeile und Zellinhalten: die Spalte ist
                // damit immer breit genug, dass beides vollstaendig lesbar ist.
                gridColumn.Width = DataGridLength.Auto;

                grid.Columns.Add(gridColumn);
            }

            var collectionView = new DataGridCollectionView(new DataViewProxyCollection(view));
            grid.ItemsSource = collectionView;
            return collectionView;
        }

        /// <summary>
        /// Setzt die Gruppierung einer bereits gebundenen View neu. Ohne
        /// Spaltennamen wird die Gruppierung entfernt.
        /// </summary>
        public static void SetGrouping(DataGridCollectionView? collectionView, params string[] groupByColumns)
        {
            if (collectionView == null) return;

            using (collectionView.DeferRefresh())
            {
                collectionView.GroupDescriptions.Clear();
                foreach (string column in groupByColumns)
                {
                    collectionView.GroupDescriptions.Add(new DataRowGroupDescription(column));
                }
            }
        }

        /// <summary>
        /// Wie <see cref="Bind(DataGrid, DataView)"/>, gruppiert die Zeilen aber
        /// zusaetzlich nach einer Spalte (WPF: GroupStyle / PropertyGroupDescription).
        /// Die vorhandenen Spalten des Grids bleiben erhalten, wenn
        /// <paramref name="keepColumns"/> gesetzt ist (z.B. Tab "Services",
        /// dessen Spalten im AXAML definiert sind).
        /// </summary>
        public static DataGridCollectionView BindGrouped(DataGrid grid, DataView view,
                                                         string groupByColumn, bool keepColumns = false)
        {
            if (!keepColumns)
            {
                grid.AutoGenerateColumns = false;
                grid.Columns.Clear();
                foreach (DataColumn column in view.Table!.Columns)
                {
                    grid.Columns.Add(CreateColumn(column));
                }
            }

            var collectionView = new DataGridCollectionView(new DataViewProxyCollection(view));
            collectionView.GroupDescriptions.Add(new DataRowGroupDescription(groupByColumn));
            grid.ItemsSource = collectionView;
            return collectionView;
        }

        private static DataGridColumn CreateColumn(DataColumn column)
        {
            var binding = new Binding($"[{column.ColumnName}]") { Mode = BindingMode.TwoWay };

            DataGridColumn gridColumn =
                  column.DataType == typeof(bool) ? new DataGridCheckBoxColumn { Header = column.ColumnName, Binding = binding }
                : column.DataType == typeof(byte[]) ? CreateImageColumn(column.ColumnName)
                : CreateTextColumn(column.ColumnName, binding);

            gridColumn.IsReadOnly = column.ReadOnly;

            // Kopfzeile und Zellinhalt sollen immer vollstaendig lesbar sein
            gridColumn.Width = DataGridLength.Auto;

            return gridColumn;
        }

        /// <summary>
        /// Textspalte wie in WPF: vertikal zentriert und ohne Zeilenumbruch.
        /// Mehrzeilige Werte (z.B. SNMPInfos) behalten ihre eigenen Umbrueche;
        /// die Zeile waechst mit, weil das Grid keine feste RowHeight hat.
        /// </summary>
        private static DataGridTextColumn CreateTextColumn(string columnName, Binding binding)
        {
            var column = new DataGridTextColumn { Header = columnName, Binding = binding };

            column.CellTheme = new ControlTheme(typeof(DataGridCell))
            {
                Setters =
                {
                    new Setter(DataGridCell.VerticalContentAlignmentProperty, VerticalAlignment.Center)
                }
            };

            return column;
        }

        /// <summary>
        /// Spalte fuer mit Tabulatoren gegliederte Mehrzeilenwerte. Statt eines
        /// TextBlocks (der Tabulatoren nicht als Tabstopps setzt) rendert
        /// <see cref="TabularTextPresenter"/> die Werte spaltenweise ausgerichtet.
        /// </summary>
        private static DataGridTemplateColumn CreateTabularColumn(string columnName)
        {
            return new DataGridTemplateColumn
            {
                Header = columnName,
                IsReadOnly = true,
                CellTemplate = new FuncDataTemplate<DataRowProxy>((_, _) =>
                    new TabularTextPresenter
                    {
                        Margin = new Thickness(4, 2, 4, 2),
                        // Alle Zellen dieser Spalte teilen sich ihre Breiten,
                        // damit z.B. die Ports der Dienste ueber alle Zeilen
                        // hinweg untereinander stehen.
                        SharedSizeGroupName = columnName,
                        [!TabularTextPresenter.TextProperty] = new Binding($"[{columnName}]")
                    },
                    supportsRecycling: true)
            };
        }

        /// <summary>
        /// Status-Spalten (ARPStatus, PingStatus, SSDPStatus, IsIPCam, LookUpStatus)
        /// enthalten PNG-Bytes. WPF zeigt sie ueber ein DataTemplate als 16x16-Bild;
        /// ohne eigene Spalte stuende hier nur "System.Byte[]".
        /// </summary>
        private static DataGridTemplateColumn CreateImageColumn(string columnName)
        {
            return new DataGridTemplateColumn
            {
                Header = columnName,
                IsReadOnly = true,
                CellTemplate = new FuncDataTemplate<DataRowProxy>((_, _) =>
                    new Image
                    {
                        Width = 16,
                        Height = 16,
                        Stretch = Stretch.Uniform,
                        [!Image.SourceProperty] = new Binding($"[{columnName}]")
                        {
                            Converter = ByteArrayToBitmapConverter.Instance
                        }
                    },
                    supportsRecycling: true)
            };
        }
    }

    /// <summary>
    /// Vergleicht zwei Zeilen anhand einer DataTable-Spalte. Wird als
    /// <see cref="DataGridColumn.CustomSortComparer"/> gesetzt, weil Avalonia
    /// den Indexer-Zugriff des Zeilen-Proxys nicht ueber einen Property-Pfad
    /// erreicht.
    /// </summary>
    public sealed class DataRowColumnComparer : System.Collections.IComparer
    {
        private readonly string _columnName;

        public DataRowColumnComparer(string columnName) => _columnName = columnName;

        public int Compare(object? x, object? y)
        {
            object? left = (x as DataRowProxy)?[_columnName];
            object? right = (y as DataRowProxy)?[_columnName];

            if (left == null && right == null) return 0;
            if (left == null) return -1;
            if (right == null) return 1;

            if (left is IComparable comparable && left.GetType() == right.GetType())
            {
                return comparable.CompareTo(right);
            }

            return string.Compare(left.ToString(), right.ToString(), StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Zeilenhintergruende der beiden Tabellen. WPF loest das ueber
    /// DataGridRow-Styles mit DataTriggern; Avalonias DataGrid kennt keine
    /// DataTrigger, deshalb wird die Farbe im LoadingRow-Ereignis gesetzt.
    /// Wichtig: Avalonia recycelt Zeilen, darum muss immer auch der
    /// Normalfall (<see cref="None"/>) explizit zurueckgesetzt werden.
    /// </summary>
    public static class RowBrushes
    {
        public static readonly IBrush None = Brushes.Transparent;

        // Ergebnistabelle (dgv_Results_LoadingRow im WPF-Original)
        public static readonly IBrush DuplicateInternalName = Brushes.LightGreen;
        public static readonly IBrush DuplicateIP = Brushes.Orange;
        public static readonly IBrush DuplicateHostname = Brushes.DarkOrange;
        public static readonly IBrush DuplicateMac = new SolidColorBrush(Color.FromRgb(0xC7, 0x3D, 0x3D));
        public static readonly IBrush DuplicateMacForeground = Brushes.WhiteSmoke;

        public static readonly IBrush DefaultForeground = Brushes.Black;

        /// <summary>
        /// Uebersetzt die in der Spalte "RowColor" abgelegten Farbnamen der
        /// internen Namen (Red / Yellow / LightGreen / #C5EDC9).
        /// </summary>
        public static IBrush FromRowColor(string? rowColor)
        {
            if (string.IsNullOrEmpty(rowColor)) return None;

            try { return new SolidColorBrush(Color.Parse(rowColor)); }
            catch (Exception) { return None; }
        }
    }

    /// <summary>
    /// Wandelt die PNG-Bytes der Status-Spalten in ein Avalonia-Bitmap.
    /// Die Ergebnisse werden pro Byte-Array-Instanz zwischengespeichert, da
    /// dieselben Icons in sehr vielen Zeilen vorkommen.
    /// </summary>
    public sealed class ByteArrayToBitmapConverter : IValueConverter
    {
        public static readonly ByteArrayToBitmapConverter Instance = new();

        private readonly ConditionalWeakTable<byte[], Bitmap> _cache = new();

        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is not byte[] bytes || bytes.Length == 0) return null;

            if (_cache.TryGetValue(bytes, out Bitmap? cached)) return cached;

            try
            {
                using var stream = new MemoryStream(bytes);
                var bitmap = new Bitmap(stream);
                _cache.Add(bytes, bitmap);
                return bitmap;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    /// <summary>
    /// Gruppierung nach einer DataTable-Spalte. Eine eigene Ableitung ist noetig,
    /// weil DataGridPathGroupDescription ueber einen Property-Pfad reflektiert und
    /// der Indexer-Zugriff des Zeilen-Proxys damit nicht erreichbar ist.
    /// </summary>
    public sealed class DataRowGroupDescription : DataGridGroupDescription
    {
        private readonly string _columnName;

        public DataRowGroupDescription(string columnName) => _columnName = columnName;

        public override string PropertyName => _columnName;

        public override object GroupKeyFromItem(object item, int level, CultureInfo culture)
            => (item as DataRowProxy)?[_columnName]?.ToString() ?? string.Empty;
    }

    /// <summary>
    /// Haelt eine DataView als beobachtbare Liste von <see cref="DataRowProxy"/>
    /// nach; Aenderungen der View (Filter, neue Zeilen, Sortierung) werden
    /// moeglichst inkrementell nachgezogen.
    /// </summary>
    public sealed class DataViewProxyCollection : ObservableCollection<DataRowProxy>
    {
        private readonly DataView _view;

        public DataViewProxyCollection(DataView view)
        {
            _view = view;
            Rebuild();
            _view.ListChanged += OnListChanged;
        }

        public void Rebuild()
        {
            Clear();
            foreach (DataRowView rowView in _view)
            {
                Add(new DataRowProxy(rowView.Row));
            }
        }

        private void OnListChanged(object? sender, ListChangedEventArgs e)
        {
            switch (e.ListChangedType)
            {
                case ListChangedType.ItemAdded when e.NewIndex >= 0 && e.NewIndex <= Count:
                    Insert(e.NewIndex, new DataRowProxy(_view[e.NewIndex].Row));
                    break;

                case ListChangedType.ItemDeleted when e.NewIndex >= 0 && e.NewIndex < Count:
                    RemoveAt(e.NewIndex);
                    break;

                case ListChangedType.ItemChanged when e.NewIndex >= 0 && e.NewIndex < Count:
                    // Geaenderte Zellen (z.B. die Status-Punkte waehrend eines
                    // Scans) muessen nachgezogen werden. Wichtig: den Proxy dabei
                    // NICHT austauschen. Ein Austausch meldet eine Collection-
                    // Aenderung, das DataGrid baut die Zeile neu auf, dabei
                    // schreibt eine TwoWay-Bindung wieder in die DataRow (etwa
                    // die CheckBox-Spalten der IP-Gruppen auf einen DBNull-Wert)
                    // - und das loeste erneut ItemChanged aus: Endlosschleife bis
                    // zum StackOverflow. Eine Benachrichtigung am vorhandenen
                    // Proxy aktualisiert die Zellen ohne Zeilenneuaufbau.
                    this[e.NewIndex].NotifyAllChanged();
                    break;

                default:
                    Rebuild();
                    break;
            }
        }
    }

    /// <summary>
    /// Zeilen-Wrapper mit genau einem String-Indexer, damit Avalonia die Bindung
    /// "[Spaltenname]" eindeutig aufloesen kann.
    /// </summary>
    public sealed class DataRowProxy : INotifyPropertyChanged
    {
        public DataRowProxy(DataRow row) => Row = row;

        public DataRow Row { get; }

        public object? this[string columnName]
        {
            get
            {
                if (!Row.Table.Columns.Contains(columnName)) return null;
                object value = Row[columnName];
                return value == DBNull.Value ? null : value;
            }
            set
            {
                if (!Row.Table.Columns.Contains(columnName)) return;

                object newValue = value ?? DBNull.Value;

                // Beim Aufbau einer Zeile schreiben die TwoWay-Bindungen ihren
                // Ausgangswert zurueck. Ohne diese Pruefung gilt die DataRow als
                // geaendert, die DataView meldet ItemChanged und das Grid baut
                // die Zeile neu auf - eine Schleife ohne echte Aenderung.
                if (Equals(Row[columnName], newValue)) return;

                Row[columnName] = newValue;
                NotifyChanged(columnName);
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public void NotifyAllChanged()
        {
            // "Item[]" ist die uebliche Sammelbenachrichtigung fuer Indexer
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));

            foreach (DataColumn column in Row.Table.Columns)
            {
                NotifyChanged(column.ColumnName);
            }
        }

        private void NotifyChanged(string columnName)
        {
            // Avalonia erkennt Indexer-Aenderungen je nach Bindungsart ueber den
            // konkreten Namen oder ueber die Sammelbenachrichtigung "Item[]" -
            // ohne beides bleiben z.B. die Status-Punkte auf dem alten Bild stehen.
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs($"Item[{columnName}]"));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        }
    }
}
