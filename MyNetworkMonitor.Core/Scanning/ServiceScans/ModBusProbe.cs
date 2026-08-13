namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Modbus TCP. Steuerungen dieser Art vertragen wenig - darum eine
    /// Verbindung, eine Anfrage, fertig.
    /// </summary>
    public sealed class ModBusProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.ModBus;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [502];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? Modbus TCP-Erkennung
            if (service == ServiceType.ModBus)
            {
                // Modbus TCP Header besteht aus 7 Bytes, der Funktionscode ist das
                // erste Byte danach - also Index 7, und der ist nur gueltig zu lesen,
                // wenn die Antwort mindestens 8 Byte lang ist. Mit ">= 7" warf response[7]
                // bei einer genau 7 Byte langen Antwort eine IndexOutOfRangeException,
                // gefangen von der pauschalen catch-Klausel in FindServicePortAsync und
                // dort als "Fehler" statt als "kein Modbus" verbucht.
                // [0-1] Transaction Identifier (2 Bytes)
                // [2-3] Protocol Identifier (immer 0x00 0x00 für Modbus TCP)
                // [4-5] Length Field (Länge der nachfolgenden Daten)
                // [6]   Unit Identifier
                // [7]   Function Code
                if (response.Length >= 8)
                {
                    // Protokollkennung überprüfen (muss 0x00 0x00 für Modbus TCP sein)
                    bool isModbusTcp = response[2] == 0x00 && response[3] == 0x00;

                    // Funktioncode prüfen: Gültige Modbus-Funktionscodes liegen zwischen 0x01 und 0x10
                    // Beispiele:
                    // 0x01 - Read Coils
                    // 0x02 - Read Discrete Inputs
                    // 0x03 - Read Holding Registers
                    // 0x04 - Read Input Registers
                    // 0x05 - Write Single Coil
                    // 0x06 - Write Single Register
                    // 0x10 - Write Multiple Registers
                    //
                    // Eine Fehlerantwort (Exception Response) traegt denselben
                    // Funktionscode mit gesetztem oberstem Bit, also 0x81-0x90 -
                    // etwa wenn das angefragte Register auf diesem Geraet nicht
                    // existiert. Das ist trotzdem eine Modbus-Antwort und kein
                    // Nichttreffer: das Geraet hat verstanden und geantwortet,
                    // nur eben mit "nein" statt mit Werten.
                    byte functionCode = response[7];
                    bool validFunctionCode = functionCode is >= 0x01 and <= 0x10 or >= 0x81 and <= 0x90;

                    // Wenn sowohl das Protokoll als auch der Funktionscode stimmen, erkennen wir Modbus TCP
                    if (isModbusTcp && validFunctionCode)
                    {
                        serviceMatched = true;
                    }
                }
            }

            return serviceMatched;
        }
    }
}
