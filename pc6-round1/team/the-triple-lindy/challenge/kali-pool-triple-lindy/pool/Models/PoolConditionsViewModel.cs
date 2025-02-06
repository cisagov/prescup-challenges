namespace PoolWeb.Models;

public class PoolConditionsViewModel
{
    public string Message { get; set; } = string.Empty;
    public string Token4 { get; set; } = string.Empty;
    public double pH { get; set; } = 7.5;
    public int TotalAlkalinity { get; set; } = 100;
    public double FreeAvailableChlorine { get; set; } = 3.2;
    public double Bromine { get; set; } = 4.0;
    public int CyanuricAcid { get; set; } = 40;
    public int CalciumHardness { get; set; } = 300;
    public int Metals { get; set; } = 2;
    public int TotalDissolvedSolids { get; set; } = 100;
    public int Phosphates { get; set; } = 0;

    // pH: 7.4-7.6
    // Total Alkalinity: 80-120 ppm
    // Calcium Hardness: 200-400 ppm
    // Free Available Chlorine: 2.0-4.0 ppm
    // Bromine: 3.0-5.0 ppm
    // Cyanuric Acid: 30-50 ppm
    // Metals: 0 ppm
    // Phosphates: 0 ppm
    // Total Dissolved Solids: 0-2500 ppm
}