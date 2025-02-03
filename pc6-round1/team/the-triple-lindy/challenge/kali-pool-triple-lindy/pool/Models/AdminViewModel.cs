namespace PoolWeb.Models;

public class AdminViewModel
{
    public string Message { get; set; } = string.Empty;
    public string Token2 { get; set; } = string.Empty;
    public int MainPoolTemperature { get; set; }
    public int SetMainPoolTemperature { get; set; }
    public string AutomatedPoolManagementUsername { get; set; } = string.Empty;
    public string AutomatedPoolManagementPassword { get; set; } = string.Empty;
}
