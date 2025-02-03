using Microsoft.AspNetCore.Mvc;

namespace SecurityApi.Controllers;

[ApiController]
public class SecurityController : ControllerBase
{
    private readonly ILogger<SecurityController> _logger;
    private readonly IConfiguration _config;

    public SecurityController(ILogger<SecurityController> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
    }

    [HttpGet]
    [Route("api/getcamerastatus")]
    public string GetCameraStatus(string securityToken)
    {
        if (!ValidateSecurityToken(securityToken))
        {
            throw new ArgumentException("Invalid security token.");
        }

        string status = "disabled";

        try
        {
            using (var sr = new StreamReader("CameraStatus.txt"))
            {
                status = sr.ReadToEnd();
            }
        }
        catch (Exception exc) { }

        return status;
    }

    // [HttpGet]
    // [Route("api/getcameraimage")]
    // public string GetCameraImage(string securityToken, int imageId)
    // {
    //     string imagePath = string.Empty;

    //     try
    //     {
    //         if (!ValidateSecurityToken(securityToken))
    //         {
    //             throw new ArgumentException("Invalid security token.");
    //         }

    //         string cameraStatus = string.Empty;

    //         using (var sr = new StreamReader("CameraStatus.txt"))
    //         {
    //             cameraStatus = sr.ReadToEnd();
    //         }

    //         if (cameraStatus.Contains("disabled"))
    //         {
    //             return cameraStatus;
    //         }

    //         imagePath = _config.GetValue<string>("ImageUrl");

    //         if (imageId == 1)
    //         {
    //             imagePath = imagePath + "6e19cc19829a4ff89eb54bf5a979c5cd.jpg";
    //         }
    //         else if (imageId == 2)
    //         {
    //             imagePath = imagePath + "794ac710948f4b90b7b22743650dde11.jpg";
    //         }
    //         else if (imageId == 3)
    //         {
    //             imagePath = imagePath + "d42d6b758fce495a9ac9e32466704c2f.jpg";
    //         }
    //         else if (imageId == 4)
    //         {
    //             imagePath = imagePath + "4c4c2b739c4b4c9eb864540cf2423bda.jpg";
    //         }
    //         else if (imageId == 5)
    //         {
    //             imagePath = imagePath + "74e0cc74c8be4679a9c917edb9987d02.jpg";
    //         }
    //     }
    //     catch (Exception exc)
    //     {
    //         using (var sr = new StreamWriter("ErrorLog.txt", append: true))
    //         {
    //             sr.WriteLine(exc.Message + Environment.NewLine + exc.StackTrace);
    //         }
    //     }

    //     return imagePath;
    // }

    [HttpPost]
    [Route("api/disablecameras")]
    public bool DisableCameras([FromBody] string securityToken)
    {
        if (!ValidateSecurityToken(securityToken))
        {
            throw new ArgumentException("Invalid security token.");
        }

        using (var sr = new StreamWriter("CameraStatus.txt"))
        {
            sr.WriteLine("disabled");
        }

        return true;
    }

    [HttpPost]
    [Route("api/enablecameras")]
    public bool EnableCameras([FromBody] string securityToken)
    {
        if (!ValidateSecurityToken(securityToken))
        {
            throw new ArgumentException("Invalid security token.");
        }

        using (var sr = new StreamWriter("CameraStatus.txt"))
        {
            sr.WriteLine("enabled");
        }

        return true;
    }

    private bool ValidateSecurityToken(string securityToken)
    {
        if (string.IsNullOrWhiteSpace(securityToken))
        {
            return false;
        }

        var secToken = _config.GetValue<string>("SecurityToken");

        if (string.IsNullOrWhiteSpace(secToken))
        {
            return false;
        }
        else
        {
            if (securityToken == secToken)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
