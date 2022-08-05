
variable "boot_wait" {
  type      = string
  default   = "5s"
}

variable "disk_size" {
  type      = string
  default   = "61440"
}

variable "iso_checksum" {
  type      = string
  default   = "sha256:69efac1df9ec8066341d8c9b62297ddece0e6b805533fdb6dd66bc8034fba27a"
}

variable "iso_url" {
  type      = string
  default   = "https://software-download.microsoft.com/download/sg/444969d5-f34g-4e03-ac9d-1f9786c69161/19044.1288.211006-0501.21h2_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso"
}

variable "memsize" {
  type      = string
  default   = "4096"
}

variable "numvcpus" {
  type      = string
  default   = "2"
}

variable "vm_name" {
  type      = string
  default   = "pc4-win10"
}

variable "winrm_password" {
  type      = string
  default   = "tartans"
}

variable "winrm_username" {
  type      = string
  default   = "Administrator"
}


source "virtualbox-iso" "pc4-win10" {
  boot_wait               = "${var.boot_wait}"
  communicator            = "winrm"
  disk_size               = "${var.disk_size}"
  floppy_files            = ["scripts/bios/autounattend.xml"]
  guest_os_type           = "Windows10_64"
  headless                = false
  http_directory          = "./scriptfiles"
  iso_checksum            = "${var.iso_checksum}"
  iso_url                 = "${var.iso_url}"
  shutdown_command        = "shutdown /s /t 5 /f /d p:4:1 /c \"Packer Shutdown\""
  shutdown_timeout        = "30m"
  vm_name                 = "${var.vm_name}"
  memory                  = "${var.memsize}"
  cpus                    = "${var.numvcpus}"
  gfx_controller          = "vmsvga"
  gfx_vram_size           = 32
  winrm_insecure          = true
  winrm_password          = "${var.winrm_password}"
  winrm_timeout           = "4h"
  winrm_use_ssl           = true
  winrm_username          = "${var.winrm_username}"
}



build {
  sources             = ["source.virtualbox-iso.pc4-win10"]

  provisioner "file" {
    sources           = ["scriptfiles/vscode_extensions.txt", "scriptfiles/pip_packages.txt", "scriptfiles/chocolatey_packages.txt", "scriptfiles/tools_README.txt", "scriptfiles/PC2022-Win10-Background-4k.jpg", "scriptfiles/challenge-root-ca.pem", "scriptfiles/change_hostname.ps1", "scriptfiles/wallpaper.ps1"]
    destination       = "C:\\"
  }

  provisioner "powershell" {
    pause_before      = "1m0s"
    scripts           = ["scripts/vmware-tools.ps1"]
  }

  provisioner "windows-restart" {
    restart_timeout   = "30m"
  }

  provisioner "powershell" {
    scripts           = ["scripts/setup.ps1"]
  }

  provisioner "windows-restart" {
    restart_timeout   = "30m"
  }

  provisioner "powershell" {
    scripts           = ["scripts/win-update.ps1"]
  }

  provisioner "windows-restart" {
    restart_timeout   = "30m"
  }

  provisioner "powershell" {
    pause_before      = "1m0s"
    scripts           = ["scripts/cert.ps1", "scripts/app_install_1.ps1"]
    elevated_user     = "${var.winrm_username}"
    elevated_password = "${var.winrm_password}"
  }

  provisioner "windows-restart" {
    restart_timeout   = "30m"
  }

  provisioner "powershell" {
    pause_before      = "1m0s"
    scripts           = ["scripts/app_install_2.ps1"]
    elevated_user     = "${var.winrm_username}"
    elevated_password = "${var.winrm_password}"
  }

  provisioner "windows-restart" {
    restart_timeout   = "30m"
  }

  provisioner "powershell" {
    pause_before      = "1m0s"
    scripts           = ["scripts/cleanup.ps1"]
  }

  provisioner "windows-restart" {
    restart_timeout   = "30m"
  }

  provisioner "powershell"{
    pause_before      = "1m0s"
    scripts           = ["scripts/schedule_tasks.ps1"]
  }
}
