/*
 This Packer build will download and install a basic Kali VM
*/

source "virtualbox-iso" "pc4-kali" {
  boot_command        = [
    "<esc><wait>",
    "install ",
    "preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
    "debian-installer=en_US auto locale=en_US kbd-chooser/method=us <wait>",
    "netcfg/get_hostname={{ .Name }} ",
    "netcfg/get_domain=local ",
    "fb=false debconf/frontend=noninteractive ",
    "console-setup/ask_detect=false <wait> ",
    "console-keymaps-at/keymap=us ",
    "keyboard-configuration/xkb-keymap=us <wait> ",
    "<enter><wait> "
]
  boot_wait           = "10s"
  cpus                = 2
  disk_size           = 50000
  memory              = 4096
  gfx_controller      = "vmsvga"
  gfx_vram_size       = 32
  guest_os_type       = "Debian_64"
  headless            = false
  http_directory      = "http"
  iso_checksum        = "eee4eab603b10a0618e1900159cb91b8969bf13107e5d834381ecb21a560e149"
  iso_urls            = ["https://cdimage.kali.org/kali-2022.2/kali-linux-2022.2-live-amd64.iso"]
  shutdown_command    = "sudo shutdown -P now"
  ssh_password        = "tartans"
  ssh_port            = 22
  ssh_username        = "user"
  ssh_wait_timeout    = "10000s"
  vm_name             = "pc4-kali"
  guest_additions_mode    = "attach"

}

build {
  sources = ["source.virtualbox-iso.pc4-kali"]

  provisioner "shell" {
      inline = ["sudo mkdir -p /usr/tmp; sudo chmod 0777 /usr/tmp"]
  }

  provisioner "file" {
    source = "files/"
    destination = "/usr/tmp/"
  }

  // run script to install tools
  provisioner "shell" {
    execute_command   = "echo 'tartans' | sudo -S sh '{{ .Path }}'"
    scripts           = ["scripts/base_install.sh"]
    environment_vars  = ["DEBIAN_FRONTEND=noninteractive"]
  }

  // run script to set wallpaper to prescup image
  provisioner "shell" {
    scripts           = ["scripts/wallpaper.sh"]
  }
}
