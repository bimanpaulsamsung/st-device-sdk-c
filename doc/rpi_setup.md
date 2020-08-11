# Setup and Build SmartThings SDK on Raspberry Pi

This version of STDK works on Raspberry Pi 4 model-B running Ubuntu Server 20.04

## Setup

### Initial setup on ubuntu machine

1. Download Ubuntu Server 20.04 from [Ubuntu RPi downloads](https://ubuntu.com/download/raspberry-pi/thank-you?version=20.04&architecture=arm64+raspi).
 
2. Flash Ubuntu image onto an SD card following [installation instructions](https://www.raspberrypi.org/documentation/installation/installing-images/).

3. Clone the stdk source code

   ```sh
   $ cd ~
   $ git clone https://github.com/SmartThingsCommunity/st-device-sdk-c.git
   $ cd st-device-sdk-c
   ```

4. Register device profile using [register a device](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref/blob/master/doc/getting_started.md#register-a-device).

5. Copy the generated `device_info.json` and `onboarding_config.json` files to `example` folder in the STDK directory.

6. Copy STDK directory into SD card.


### Setup on Raspberry Pi

1. Insert SD card into RPi4 and boot the device.

2. After booting, packages needed by STDK can be downloaded either via LAN or Wi-Fi.

   For Wi-Fi, run the following commands to connect to a Wi-Fi network:
   - Check your wireless interface using following command
      ```sh
      $ ls /sys/class/net
      ```
     Note down the name of your wireless interface which begins with 'wl'. Eg: wlan0

   - Edit `/etc/wpa_supplicant.conf` with the following details:

      ```sh
      network={
          ssid="YOUR_WIFI_NETWORK_NAME"
          psk="YOUR_WIFI_PASSWORD"
      }
      ```

   - Connect to your wifi network using appropriate wireless interface

     ```sh
     $ sudo wpa_supplicant -B -i wlan0 –c /etc/wpa_supplicant.conf
     $ sudo dhclient wlan0 -v
     ```

   - To check whether you have connected to the internet use ping.
     ```sh
     $ ping www.google.com
     ```

3. Install the following packages needed for STDK

   ```sh
   $ sudo apt install gcc make psmisc libssl-dev libpthread-stubs0-dev libglib2.0-dev dnsmasq ntp
   ```

4. Edit `/etc/dnsmasq.conf` by uncommenting `bind-interfaces`

5. Edit `/etc/ntp.conf` by replacing pool servers with:

   ```sh
   pool pool.ntp.org iburst
   pool 1.kr.pool.ntp.org iburst
   pool 1.asia.pool.ntp.org iburst
   pool us.pool.ntp.org iburst
   ```

5. Restart dnsmasq and ntp services

   ```sh
   $ sudo systemctl restart dnsmasq ntp
   ```

6. Install the Root CA certificates

   ```sh
   sudo apt install apt-transport-https ca-certificates
   sudo update-ca-certificates
   ```

## Build

1. Enter the STDK directory

   ```sh
   $ cd <STDK folder>
   ```

   **Note:** If you are building for the first time or after reboot then you will face these warnings: "File make has modification time in the future" or "clock skew detected”. So run the following command before building:

   ```sh
   $ find . -exec touch {} \;
   ```

2. Build STDK on Raspberry Pi

   ```sh
   $ make OS=linux
   ```

   **Note:** The first build will download all dependent modules and will require an internet connection.

3. To build and run the example app provided in STDK

   ```
   $ cd example/
   $ make OS=linux
   $ sudo ./example
   ```

Now you will be able to Onboard Raspberry Pi using the ST mobile app

**Note:** If there are problems with connecting to internet via Wi-Fi, use the following command:

```sh
$ sudo killall wpa_supplicant dhclient
```
