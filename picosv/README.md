# vrnetlab / PICA8 PicOS-V

This is the vrnetlab docker image for PICA8 PicOS-V.

## Building the docker image

Download the PICOS-V image from https://www.pica8.com/picos-v/
Copy the qcow2 image into this folder, then run `make docker-image`.
The resulting images is called `vrnetlab/vr-picosv:VERSION`. You can tag
it with something else if you want, like `my-repo.example.com/vr-picosv`
and then push it to your repo.

Tested booting and responding to SSH:

- picos-4.3.1-2f9c70c4ee-x86v.qcow2


## System requirements

* CPU: 1 core
* RAM: 2GB
* Disk: <4GB

