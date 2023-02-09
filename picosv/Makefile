VENDOR=PICA8
NAME=PicOS-V
IMAGE_FORMAT=qcow2
IMAGE_GLOB=*.qcow2

# match versions like:
# picos-4.3.1-2f9c70c4ee-x86v.qcow2
VERSION=$(shell echo $(IMAGE) | sed -rn 's/picos-(.+)-(.+)-(.+)\..*/\1/p')

-include ../makefile-sanity.include
-include ../makefile.include
