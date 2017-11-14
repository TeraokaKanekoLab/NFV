#!/bin/sh

virt-install --virt-type=kvm --name ubuntu16.04 --ram 4096 --vcpus 2 --disk path=/great/hannah/ubuntu_xenial.img,size=100 network bridge=br61 os-type linux --graphics none --console pty,target_type=serial --extra-args 'console=ttyS0,115200n8 serial' --location  'http://jp.archive.ubuntu.com/ubuntu/dists/xenial/main/installer-amd64/'
