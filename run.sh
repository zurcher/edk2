#! /bin/bash
if
  [ $# != 1 ]; then
  echo "Pass TOOL_CHAIN_TAG as only argument!"
  echo "VS2019"
  echo "VS2015x86"
  echo "CLANGPDB"
  echo "GCC5"
else
  #time qemu-system-x86_64 -bios Build/OvmfX64/DEBUG_$@/FV/OVMF.fd -debugcon file:bios.log -global isa-debugcon.iobase=0x402 -nic none -nographic
  time qemu-system-x86_64 -bios Build/OvmfIa32/DEBUG_$@/FV/OVMF.fd -debugcon file:bios.log -global isa-debugcon.iobase=0x402 -nic none -nographic
fi
