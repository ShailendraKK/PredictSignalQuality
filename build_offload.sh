#! /bin/bash -x

compile_flag=0
location=$(pwd)
while getopts 'c' flag; do
  case "${flag}" in
    c) compile_flag=1 ;;
  esac
done

if [[ $compile_flag -eq 1 ]]
then
    # compile the nfp code
    sudo /opt/netronome/p4/bin/nfp4build -o ./p4src/SessionWorking.nffw -p ./p4src/out -4 ./p4src/SessionWorking.p4 -l lithium --nfp4c_p4_version 16 --nfp4c_p4_compiler p4c-nfp --nfirc_mac_ingress_timestamp
fi
# move to p4 bin
cd /opt/netronome/p4/bin/

# #offload
sudo ./rtecli design-load -f $location/p4src/SessionWorking.nffw -p $location/p4src/out/pif_design.json

# returning back to base
cd $location
