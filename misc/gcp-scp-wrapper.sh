#!/bin/bash
# This is a wrapper script allowing to use GCP's IAP option to connect
# to our servers.
# Courtesy of @lotjuh/stackoverflow:)
# Ansible passes a large number of SSH parameters along with the hostname as the
# second to last argument and the command as the last. We will pop the last two
# arguments off of the list and then pass all of the other SSH flags through
# without modification:
host="${@: -2: 1}"
cmd="${@: -1: 1}"
declare -a opts
for scp_arg in "${@: 1: $# -3}" ; do
        if [[ "${scp_arg}" == --* ]] ; then
                opts+="${scp_arg} "
        fi
done

cmd=`echo "${cmd}" | tr -d []`

exec gcloud compute scp $opts "${host}" "${cmd}"