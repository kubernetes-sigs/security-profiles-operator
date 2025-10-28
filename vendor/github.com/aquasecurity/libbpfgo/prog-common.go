package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

// BPFFunc is an enum as defined in https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h
type BPFFunc uint32

const (
	BPFFuncUnspec BPFFunc = iota
	BPFFuncMapLookupElem
	BPFFuncMapUpdateElem
	BPFFuncMapDeleteElem
	BPFFuncProbeRead
	BPFFuncKtimeGetNs
	BPFFuncTracePrintk
	BPFFuncGetPrandomU32
	BPFFuncGetSmpProcessorId
	BPFFuncSkbStoreBytes
	BPFFuncL3CsumReplace
	BPFFuncL4CsumReplace
	BPFFuncTailCall
	BPFFuncCloneRedirect
	BPFFuncGetCurrentPidTgid
	BPFFuncGetCurrentUidGid
	BPFFuncGetCurrentComm
	BPFFuncGetCgroupClassid
	BPFFuncSkbVlanPush
	BPFFuncSkbVlanPop
	BPFFuncSkbGetTunnelKey
	BPFFuncSkbSetTunnelKey
	BPFFuncPerfEventRead
	BPFFuncRedirect
	BPFFuncGetRouteRealm
	BPFFuncPerfEventOutput
	BPFFuncSkbLoadBytes
	BPFFuncGetStackid
	BPFFuncCsumDiff
	BPFFuncSkbGetTunnelOpt
	BPFFuncSkbSetTunnelOpt
	BPFFuncSkbChangeProto
	BPFFuncSkbChangeType
	BPFFuncSkbUnderCgroup
	BPFFuncGetHashRecalc
	BPFFuncGetCurrentTask
	BPFFuncProbeWriteUser
	BPFFuncCurrentTaskUnderCgroup
	BPFFuncSkbChangeTail
	BPFFuncSkbPullData
	BPFFuncCsumUpdate
	BPFFuncSetHashInvalid
	BPFFuncGetNumaNodeId
	BPFFuncSkbChangeHead
	BPFFuncXdpAdjustHead
	BPFFuncProbeReadStr
	BPFFuncGetSocketCookie
	BPFFuncGetSocketUid
	BPFFuncSetHash
	BPFFuncSetsockopt
	BPFFuncSkbAdjustRoom
	BPFFuncRedirectMap
	BPFFuncSkRedirectMap
	BPFFuncSockMapUpdate
	BPFFuncXdpAdjustMeta
	BPFFuncPerfEventReadValue
	BPFFuncPerfProgReadValue
	BPFFuncGetsockopt
	BPFFuncOverrideReturn
	BPFFuncSockOpsCbFlagsSet
	BPFFuncMsgRedirectMap
	BPFFuncMsgApplyBytes
	BPFFuncMsgCorkBytes
	BPFFuncMsgPullData
	BPFFuncBind
	BPFFuncXdpAdjustTail
	BPFFuncSkbGetXfrmState
	BPFFuncGetStack
	BPFFuncSkbLoadBytesRelative
	BPFFuncFibLookup
	BPFFuncSockHashUpdate
	BPFFuncMsgRedirectHash
	BPFFuncSkRedirectHash
	BPFFuncLwtPushEncap
	BPFFuncLwtSeg6StoreBytes
	BPFFuncLwtSeg6AdjustSrh
	BPFFuncLwtSeg6Action
	BPFFuncRcRepeat
	BPFFuncRcKeydown
	BPFFuncSkbCgroupId
	BPFFuncGetCurrentCgroupId
	BPFFuncGetLocalStorage
	BPFFuncSkSelectReuseport
	BPFFuncSkbAncestorCgroupId
	BPFFuncSkLookupTcp
	BPFFuncSkLookupUdp
	BPFFuncSkRelease
	BPFFuncMapPushElem
	BPFFuncMapPopElem
	BPFFuncMapPeekElem
	BPFFuncMsgPushData
	BPFFuncMsgPopData
	BPFFuncRcPointerRel
	BPFFuncSpinLock
	BPFFuncSpinUnlock
	BPFFuncSkFullsock
	BPFFuncTcpSock
	BPFFuncSkbEcnSetCe
	BPFFuncGetListenerSock
	BPFFuncSkcLookupTcp
	BPFFuncTcpCheckSyncookie
	BPFFuncSysctlGetName
	BPFFuncSysctlGetCurrentValue
	BPFFuncSysctlGetNewValue
	BPFFuncSysctlSetNewValue
	BPFFuncStrtol
	BPFFuncStrtoul
	BPFFuncSkStorageGet
	BPFFuncSkStorageDelete
	BPFFuncSendSignal
	BPFFuncTcpGenSyncookie
	BPFFuncSkbOutput
	BPFFuncProbeReadUser
	BPFFuncProbeReadKernel
	BPFFuncProbeReadUserStr
	BPFFuncProbeReadKernelStr
	BPFFuncTcpSendAck
	BPFFuncSendSignalThread
	BPFFuncJiffies64
	BPFFuncReadBranchRecords
	BPFFuncGetNsCurrentPidTgid
	BPFFuncXdpOutput
	BPFFuncGetNetnsCookie
	BPFFuncGetCurrentAncestorCgroupId
	BPFFuncSkAssign
	BPFFuncKtimeGetBootNs
	BPFFuncSeqPrintf
	BPFFuncSeqWrite
	BPFFuncSkCgroupId
	BPFFuncSkAncestorCgroupId
	BPFFuncRingbufOutput
	BPFFuncRingbufReserve
	BPFFuncRingbufSubmit
	BPFFuncRingbufDiscard
	BPFFuncRingbufQuery
	BPFFuncCsumLevel
	BPFFuncSkcToTcp6Sock
	BPFFuncSkcToTcpSock
	BPFFuncSkcToTcpTimewaitSock
	BPFFuncSkcToTcpRequestSock
	BPFFuncSkcToUdp6Sock
	BPFFuncGetTaskStack
	BPFFuncLoadHdrOpt
	BPFFuncStoreHdrOpt
	BPFFuncReserveHdrOpt
	BPFFuncInodeStorageGet
	BPFFuncInodeStorageDelete
	BPFFuncDPath
	BPFFuncCopyFromUser
	BPFFuncSnprintfBtf
	BPFFuncSeqPrintfBtf
	BPFFuncSkbCgroupClassid
	BPFFuncRedirectNeigh
	BPFFuncPerCpuPtr
	BPFFuncThisCpuPtr
	BPFFuncRedirectPeer
	BPFFuncTaskStorageGet
	BPFFuncTaskStorageDelete
	BPFFuncGetCurrentTaskBtf
	BPFFuncBprmOptsSet
	BPFFuncKtimeGetCoarseNs
	BPFFuncImaInodeHash
	BPFFuncSockFromFile
	BPFFuncCheckMtu
	BPFFuncForEachMapElem
	BPFFuncSnprintf
	BPFFuncSysBpf
	BPFFuncBtfFindByNameKind
	BPFFuncSysClose
	BPFFuncTimerInit
	BPFFuncTimerSetCallback
	BPFFuncTimerStart
	BPFFuncTimerCancel
	BPFFuncGetFuncIp
	BPFFuncGetAttachCookie
	BPFFuncTaskPtRegs
	BPFFuncGetBranchSnapshot
	BPFFuncTraceVprintk
	BPFFuncSkcToUnixSock
	BPFFuncKallsymsLookupName
	BPFFuncFindVma
	BPFFuncLoop
	BPFFuncStrncmp
	BPFFuncGetFuncArg
	BPFFuncGetFuncRet
	BPFFuncGetFuncArgCnt
	BPFFuncGetRetval
	BPFFuncSetRetval
	BPFFuncXdpGetBuffLen
	BPFFuncXdpLoadBytes
	BPFFuncXdpStoreBytes
	BPFFuncCopyFromUserTask
	BPFFuncSkbSetTstamp
	BPFFuncImaFileHash
	BPFFuncKptrXchg
	BPFFuncMapLookupPercpuElem
	BPFFuncSkcToMptcpSock
	BPFFuncDynptrFromMem
	BPFFuncRingbufReserveDynptr
	BPFFuncRingbufSubmitDynptr
	BPFFuncRingbufDiscardDynptr
	BPFFuncDynptrRead
	BPFFuncDynptrWrite
	BPFFuncDynptrData
	BPFFuncTcpRawGenSyncookieIpv4
	BPFFuncTcpRawGenSyncookieIpv6
	BPFFuncTcpRawCheckSyncookieIpv4
	BPFFuncTcpRawCheckSyncookieIpv6
	BPFFuncKtimeGetTaiNs
	BPFFuncUserRingbufDrain
	BPFFuncCgrpStorageGet
	BPFFuncCgrpStorageDelete
)

func (b BPFFunc) Value() uint64 {
	return uint64(b)
}

func (b BPFFunc) String() string {
	x := map[BPFFunc]string{
		BPFFuncUnspec:                     "unspec",
		BPFFuncMapLookupElem:              "map_lookup_elem",
		BPFFuncMapUpdateElem:              "map_update_elem",
		BPFFuncMapDeleteElem:              "map_delete_elem",
		BPFFuncProbeRead:                  "probe_read",
		BPFFuncKtimeGetNs:                 "ktime_get_ns",
		BPFFuncTracePrintk:                "trace_printk",
		BPFFuncGetPrandomU32:              "get_prandom_u32",
		BPFFuncGetSmpProcessorId:          "get_smp_processor_id",
		BPFFuncSkbStoreBytes:              "skb_store_bytes",
		BPFFuncL3CsumReplace:              "l3_csum_replace",
		BPFFuncL4CsumReplace:              "l4_csum_replace",
		BPFFuncTailCall:                   "tail_call",
		BPFFuncCloneRedirect:              "clone_redirect",
		BPFFuncGetCurrentPidTgid:          "get_current_pid_tgid",
		BPFFuncGetCurrentUidGid:           "get_current_uid_gid",
		BPFFuncGetCurrentComm:             "get_current_comm",
		BPFFuncGetCgroupClassid:           "get_cgroup_classid",
		BPFFuncSkbVlanPush:                "skb_vlan_push",
		BPFFuncSkbVlanPop:                 "skb_vlan_pop",
		BPFFuncSkbGetTunnelKey:            "skb_get_tunnel_key",
		BPFFuncSkbSetTunnelKey:            "skb_set_tunnel_key",
		BPFFuncPerfEventRead:              "perf_event_read",
		BPFFuncRedirect:                   "redirect",
		BPFFuncGetRouteRealm:              "get_route_realm",
		BPFFuncPerfEventOutput:            "perf_event_output",
		BPFFuncSkbLoadBytes:               "skb_load_bytes",
		BPFFuncGetStackid:                 "get_stackid",
		BPFFuncCsumDiff:                   "csum_diff",
		BPFFuncSkbGetTunnelOpt:            "skb_get_tunnel_opt",
		BPFFuncSkbSetTunnelOpt:            "skb_set_tunnel_opt",
		BPFFuncSkbChangeProto:             "skb_change_proto",
		BPFFuncSkbChangeType:              "skb_change_type",
		BPFFuncSkbUnderCgroup:             "skb_under_cgroup",
		BPFFuncGetHashRecalc:              "get_hash_recalc",
		BPFFuncGetCurrentTask:             "get_current_task",
		BPFFuncProbeWriteUser:             "probe_write_user",
		BPFFuncCurrentTaskUnderCgroup:     "current_task_under_cgroup",
		BPFFuncSkbChangeTail:              "skb_change_tail",
		BPFFuncSkbPullData:                "skb_pull_data",
		BPFFuncCsumUpdate:                 "csum_update",
		BPFFuncSetHashInvalid:             "set_hash_invalid",
		BPFFuncGetNumaNodeId:              "get_numa_node_id",
		BPFFuncSkbChangeHead:              "skb_change_head",
		BPFFuncXdpAdjustHead:              "xdp_adjust_head",
		BPFFuncProbeReadStr:               "probe_read_str",
		BPFFuncGetSocketCookie:            "get_socket_cookie",
		BPFFuncGetSocketUid:               "get_socket_uid",
		BPFFuncSetHash:                    "set_hash",
		BPFFuncSetsockopt:                 "setsockopt",
		BPFFuncSkbAdjustRoom:              "skb_adjust_room",
		BPFFuncRedirectMap:                "redirect_map",
		BPFFuncSkRedirectMap:              "sk_redirect_map",
		BPFFuncSockMapUpdate:              "sock_map_update",
		BPFFuncXdpAdjustMeta:              "xdp_adjust_meta",
		BPFFuncPerfEventReadValue:         "perf_event_read_value",
		BPFFuncPerfProgReadValue:          "perf_prog_read_value",
		BPFFuncGetsockopt:                 "getsockopt",
		BPFFuncOverrideReturn:             "override_return",
		BPFFuncSockOpsCbFlagsSet:          "sock_ops_cb_flags_set",
		BPFFuncMsgRedirectMap:             "msg_redirect_map",
		BPFFuncMsgApplyBytes:              "msg_apply_bytes",
		BPFFuncMsgCorkBytes:               "msg_cork_bytes",
		BPFFuncMsgPullData:                "msg_pull_data",
		BPFFuncBind:                       "bind",
		BPFFuncXdpAdjustTail:              "xdp_adjust_tail",
		BPFFuncSkbGetXfrmState:            "skb_get_xfrm_state",
		BPFFuncGetStack:                   "get_stack",
		BPFFuncSkbLoadBytesRelative:       "skb_load_bytes_relative",
		BPFFuncFibLookup:                  "fib_lookup",
		BPFFuncSockHashUpdate:             "sock_hash_update",
		BPFFuncMsgRedirectHash:            "msg_redirect_hash",
		BPFFuncSkRedirectHash:             "sk_redirect_hash",
		BPFFuncLwtPushEncap:               "lwt_push_encap",
		BPFFuncLwtSeg6StoreBytes:          "lwt_seg6_store_bytes",
		BPFFuncLwtSeg6AdjustSrh:           "lwt_seg6_adjust_srh",
		BPFFuncLwtSeg6Action:              "lwt_seg6_action",
		BPFFuncRcRepeat:                   "rc_repeat",
		BPFFuncRcKeydown:                  "rc_keydown",
		BPFFuncSkbCgroupId:                "skb_cgroup_id",
		BPFFuncGetCurrentCgroupId:         "get_current_cgroup_id",
		BPFFuncGetLocalStorage:            "get_local_storage",
		BPFFuncSkSelectReuseport:          "sk_select_reuseport",
		BPFFuncSkbAncestorCgroupId:        "skb_ancestor_cgroup_id",
		BPFFuncSkLookupTcp:                "sk_lookup_tcp",
		BPFFuncSkLookupUdp:                "sk_lookup_udp",
		BPFFuncSkRelease:                  "sk_release",
		BPFFuncMapPushElem:                "map_push_elem",
		BPFFuncMapPopElem:                 "map_pop_elem",
		BPFFuncMapPeekElem:                "map_peek_elem",
		BPFFuncMsgPushData:                "msg_push_data",
		BPFFuncMsgPopData:                 "msg_pop_data",
		BPFFuncRcPointerRel:               "rc_pointer_rel",
		BPFFuncSpinLock:                   "spin_lock",
		BPFFuncSpinUnlock:                 "spin_unlock",
		BPFFuncSkFullsock:                 "sk_fullsock",
		BPFFuncTcpSock:                    "tcp_sock",
		BPFFuncSkbEcnSetCe:                "skb_ecn_set_ce",
		BPFFuncGetListenerSock:            "get_listener_sock",
		BPFFuncSkcLookupTcp:               "skc_lookup_tcp",
		BPFFuncTcpCheckSyncookie:          "tcp_check_syncookie",
		BPFFuncSysctlGetName:              "sysctl_get_name",
		BPFFuncSysctlGetCurrentValue:      "sysctl_get_current_value",
		BPFFuncSysctlGetNewValue:          "sysctl_get_new_value",
		BPFFuncSysctlSetNewValue:          "sysctl_set_new_value",
		BPFFuncStrtol:                     "strtol",
		BPFFuncStrtoul:                    "strtoul",
		BPFFuncSkStorageGet:               "sk_storage_get",
		BPFFuncSkStorageDelete:            "sk_storage_delete",
		BPFFuncSendSignal:                 "send_signal",
		BPFFuncTcpGenSyncookie:            "tcp_gen_syncookie",
		BPFFuncSkbOutput:                  "skb_output",
		BPFFuncProbeReadUser:              "probe_read_user",
		BPFFuncProbeReadKernel:            "probe_read_kernel",
		BPFFuncProbeReadUserStr:           "probe_read_user_str",
		BPFFuncProbeReadKernelStr:         "probe_read_kernel_str",
		BPFFuncTcpSendAck:                 "tcp_send_ack",
		BPFFuncSendSignalThread:           "send_signal_thread",
		BPFFuncJiffies64:                  "jiffies64",
		BPFFuncReadBranchRecords:          "read_branch_records",
		BPFFuncGetNsCurrentPidTgid:        "get_ns_current_pid_tgid",
		BPFFuncXdpOutput:                  "xdp_output",
		BPFFuncGetNetnsCookie:             "get_netns_cookie",
		BPFFuncGetCurrentAncestorCgroupId: "get_current_ancestor_cgroup_id",
		BPFFuncSkAssign:                   "sk_assign",
		BPFFuncKtimeGetBootNs:             "ktime_get_boot_ns",
		BPFFuncSeqPrintf:                  "seq_printf",
		BPFFuncSeqWrite:                   "seq_write",
		BPFFuncSkCgroupId:                 "sk_cgroup_id",
		BPFFuncSkAncestorCgroupId:         "sk_ancestor_cgroup_id",
		BPFFuncRingbufOutput:              "ringbuf_output",
		BPFFuncRingbufReserve:             "ringbuf_reserve",
		BPFFuncRingbufSubmit:              "ringbuf_submit",
		BPFFuncRingbufDiscard:             "ringbuf_discard",
		BPFFuncRingbufQuery:               "ringbuf_query",
		BPFFuncCsumLevel:                  "csum_level",
		BPFFuncSkcToTcp6Sock:              "skc_to_tcp6_sock",
		BPFFuncSkcToTcpSock:               "skc_to_tcp_sock",
		BPFFuncSkcToTcpTimewaitSock:       "skc_to_tcp_timewait_sock",
		BPFFuncSkcToTcpRequestSock:        "skc_to_tcp_request_sock",
		BPFFuncSkcToUdp6Sock:              "skc_to_udp6_sock",
		BPFFuncGetTaskStack:               "get_task_stack",
		BPFFuncLoadHdrOpt:                 "load_hdr_opt",
		BPFFuncStoreHdrOpt:                "store_hdr_opt",
		BPFFuncReserveHdrOpt:              "reserve_hdr_opt",
		BPFFuncInodeStorageGet:            "inode_storage_get",
		BPFFuncInodeStorageDelete:         "inode_storage_delete",
		BPFFuncDPath:                      "d_path",
		BPFFuncCopyFromUser:               "copy_from_user",
		BPFFuncSnprintfBtf:                "snprintf_btf",
		BPFFuncSeqPrintfBtf:               "seq_printf_btf",
		BPFFuncSkbCgroupClassid:           "skb_cgroup_classid",
		BPFFuncRedirectNeigh:              "redirect_neigh",
		BPFFuncPerCpuPtr:                  "per_cpu_ptr",
		BPFFuncThisCpuPtr:                 "this_cpu_ptr",
		BPFFuncRedirectPeer:               "redirect_peer",
		BPFFuncTaskStorageGet:             "task_storage_get",
		BPFFuncTaskStorageDelete:          "task_storage_delete",
		BPFFuncGetCurrentTaskBtf:          "get_current_task_btf",
		BPFFuncBprmOptsSet:                "bprm_opts_set",
		BPFFuncKtimeGetCoarseNs:           "ktime_get_coarse_ns",
		BPFFuncImaInodeHash:               "ima_inode_hash",
		BPFFuncSockFromFile:               "sock_from_file",
		BPFFuncCheckMtu:                   "check_mtu",
		BPFFuncForEachMapElem:             "for_each_map_elem",
		BPFFuncSnprintf:                   "snprintf",
		BPFFuncSysBpf:                     "sys_bpf",
		BPFFuncBtfFindByNameKind:          "btf_find_by_name_kind",
		BPFFuncSysClose:                   "sys_close",
		BPFFuncTimerInit:                  "timer_init",
		BPFFuncTimerSetCallback:           "timer_set_callback",
		BPFFuncTimerStart:                 "timer_start",
		BPFFuncTimerCancel:                "timer_cancel",
		BPFFuncGetFuncIp:                  "get_func_ip",
		BPFFuncGetAttachCookie:            "get_attach_cookie",
		BPFFuncTaskPtRegs:                 "task_pt_regs",
		BPFFuncGetBranchSnapshot:          "get_branch_snapshot",
		BPFFuncTraceVprintk:               "trace_vprintk",
		BPFFuncSkcToUnixSock:              "skc_to_unix_sock",
		BPFFuncKallsymsLookupName:         "kallsyms_lookup_name",
		BPFFuncFindVma:                    "find_vma",
		BPFFuncLoop:                       "loop",
		BPFFuncStrncmp:                    "strncmp",
		BPFFuncGetFuncArg:                 "get_func_arg",
		BPFFuncGetFuncRet:                 "get_func_ret",
		BPFFuncGetFuncArgCnt:              "get_func_arg_cnt",
		BPFFuncGetRetval:                  "get_retval",
		BPFFuncSetRetval:                  "set_retval",
		BPFFuncXdpGetBuffLen:              "xdp_get_buff_len",
		BPFFuncXdpLoadBytes:               "xdp_load_bytes",
		BPFFuncXdpStoreBytes:              "xdp_store_bytes",
		BPFFuncCopyFromUserTask:           "copy_from_user_task",
		BPFFuncSkbSetTstamp:               "skb_set_tstamp",
		BPFFuncImaFileHash:                "ima_file_hash",
		BPFFuncKptrXchg:                   "kptr_xchg",
		BPFFuncMapLookupPercpuElem:        "map_lookup_percpu_elem",
		BPFFuncSkcToMptcpSock:             "skc_to_mptcp_sock",
		BPFFuncDynptrFromMem:              "dynptr_from_mem",
		BPFFuncRingbufReserveDynptr:       "ringbuf_reserve_dynptr",
		BPFFuncRingbufSubmitDynptr:        "ringbuf_submit_dynptr",
		BPFFuncRingbufDiscardDynptr:       "ringbuf_discard_dynptr",
		BPFFuncDynptrRead:                 "dynptr_read",
		BPFFuncDynptrWrite:                "dynptr_write",
		BPFFuncDynptrData:                 "dynptr_data",
		BPFFuncTcpRawGenSyncookieIpv4:     "tcp_raw_gen_syncookie_ipv4",
		BPFFuncTcpRawGenSyncookieIpv6:     "tcp_raw_gen_syncookie_ipv6",
		BPFFuncTcpRawCheckSyncookieIpv4:   "tcp_raw_check_syncookie_ipv4",
		BPFFuncTcpRawCheckSyncookieIpv6:   "tcp_raw_check_syncookie_ipv6",
		BPFFuncKtimeGetTaiNs:              "ktime_get_tai_ns",
		BPFFuncUserRingbufDrain:           "user_ringbuf_drain",
		BPFFuncCgrpStorageGet:             "cgrp_storage_get",
		BPFFuncCgrpStorageDelete:          "cgrp_storage_delete",
	}
	str, found := x[b]
	if !found {
		str = BPFFuncUnspec.String()
	}
	return str
}

var bpfFuncsMap = map[uint64]BPFFunc{
	BPFFuncUnspec.Value():                     BPFFuncUnspec,
	BPFFuncMapLookupElem.Value():              BPFFuncMapLookupElem,
	BPFFuncMapUpdateElem.Value():              BPFFuncMapUpdateElem,
	BPFFuncMapDeleteElem.Value():              BPFFuncMapDeleteElem,
	BPFFuncProbeRead.Value():                  BPFFuncProbeRead,
	BPFFuncKtimeGetNs.Value():                 BPFFuncKtimeGetNs,
	BPFFuncTracePrintk.Value():                BPFFuncTracePrintk,
	BPFFuncGetPrandomU32.Value():              BPFFuncGetPrandomU32,
	BPFFuncGetSmpProcessorId.Value():          BPFFuncGetSmpProcessorId,
	BPFFuncSkbStoreBytes.Value():              BPFFuncSkbStoreBytes,
	BPFFuncL3CsumReplace.Value():              BPFFuncL3CsumReplace,
	BPFFuncL4CsumReplace.Value():              BPFFuncL4CsumReplace,
	BPFFuncTailCall.Value():                   BPFFuncTailCall,
	BPFFuncCloneRedirect.Value():              BPFFuncCloneRedirect,
	BPFFuncGetCurrentPidTgid.Value():          BPFFuncGetCurrentPidTgid,
	BPFFuncGetCurrentUidGid.Value():           BPFFuncGetCurrentUidGid,
	BPFFuncGetCurrentComm.Value():             BPFFuncGetCurrentComm,
	BPFFuncGetCgroupClassid.Value():           BPFFuncGetCgroupClassid,
	BPFFuncSkbVlanPush.Value():                BPFFuncSkbVlanPush,
	BPFFuncSkbVlanPop.Value():                 BPFFuncSkbVlanPop,
	BPFFuncSkbGetTunnelKey.Value():            BPFFuncSkbGetTunnelKey,
	BPFFuncSkbSetTunnelKey.Value():            BPFFuncSkbSetTunnelKey,
	BPFFuncPerfEventRead.Value():              BPFFuncPerfEventRead,
	BPFFuncRedirect.Value():                   BPFFuncRedirect,
	BPFFuncGetRouteRealm.Value():              BPFFuncGetRouteRealm,
	BPFFuncPerfEventOutput.Value():            BPFFuncPerfEventOutput,
	BPFFuncSkbLoadBytes.Value():               BPFFuncSkbLoadBytes,
	BPFFuncGetStackid.Value():                 BPFFuncGetStackid,
	BPFFuncCsumDiff.Value():                   BPFFuncCsumDiff,
	BPFFuncSkbGetTunnelOpt.Value():            BPFFuncSkbGetTunnelOpt,
	BPFFuncSkbSetTunnelOpt.Value():            BPFFuncSkbSetTunnelOpt,
	BPFFuncSkbChangeProto.Value():             BPFFuncSkbChangeProto,
	BPFFuncSkbChangeType.Value():              BPFFuncSkbChangeType,
	BPFFuncSkbUnderCgroup.Value():             BPFFuncSkbUnderCgroup,
	BPFFuncGetHashRecalc.Value():              BPFFuncGetHashRecalc,
	BPFFuncGetCurrentTask.Value():             BPFFuncGetCurrentTask,
	BPFFuncProbeWriteUser.Value():             BPFFuncProbeWriteUser,
	BPFFuncCurrentTaskUnderCgroup.Value():     BPFFuncCurrentTaskUnderCgroup,
	BPFFuncSkbChangeTail.Value():              BPFFuncSkbChangeTail,
	BPFFuncSkbPullData.Value():                BPFFuncSkbPullData,
	BPFFuncCsumUpdate.Value():                 BPFFuncCsumUpdate,
	BPFFuncSetHashInvalid.Value():             BPFFuncSetHashInvalid,
	BPFFuncGetNumaNodeId.Value():              BPFFuncGetNumaNodeId,
	BPFFuncSkbChangeHead.Value():              BPFFuncSkbChangeHead,
	BPFFuncXdpAdjustHead.Value():              BPFFuncXdpAdjustHead,
	BPFFuncProbeReadStr.Value():               BPFFuncProbeReadStr,
	BPFFuncGetSocketCookie.Value():            BPFFuncGetSocketCookie,
	BPFFuncGetSocketUid.Value():               BPFFuncGetSocketUid,
	BPFFuncSetHash.Value():                    BPFFuncSetHash,
	BPFFuncSetsockopt.Value():                 BPFFuncSetsockopt,
	BPFFuncSkbAdjustRoom.Value():              BPFFuncSkbAdjustRoom,
	BPFFuncRedirectMap.Value():                BPFFuncRedirectMap,
	BPFFuncSkRedirectMap.Value():              BPFFuncSkRedirectMap,
	BPFFuncSockMapUpdate.Value():              BPFFuncSockMapUpdate,
	BPFFuncXdpAdjustMeta.Value():              BPFFuncXdpAdjustMeta,
	BPFFuncPerfEventReadValue.Value():         BPFFuncPerfEventReadValue,
	BPFFuncPerfProgReadValue.Value():          BPFFuncPerfProgReadValue,
	BPFFuncGetsockopt.Value():                 BPFFuncGetsockopt,
	BPFFuncOverrideReturn.Value():             BPFFuncOverrideReturn,
	BPFFuncSockOpsCbFlagsSet.Value():          BPFFuncSockOpsCbFlagsSet,
	BPFFuncMsgRedirectMap.Value():             BPFFuncMsgRedirectMap,
	BPFFuncMsgApplyBytes.Value():              BPFFuncMsgApplyBytes,
	BPFFuncMsgCorkBytes.Value():               BPFFuncMsgCorkBytes,
	BPFFuncMsgPullData.Value():                BPFFuncMsgPullData,
	BPFFuncBind.Value():                       BPFFuncBind,
	BPFFuncXdpAdjustTail.Value():              BPFFuncXdpAdjustTail,
	BPFFuncSkbGetXfrmState.Value():            BPFFuncSkbGetXfrmState,
	BPFFuncGetStack.Value():                   BPFFuncGetStack,
	BPFFuncSkbLoadBytesRelative.Value():       BPFFuncSkbLoadBytesRelative,
	BPFFuncFibLookup.Value():                  BPFFuncFibLookup,
	BPFFuncSockHashUpdate.Value():             BPFFuncSockHashUpdate,
	BPFFuncMsgRedirectHash.Value():            BPFFuncMsgRedirectHash,
	BPFFuncSkRedirectHash.Value():             BPFFuncSkRedirectHash,
	BPFFuncLwtPushEncap.Value():               BPFFuncLwtPushEncap,
	BPFFuncLwtSeg6StoreBytes.Value():          BPFFuncLwtSeg6StoreBytes,
	BPFFuncLwtSeg6AdjustSrh.Value():           BPFFuncLwtSeg6AdjustSrh,
	BPFFuncLwtSeg6Action.Value():              BPFFuncLwtSeg6Action,
	BPFFuncRcRepeat.Value():                   BPFFuncRcRepeat,
	BPFFuncRcKeydown.Value():                  BPFFuncRcKeydown,
	BPFFuncSkbCgroupId.Value():                BPFFuncSkbCgroupId,
	BPFFuncGetCurrentCgroupId.Value():         BPFFuncGetCurrentCgroupId,
	BPFFuncGetLocalStorage.Value():            BPFFuncGetLocalStorage,
	BPFFuncSkSelectReuseport.Value():          BPFFuncSkSelectReuseport,
	BPFFuncSkbAncestorCgroupId.Value():        BPFFuncSkbAncestorCgroupId,
	BPFFuncSkLookupTcp.Value():                BPFFuncSkLookupTcp,
	BPFFuncSkLookupUdp.Value():                BPFFuncSkLookupUdp,
	BPFFuncSkRelease.Value():                  BPFFuncSkRelease,
	BPFFuncMapPushElem.Value():                BPFFuncMapPushElem,
	BPFFuncMapPopElem.Value():                 BPFFuncMapPopElem,
	BPFFuncMapPeekElem.Value():                BPFFuncMapPeekElem,
	BPFFuncMsgPushData.Value():                BPFFuncMsgPushData,
	BPFFuncMsgPopData.Value():                 BPFFuncMsgPopData,
	BPFFuncRcPointerRel.Value():               BPFFuncRcPointerRel,
	BPFFuncSpinLock.Value():                   BPFFuncSpinLock,
	BPFFuncSpinUnlock.Value():                 BPFFuncSpinUnlock,
	BPFFuncSkFullsock.Value():                 BPFFuncSkFullsock,
	BPFFuncTcpSock.Value():                    BPFFuncTcpSock,
	BPFFuncSkbEcnSetCe.Value():                BPFFuncSkbEcnSetCe,
	BPFFuncGetListenerSock.Value():            BPFFuncGetListenerSock,
	BPFFuncSkcLookupTcp.Value():               BPFFuncSkcLookupTcp,
	BPFFuncTcpCheckSyncookie.Value():          BPFFuncTcpCheckSyncookie,
	BPFFuncSysctlGetName.Value():              BPFFuncSysctlGetName,
	BPFFuncSysctlGetCurrentValue.Value():      BPFFuncSysctlGetCurrentValue,
	BPFFuncSysctlGetNewValue.Value():          BPFFuncSysctlGetNewValue,
	BPFFuncSysctlSetNewValue.Value():          BPFFuncSysctlSetNewValue,
	BPFFuncStrtol.Value():                     BPFFuncStrtol,
	BPFFuncStrtoul.Value():                    BPFFuncStrtoul,
	BPFFuncSkStorageGet.Value():               BPFFuncSkStorageGet,
	BPFFuncSkStorageDelete.Value():            BPFFuncSkStorageDelete,
	BPFFuncSendSignal.Value():                 BPFFuncSendSignal,
	BPFFuncTcpGenSyncookie.Value():            BPFFuncTcpGenSyncookie,
	BPFFuncSkbOutput.Value():                  BPFFuncSkbOutput,
	BPFFuncProbeReadUser.Value():              BPFFuncProbeReadUser,
	BPFFuncProbeReadKernel.Value():            BPFFuncProbeReadKernel,
	BPFFuncProbeReadUserStr.Value():           BPFFuncProbeReadUserStr,
	BPFFuncProbeReadKernelStr.Value():         BPFFuncProbeReadKernelStr,
	BPFFuncTcpSendAck.Value():                 BPFFuncTcpSendAck,
	BPFFuncSendSignalThread.Value():           BPFFuncSendSignalThread,
	BPFFuncJiffies64.Value():                  BPFFuncJiffies64,
	BPFFuncReadBranchRecords.Value():          BPFFuncReadBranchRecords,
	BPFFuncGetNsCurrentPidTgid.Value():        BPFFuncGetNsCurrentPidTgid,
	BPFFuncXdpOutput.Value():                  BPFFuncXdpOutput,
	BPFFuncGetNetnsCookie.Value():             BPFFuncGetNetnsCookie,
	BPFFuncGetCurrentAncestorCgroupId.Value(): BPFFuncGetCurrentAncestorCgroupId,
	BPFFuncSkAssign.Value():                   BPFFuncSkAssign,
	BPFFuncKtimeGetBootNs.Value():             BPFFuncKtimeGetBootNs,
	BPFFuncSeqPrintf.Value():                  BPFFuncSeqPrintf,
	BPFFuncSeqWrite.Value():                   BPFFuncSeqWrite,
	BPFFuncSkCgroupId.Value():                 BPFFuncSkCgroupId,
	BPFFuncSkAncestorCgroupId.Value():         BPFFuncSkAncestorCgroupId,
	BPFFuncRingbufOutput.Value():              BPFFuncRingbufOutput,
	BPFFuncRingbufReserve.Value():             BPFFuncRingbufReserve,
	BPFFuncRingbufSubmit.Value():              BPFFuncRingbufSubmit,
	BPFFuncRingbufDiscard.Value():             BPFFuncRingbufDiscard,
	BPFFuncRingbufQuery.Value():               BPFFuncRingbufQuery,
	BPFFuncCsumLevel.Value():                  BPFFuncCsumLevel,
	BPFFuncSkcToTcp6Sock.Value():              BPFFuncSkcToTcp6Sock,
	BPFFuncSkcToTcpSock.Value():               BPFFuncSkcToTcpSock,
	BPFFuncSkcToTcpTimewaitSock.Value():       BPFFuncSkcToTcpTimewaitSock,
	BPFFuncSkcToTcpRequestSock.Value():        BPFFuncSkcToTcpRequestSock,
	BPFFuncSkcToUdp6Sock.Value():              BPFFuncSkcToUdp6Sock,
	BPFFuncGetTaskStack.Value():               BPFFuncGetTaskStack,
	BPFFuncLoadHdrOpt.Value():                 BPFFuncLoadHdrOpt,
	BPFFuncStoreHdrOpt.Value():                BPFFuncStoreHdrOpt,
	BPFFuncReserveHdrOpt.Value():              BPFFuncReserveHdrOpt,
	BPFFuncInodeStorageGet.Value():            BPFFuncInodeStorageGet,
	BPFFuncInodeStorageDelete.Value():         BPFFuncInodeStorageDelete,
	BPFFuncDPath.Value():                      BPFFuncDPath,
	BPFFuncCopyFromUser.Value():               BPFFuncCopyFromUser,
	BPFFuncSnprintfBtf.Value():                BPFFuncSnprintfBtf,
	BPFFuncSeqPrintfBtf.Value():               BPFFuncSeqPrintfBtf,
	BPFFuncSkbCgroupClassid.Value():           BPFFuncSkbCgroupClassid,
	BPFFuncRedirectNeigh.Value():              BPFFuncRedirectNeigh,
	BPFFuncPerCpuPtr.Value():                  BPFFuncPerCpuPtr,
	BPFFuncThisCpuPtr.Value():                 BPFFuncThisCpuPtr,
	BPFFuncRedirectPeer.Value():               BPFFuncRedirectPeer,
	BPFFuncTaskStorageGet.Value():             BPFFuncTaskStorageGet,
	BPFFuncTaskStorageDelete.Value():          BPFFuncTaskStorageDelete,
	BPFFuncGetCurrentTaskBtf.Value():          BPFFuncGetCurrentTaskBtf,
	BPFFuncBprmOptsSet.Value():                BPFFuncBprmOptsSet,
	BPFFuncKtimeGetCoarseNs.Value():           BPFFuncKtimeGetCoarseNs,
	BPFFuncImaInodeHash.Value():               BPFFuncImaInodeHash,
	BPFFuncSockFromFile.Value():               BPFFuncSockFromFile,
	BPFFuncCheckMtu.Value():                   BPFFuncCheckMtu,
	BPFFuncForEachMapElem.Value():             BPFFuncForEachMapElem,
	BPFFuncSnprintf.Value():                   BPFFuncSnprintf,
	BPFFuncSysBpf.Value():                     BPFFuncSysBpf,
	BPFFuncBtfFindByNameKind.Value():          BPFFuncBtfFindByNameKind,
	BPFFuncSysClose.Value():                   BPFFuncSysClose,
	BPFFuncTimerInit.Value():                  BPFFuncTimerInit,
	BPFFuncTimerSetCallback.Value():           BPFFuncTimerSetCallback,
	BPFFuncTimerStart.Value():                 BPFFuncTimerStart,
	BPFFuncTimerCancel.Value():                BPFFuncTimerCancel,
	BPFFuncGetFuncIp.Value():                  BPFFuncGetFuncIp,
	BPFFuncGetAttachCookie.Value():            BPFFuncGetAttachCookie,
	BPFFuncTaskPtRegs.Value():                 BPFFuncTaskPtRegs,
	BPFFuncGetBranchSnapshot.Value():          BPFFuncGetBranchSnapshot,
	BPFFuncTraceVprintk.Value():               BPFFuncTraceVprintk,
	BPFFuncSkcToUnixSock.Value():              BPFFuncSkcToUnixSock,
	BPFFuncKallsymsLookupName.Value():         BPFFuncKallsymsLookupName,
	BPFFuncFindVma.Value():                    BPFFuncFindVma,
	BPFFuncLoop.Value():                       BPFFuncLoop,
	BPFFuncStrncmp.Value():                    BPFFuncStrncmp,
	BPFFuncGetFuncArg.Value():                 BPFFuncGetFuncArg,
	BPFFuncGetFuncRet.Value():                 BPFFuncGetFuncRet,
	BPFFuncGetFuncArgCnt.Value():              BPFFuncGetFuncArgCnt,
	BPFFuncGetRetval.Value():                  BPFFuncGetRetval,
	BPFFuncSetRetval.Value():                  BPFFuncSetRetval,
	BPFFuncXdpGetBuffLen.Value():              BPFFuncXdpGetBuffLen,
	BPFFuncXdpLoadBytes.Value():               BPFFuncXdpLoadBytes,
	BPFFuncXdpStoreBytes.Value():              BPFFuncXdpStoreBytes,
	BPFFuncCopyFromUserTask.Value():           BPFFuncCopyFromUserTask,
	BPFFuncSkbSetTstamp.Value():               BPFFuncSkbSetTstamp,
	BPFFuncImaFileHash.Value():                BPFFuncImaFileHash,
	BPFFuncKptrXchg.Value():                   BPFFuncKptrXchg,
	BPFFuncMapLookupPercpuElem.Value():        BPFFuncMapLookupPercpuElem,
	BPFFuncSkcToMptcpSock.Value():             BPFFuncSkcToMptcpSock,
	BPFFuncDynptrFromMem.Value():              BPFFuncDynptrFromMem,
	BPFFuncRingbufReserveDynptr.Value():       BPFFuncRingbufReserveDynptr,
	BPFFuncRingbufSubmitDynptr.Value():        BPFFuncRingbufSubmitDynptr,
	BPFFuncRingbufDiscardDynptr.Value():       BPFFuncRingbufDiscardDynptr,
	BPFFuncDynptrRead.Value():                 BPFFuncDynptrRead,
	BPFFuncDynptrWrite.Value():                BPFFuncDynptrWrite,
	BPFFuncDynptrData.Value():                 BPFFuncDynptrData,
	BPFFuncTcpRawGenSyncookieIpv4.Value():     BPFFuncTcpRawGenSyncookieIpv4,
	BPFFuncTcpRawGenSyncookieIpv6.Value():     BPFFuncTcpRawGenSyncookieIpv6,
	BPFFuncTcpRawCheckSyncookieIpv4.Value():   BPFFuncTcpRawCheckSyncookieIpv4,
	BPFFuncTcpRawCheckSyncookieIpv6.Value():   BPFFuncTcpRawCheckSyncookieIpv6,
	BPFFuncKtimeGetTaiNs.Value():              BPFFuncKtimeGetTaiNs,
	BPFFuncUserRingbufDrain.Value():           BPFFuncUserRingbufDrain,
	BPFFuncCgrpStorageGet.Value():             BPFFuncCgrpStorageGet,
	BPFFuncCgrpStorageDelete.Value():          BPFFuncCgrpStorageDelete,
}

//
// BPFProgType
//

// BPFProgType is an enum as defined in https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h
type BPFProgType uint32

const (
	BPFProgTypeUnspec                BPFProgType = C.BPF_PROG_TYPE_UNSPEC
	BPFProgTypeSocketFilter          BPFProgType = C.BPF_PROG_TYPE_SOCKET_FILTER
	BPFProgTypeKprobe                BPFProgType = C.BPF_PROG_TYPE_KPROBE
	BPFProgTypeSchedCls              BPFProgType = C.BPF_PROG_TYPE_SCHED_CLS
	BPFProgTypeSchedAct              BPFProgType = C.BPF_PROG_TYPE_SCHED_ACT
	BPFProgTypeTracepoint            BPFProgType = C.BPF_PROG_TYPE_TRACEPOINT
	BPFProgTypeXdp                   BPFProgType = C.BPF_PROG_TYPE_XDP
	BPFProgTypePerfEvent             BPFProgType = C.BPF_PROG_TYPE_PERF_EVENT
	BPFProgTypeCgroupSkb             BPFProgType = C.BPF_PROG_TYPE_CGROUP_SKB
	BPFProgTypeCgroupSock            BPFProgType = C.BPF_PROG_TYPE_CGROUP_SOCK
	BPFProgTypeLwtIn                 BPFProgType = C.BPF_PROG_TYPE_LWT_IN
	BPFProgTypeLwtOut                BPFProgType = C.BPF_PROG_TYPE_LWT_OUT
	BPFProgTypeLwtXmit               BPFProgType = C.BPF_PROG_TYPE_LWT_XMIT
	BPFProgTypeSockOps               BPFProgType = C.BPF_PROG_TYPE_SOCK_OPS
	BPFProgTypeSkSkb                 BPFProgType = C.BPF_PROG_TYPE_SK_SKB
	BPFProgTypeCgroupDevice          BPFProgType = C.BPF_PROG_TYPE_CGROUP_DEVICE
	BPFProgTypeSkMsg                 BPFProgType = C.BPF_PROG_TYPE_SK_MSG
	BPFProgTypeRawTracepoint         BPFProgType = C.BPF_PROG_TYPE_RAW_TRACEPOINT
	BPFProgTypeCgroupSockAddr        BPFProgType = C.BPF_PROG_TYPE_CGROUP_SOCK_ADDR
	BPFProgTypeLwtSeg6Local          BPFProgType = C.BPF_PROG_TYPE_LWT_SEG6LOCAL
	BPFProgTypeLircMode2             BPFProgType = C.BPF_PROG_TYPE_LIRC_MODE2
	BPFProgTypeSkReuseport           BPFProgType = C.BPF_PROG_TYPE_SK_REUSEPORT
	BPFProgTypeFlowDissector         BPFProgType = C.BPF_PROG_TYPE_FLOW_DISSECTOR
	BPFProgTypeCgroupSysctl          BPFProgType = C.BPF_PROG_TYPE_CGROUP_SYSCTL
	BPFProgTypeRawTracepointWritable BPFProgType = C.BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
	BPFProgTypeCgroupSockopt         BPFProgType = C.BPF_PROG_TYPE_CGROUP_SOCKOPT
	BPFProgTypeTracing               BPFProgType = C.BPF_PROG_TYPE_TRACING
	BPFProgTypeStructOps             BPFProgType = C.BPF_PROG_TYPE_STRUCT_OPS
	BPFProgTypeExt                   BPFProgType = C.BPF_PROG_TYPE_EXT
	BPFProgTypeLsm                   BPFProgType = C.BPF_PROG_TYPE_LSM
	BPFProgTypeSkLookup              BPFProgType = C.BPF_PROG_TYPE_SK_LOOKUP
	BPFProgTypeSyscall               BPFProgType = C.BPF_PROG_TYPE_SYSCALL
	BPFProgTypeNetfilter             BPFProgType = C.BPF_PROG_TYPE_NETFILTER
)

// Deprecated: Convert type directly instead.
func (t BPFProgType) Value() uint64 { return uint64(t) }

var bpfProgTypeToString = map[BPFProgType]string{
	BPFProgTypeUnspec:                "BPF_PROG_TYPE_UNSPEC",
	BPFProgTypeSocketFilter:          "BPF_PROG_TYPE_SOCKET_FILTER",
	BPFProgTypeKprobe:                "BPF_PROG_TYPE_KPROBE",
	BPFProgTypeSchedCls:              "BPF_PROG_TYPE_SCHED_CLS",
	BPFProgTypeSchedAct:              "BPF_PROG_TYPE_SCHED_ACT",
	BPFProgTypeTracepoint:            "BPF_PROG_TYPE_TRACEPOINT",
	BPFProgTypeXdp:                   "BPF_PROG_TYPE_XDP",
	BPFProgTypePerfEvent:             "BPF_PROG_TYPE_PERF_EVENT",
	BPFProgTypeCgroupSkb:             "BPF_PROG_TYPE_CGROUP_SKB",
	BPFProgTypeCgroupSock:            "BPF_PROG_TYPE_CGROUP_SOCK",
	BPFProgTypeLwtIn:                 "BPF_PROG_TYPE_LWT_IN",
	BPFProgTypeLwtOut:                "BPF_PROG_TYPE_LWT_OUT",
	BPFProgTypeLwtXmit:               "BPF_PROG_TYPE_LWT_XMIT",
	BPFProgTypeSockOps:               "BPF_PROG_TYPE_SOCK_OPS",
	BPFProgTypeSkSkb:                 "BPF_PROG_TYPE_SK_SKB",
	BPFProgTypeCgroupDevice:          "BPF_PROG_TYPE_CGROUP_DEVICE",
	BPFProgTypeSkMsg:                 "BPF_PROG_TYPE_SK_MSG",
	BPFProgTypeRawTracepoint:         "BPF_PROG_TYPE_RAW_TRACEPOINT",
	BPFProgTypeCgroupSockAddr:        "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
	BPFProgTypeLwtSeg6Local:          "BPF_PROG_TYPE_LWT_SEG6LOCAL",
	BPFProgTypeLircMode2:             "BPF_PROG_TYPE_LIRC_MODE2",
	BPFProgTypeSkReuseport:           "BPF_PROG_TYPE_SK_REUSEPORT",
	BPFProgTypeFlowDissector:         "BPF_PROG_TYPE_FLOW_DISSECTOR",
	BPFProgTypeCgroupSysctl:          "BPF_PROG_TYPE_CGROUP_SYSCTL",
	BPFProgTypeRawTracepointWritable: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
	BPFProgTypeCgroupSockopt:         "BPF_PROG_TYPE_CGROUP_SOCKOPT",
	BPFProgTypeTracing:               "BPF_PROG_TYPE_TRACING",
	BPFProgTypeStructOps:             "BPF_PROG_TYPE_STRUCT_OPS",
	BPFProgTypeExt:                   "BPF_PROG_TYPE_EXT",
	BPFProgTypeLsm:                   "BPF_PROG_TYPE_LSM",
	BPFProgTypeSkLookup:              "BPF_PROG_TYPE_SK_LOOKUP",
	BPFProgTypeSyscall:               "BPF_PROG_TYPE_SYSCALL",
	BPFProgTypeNetfilter:             "BPF_PROG_TYPE_NETFILTER",
}

func (t BPFProgType) String() string {
	str, ok := bpfProgTypeToString[t]
	if !ok {
		// BPFProgTypeUnspec must exist in bpfProgTypeToString to avoid infinite recursion.
		return BPFProgTypeUnspec.String()
	}

	return str
}

func (t BPFProgType) Name() string {
	return C.GoString(C.libbpf_bpf_prog_type_str(C.enum_bpf_prog_type(t)))
}

//
// BPFAttachType
//

type BPFAttachType uint32

const (
	BPFAttachTypeCgroupInetIngress          BPFAttachType = C.BPF_CGROUP_INET_INGRESS
	BPFAttachTypeCgroupInetEgress           BPFAttachType = C.BPF_CGROUP_INET_EGRESS
	BPFAttachTypeCgroupInetSockCreate       BPFAttachType = C.BPF_CGROUP_INET_SOCK_CREATE
	BPFAttachTypeCgroupSockOps              BPFAttachType = C.BPF_CGROUP_SOCK_OPS
	BPFAttachTypeSKSKBStreamParser          BPFAttachType = C.BPF_SK_SKB_STREAM_PARSER
	BPFAttachTypeSKSKBStreamVerdict         BPFAttachType = C.BPF_SK_SKB_STREAM_VERDICT
	BPFAttachTypeCgroupDevice               BPFAttachType = C.BPF_CGROUP_DEVICE
	BPFAttachTypeSKMSGVerdict               BPFAttachType = C.BPF_SK_MSG_VERDICT
	BPFAttachTypeCgroupInet4Bind            BPFAttachType = C.BPF_CGROUP_INET4_BIND
	BPFAttachTypeCgroupInet6Bind            BPFAttachType = C.BPF_CGROUP_INET6_BIND
	BPFAttachTypeCgroupInet4Connect         BPFAttachType = C.BPF_CGROUP_INET4_CONNECT
	BPFAttachTypeCgroupInet6Connect         BPFAttachType = C.BPF_CGROUP_INET6_CONNECT
	BPFAttachTypeCgroupInet4PostBind        BPFAttachType = C.BPF_CGROUP_INET4_POST_BIND
	BPFAttachTypeCgroupInet6PostBind        BPFAttachType = C.BPF_CGROUP_INET6_POST_BIND
	BPFAttachTypeCgroupUDP4SendMsg          BPFAttachType = C.BPF_CGROUP_UDP4_SENDMSG
	BPFAttachTypeCgroupUDP6SendMsg          BPFAttachType = C.BPF_CGROUP_UDP6_SENDMSG
	BPFAttachTypeLircMode2                  BPFAttachType = C.BPF_LIRC_MODE2
	BPFAttachTypeFlowDissector              BPFAttachType = C.BPF_FLOW_DISSECTOR
	BPFAttachTypeCgroupSysctl               BPFAttachType = C.BPF_CGROUP_SYSCTL
	BPFAttachTypeCgroupUDP4RecvMsg          BPFAttachType = C.BPF_CGROUP_UDP4_RECVMSG
	BPFAttachTypeCgroupUDP6RecvMsg          BPFAttachType = C.BPF_CGROUP_UDP6_RECVMSG
	BPFAttachTypeCgroupGetSockOpt           BPFAttachType = C.BPF_CGROUP_GETSOCKOPT
	BPFAttachTypeCgroupSetSockOpt           BPFAttachType = C.BPF_CGROUP_SETSOCKOPT
	BPFAttachTypeTraceRawTP                 BPFAttachType = C.BPF_TRACE_RAW_TP
	BPFAttachTypeTraceFentry                BPFAttachType = C.BPF_TRACE_FENTRY
	BPFAttachTypeTraceFexit                 BPFAttachType = C.BPF_TRACE_FEXIT
	BPFAttachTypeModifyReturn               BPFAttachType = C.BPF_MODIFY_RETURN
	BPFAttachTypeLSMMac                     BPFAttachType = C.BPF_LSM_MAC
	BPFAttachTypeTraceIter                  BPFAttachType = C.BPF_TRACE_ITER
	BPFAttachTypeCgroupInet4GetPeerName     BPFAttachType = C.BPF_CGROUP_INET4_GETPEERNAME
	BPFAttachTypeCgroupInet6GetPeerName     BPFAttachType = C.BPF_CGROUP_INET6_GETPEERNAME
	BPFAttachTypeCgroupInet4GetSockName     BPFAttachType = C.BPF_CGROUP_INET4_GETSOCKNAME
	BPFAttachTypeCgroupInet6GetSockName     BPFAttachType = C.BPF_CGROUP_INET6_GETSOCKNAME
	BPFAttachTypeXDPDevMap                  BPFAttachType = C.BPF_XDP_DEVMAP
	BPFAttachTypeCgroupInetSockRelease      BPFAttachType = C.BPF_CGROUP_INET_SOCK_RELEASE
	BPFAttachTypeXDPCPUMap                  BPFAttachType = C.BPF_XDP_CPUMAP
	BPFAttachTypeSKLookup                   BPFAttachType = C.BPF_SK_LOOKUP
	BPFAttachTypeXDP                        BPFAttachType = C.BPF_XDP
	BPFAttachTypeSKSKBVerdict               BPFAttachType = C.BPF_SK_SKB_VERDICT
	BPFAttachTypeSKReusePortSelect          BPFAttachType = C.BPF_SK_REUSEPORT_SELECT
	BPFAttachTypeSKReusePortSelectorMigrate BPFAttachType = C.BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
	BPFAttachTypePerfEvent                  BPFAttachType = C.BPF_PERF_EVENT
	BPFAttachTypeTraceKprobeMulti           BPFAttachType = C.BPF_TRACE_KPROBE_MULTI
	BPFAttachTypeLSMCgroup                  BPFAttachType = C.BPF_LSM_CGROUP
	BPFAttachTypeStructOps                  BPFAttachType = C.BPF_STRUCT_OPS
	BPFAttachTypeNetfilter                  BPFAttachType = C.BPF_NETFILTER
	BPFAttachTypeTCXIngress                 BPFAttachType = C.BPF_TCX_INGRESS
	BPFAttachTypeTCXEgress                  BPFAttachType = C.BPF_TCX_EGRESS
	BPFAttachTypeTraceUprobeMulti           BPFAttachType = C.BPF_TRACE_UPROBE_MULTI
	BPFAttachTypeCgroupUnixConnect          BPFAttachType = C.BPF_CGROUP_UNIX_CONNECT
	BPFAttachTypeCgroupUnixSendMsg          BPFAttachType = C.BPF_CGROUP_UNIX_SENDMSG
	BPFAttachTypeCgroupUnixRecvMsg          BPFAttachType = C.BPF_CGROUP_UNIX_RECVMSG
	BPFAttachTypeCgroupUnixGetPeerName      BPFAttachType = C.BPF_CGROUP_UNIX_GETPEERNAME
	BPFAttachTypeCgroupUnixGetSockName      BPFAttachType = C.BPF_CGROUP_UNIX_GETSOCKNAME
	BPFAttachTypeNetkitPrimary              BPFAttachType = C.BPF_NETKIT_PRIMARY
	BPFAttachTypeNetkitPeer                 BPFAttachType = C.BPF_NETKIT_PEER
	BPFAttachTypeTraceKprobeSession         BPFAttachType = C.BPF_TRACE_KPROBE_SESSION
)

var bpfAttachTypeToString = map[BPFAttachType]string{
	BPFAttachTypeCgroupInetIngress:          "BPF_CGROUP_INET_INGRESS",
	BPFAttachTypeCgroupInetEgress:           "BPF_CGROUP_INET_EGRESS",
	BPFAttachTypeCgroupInetSockCreate:       "BPF_CGROUP_INET_SOCK_CREATE",
	BPFAttachTypeCgroupSockOps:              "BPF_CGROUP_SOCK_OPS",
	BPFAttachTypeSKSKBStreamParser:          "BPF_SK_SKB_STREAM_PARSER",
	BPFAttachTypeSKSKBStreamVerdict:         "BPF_SK_SKB_STREAM_VERDICT",
	BPFAttachTypeCgroupDevice:               "BPF_CGROUP_DEVICE",
	BPFAttachTypeSKMSGVerdict:               "BPF_SK_MSG_VERDICT",
	BPFAttachTypeCgroupInet4Bind:            "BPF_CGROUP_INET4_BIND",
	BPFAttachTypeCgroupInet6Bind:            "BPF_CGROUP_INET6_BIND",
	BPFAttachTypeCgroupInet4Connect:         "BPF_CGROUP_INET4_CONNECT",
	BPFAttachTypeCgroupInet6Connect:         "BPF_CGROUP_INET6_CONNECT",
	BPFAttachTypeCgroupInet4PostBind:        "BPF_CGROUP_INET4_POST_BIND",
	BPFAttachTypeCgroupInet6PostBind:        "BPF_CGROUP_INET6_POST_BIND",
	BPFAttachTypeCgroupUDP4SendMsg:          "BPF_CGROUP_UDP4_SENDMSG",
	BPFAttachTypeCgroupUDP6SendMsg:          "BPF_CGROUP_UDP6_SENDMSG",
	BPFAttachTypeLircMode2:                  "BPF_LIRC_MODE2",
	BPFAttachTypeFlowDissector:              "BPF_FLOW_DISSECTOR",
	BPFAttachTypeCgroupSysctl:               "BPF_CGROUP_SYSCTL",
	BPFAttachTypeCgroupUDP4RecvMsg:          "BPF_CGROUP_UDP4_RECVMSG",
	BPFAttachTypeCgroupUDP6RecvMsg:          "BPF_CGROUP_UDP6_RECVMSG",
	BPFAttachTypeCgroupGetSockOpt:           "BPF_CGROUP_GETSOCKOPT",
	BPFAttachTypeCgroupSetSockOpt:           "BPF_CGROUP_SETSOCKOPT",
	BPFAttachTypeTraceRawTP:                 "BPF_TRACE_RAW_TP",
	BPFAttachTypeTraceFentry:                "BPF_TRACE_FENTRY",
	BPFAttachTypeTraceFexit:                 "BPF_TRACE_FEXIT",
	BPFAttachTypeModifyReturn:               "BPF_MODIFY_RETURN",
	BPFAttachTypeLSMMac:                     "BPF_LSM_MAC",
	BPFAttachTypeTraceIter:                  "BPF_TRACE_ITER",
	BPFAttachTypeCgroupInet4GetPeerName:     "BPF_CGROUP_INET4_GETPEERNAME",
	BPFAttachTypeCgroupInet6GetPeerName:     "BPF_CGROUP_INET6_GETPEERNAME",
	BPFAttachTypeCgroupInet4GetSockName:     "BPF_CGROUP_INET4_GETSOCKNAME",
	BPFAttachTypeCgroupInet6GetSockName:     "BPF_CGROUP_INET6_GETSOCKNAME",
	BPFAttachTypeXDPDevMap:                  "BPF_XDP_DEVMAP",
	BPFAttachTypeCgroupInetSockRelease:      "BPF_CGROUP_INET_SOCK_RELEASE",
	BPFAttachTypeXDPCPUMap:                  "BPF_XDP_CPUMAP",
	BPFAttachTypeSKLookup:                   "BPF_SK_LOOKUP",
	BPFAttachTypeXDP:                        "BPF_XDP",
	BPFAttachTypeSKSKBVerdict:               "BPF_SK_SKB_VERDICT",
	BPFAttachTypeSKReusePortSelect:          "BPF_SK_REUSEPORT_SELECT",
	BPFAttachTypeSKReusePortSelectorMigrate: "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE",
	BPFAttachTypePerfEvent:                  "BPF_PERF_EVENT",
	BPFAttachTypeTraceKprobeMulti:           "BPF_TRACE_KPROBE_MULTI",
	BPFAttachTypeLSMCgroup:                  "BPF_LSM_CGROUP",
	BPFAttachTypeStructOps:                  "BPF_STRUCT_OPS",
	BPFAttachTypeNetfilter:                  "BPF_NETFILTER",
	BPFAttachTypeTCXIngress:                 "BPF_TCX_INGRESS",
	BPFAttachTypeTCXEgress:                  "BPF_TCX_EGRESS",
	BPFAttachTypeTraceUprobeMulti:           "BPF_TRACE_UPROBE_MULTI",
	BPFAttachTypeCgroupUnixConnect:          "BPF_CGROUP_UNIX_CONNECT",
	BPFAttachTypeCgroupUnixSendMsg:          "BPF_CGROUP_UNIX_SENDMSG",
	BPFAttachTypeCgroupUnixRecvMsg:          "BPF_CGROUP_UNIX_RECVMSG",
	BPFAttachTypeCgroupUnixGetPeerName:      "BPF_CGROUP_UNIX_GETPEERNAME",
	BPFAttachTypeCgroupUnixGetSockName:      "BPF_CGROUP_UNIX_GETSOCKNAME",
	BPFAttachTypeNetkitPrimary:              "BPF_NETKIT_PRIMARY",
	BPFAttachTypeNetkitPeer:                 "BPF_NETKIT_PEER",
	BPFAttachTypeTraceKprobeSession:         "BPF_TRACE_KPROBE_SESSION",
}

func (t BPFAttachType) String() string {
	str, ok := bpfAttachTypeToString[t]
	if !ok {
		return "BPFAttachType unspecified"
	}

	return str
}

func (t BPFAttachType) Name() string {
	return C.GoString(C.libbpf_bpf_attach_type_str(C.enum_bpf_attach_type(t)))
}

//
// BPFCgroupIterOrder
//

type BPFCgroupIterOrder uint32

const (
	BPFIterOrderUnspec BPFCgroupIterOrder = iota
	BPFIterSelfOnly
	BPFIterDescendantsPre
	BPFIterDescendantsPost
	BPFIterAncestorsUp
)

//
// AttachFlag
//

type AttachFlag uint32

const (
	BPFFNone          AttachFlag = 0
	BPFFAllowOverride AttachFlag = C.BPF_F_ALLOW_OVERRIDE
	BPFFAllowMulti    AttachFlag = C.BPF_F_ALLOW_MULTI
	BPFFReplace       AttachFlag = C.BPF_F_REPLACE
	BPFFBefore        AttachFlag = C.BPF_F_BEFORE
	BPFFAfter         AttachFlag = C.BPF_F_AFTER
	BPFFID            AttachFlag = C.BPF_F_ID
	BPFFLink          AttachFlag = C.BPF_F_LINK
)

//
// XDPFlags
//

type XDPFlags uint32

const (
	XDPFlagsUpdateIfNoExist XDPFlags = C.XDP_FLAGS_UPDATE_IF_NOEXIST
	XDPFlagsSkbMode         XDPFlags = C.XDP_FLAGS_SKB_MODE
	XDPFlagsDrvMode         XDPFlags = C.XDP_FLAGS_DRV_MODE
	XDPFlagsHwMode          XDPFlags = C.XDP_FLAGS_HW_MODE
	XDPFlagsReplace         XDPFlags = C.XDP_FLAGS_REPLACE
	XDPFlagsModes           XDPFlags = C.XDP_FLAGS_MODES
	XDPFlagsMask            XDPFlags = C.XDP_FLAGS_MASK
)
