# SPDX-License-Identifier: GPL-2.0
# Makefile for net selftests

CFLAGS =  -Wall -Wl,--no-as-needed -O2 -g
CFLAGS += -I../../../../usr/include/

TEST_PROGS := run_netsocktests run_afpackettests test_bpf.sh netdevice.sh \
	      rtnetlink.sh xfrm_policy.sh test_blackhole_dev.sh
TEST_PROGS += fib_tests.sh fib-onlink-tests.sh pmtu.sh udpgso.sh ip_defrag.sh
TEST_PROGS += udpgso_bench.sh fib_rule_tests.sh msg_zerocopy.sh psock_snd.sh
TEST_PROGS += udpgro_bench.sh udpgro.sh test_vxlan_under_vrf.sh reuseport_addr_any.sh
TEST_PROGS += test_vxlan_fdb_changelink.sh so_txtime.sh ipv6_flowlabel.sh
TEST_PROGS += tcp_fastopen_backup_key.sh fcnal-test.sh l2tp.sh traceroute.sh
TEST_PROGS += fin_ack_lat.sh fib_nexthop_multiprefix.sh fib_nexthops.sh
TEST_PROGS += altnames.sh icmp_redirect.sh ip6_gre_headroom.sh
TEST_PROGS += route_localnet.sh
TEST_PROGS += reuseaddr_ports_exhausted.sh
TEST_PROGS += txtimestamp.sh
TEST_PROGS += vrf-xfrm-tests.sh
TEST_PROGS += rxtimestamp.sh
TEST_PROGS += devlink_port_split.py
TEST_PROGS += drop_monitor_tests.sh
TEST_PROGS += vrf_route_leaking.sh
TEST_PROGS += ipv6_route_update_soft_lockup.sh
TEST_PROGS_EXTENDED := in_netns.sh
TEST_GEN_FILES =  socket nettest
TEST_GEN_FILES += psock_fanout psock_tpacket msg_zerocopy reuseport_addr_any
TEST_GEN_FILES += tcp_mmap tcp_inq psock_snd txring_overwrite
TEST_GEN_FILES += udpgso udpgso_bench_tx udpgso_bench_rx ip_defrag
TEST_GEN_FILES += so_txtime ipv6_flowlabel ipv6_flowlabel_mgr
TEST_GEN_FILES += tcp_fastopen_backup_key
TEST_GEN_FILES += fin_ack_lat
TEST_GEN_FILES += reuseaddr_ports_exhausted
TEST_GEN_FILES += hwtstamp_config rxtimestamp timestamping txtimestamp
TEST_GEN_FILES += ipsec
TEST_GEN_PROGS = reuseport_bpf reuseport_bpf_cpu reuseport_bpf_numa
TEST_GEN_PROGS += reuseport_dualstack reuseaddr_conflict tls

KSFT_KHDR_INSTALL := 1
include ../lib.mk

$(OUTPUT)/reuseport_bpf_numa: LDLIBS += -lnuma
$(OUTPUT)/tcp_mmap: LDLIBS += -lpthread
$(OUTPUT)/tcp_inq: LDLIBS += -lpthread
