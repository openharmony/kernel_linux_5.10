/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM rtg

#if !defined(_TRACE_RTG_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RTG_H

#include <linux/trace_seq.h>
#include <linux/tracepoint.h>
#include <linux/sched/frame_rtg.h>

struct rq;

TRACE_EVENT(find_rtg_cpu,

	TP_PROTO(struct task_struct *p, const struct cpumask *perferred_cpumask,
		 char *msg, int cpu),

	TP_ARGS(p, perferred_cpumask, msg, cpu),

	TP_STRUCT__entry(
		__array(char, comm, TASK_COMM_LEN)
		__field(pid_t, pid)
		__bitmask(cpus,	num_possible_cpus())
		__array(char, msg, TASK_COMM_LEN)
		__field(int, cpu)
	),

	TP_fast_assign(
		__entry->pid = p->pid;
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__assign_bitmask(cpus, cpumask_bits(perferred_cpumask), num_possible_cpus());
		memcpy(__entry->msg, msg, min((size_t)TASK_COMM_LEN, strlen(msg)+1));
		__entry->cpu = cpu;
	),

	TP_printk("comm=%s pid=%d perferred_cpus=%s reason=%s target_cpu=%d",
		__entry->comm, __entry->pid, __get_bitmask(cpus), __entry->msg, __entry->cpu)
);

TRACE_EVENT(sched_rtg_task_each,

	TP_PROTO(unsigned int id, unsigned int nr_running, struct task_struct *task),

	TP_ARGS(id, nr_running, task),

	TP_STRUCT__entry(
		__field(unsigned int,	id)
		__field(unsigned int,	nr_running)
		__array(char,	comm,	TASK_COMM_LEN)
		__field(pid_t,		pid)
		__field(int,		prio)
		__bitmask(allowed, num_possible_cpus())
		__field(int,		cpu)
		__field(int,		state)
		__field(bool,		on_rq)
		__field(int,		on_cpu)
	),

	TP_fast_assign(
		__entry->id		= id;
		__entry->nr_running	= nr_running;
		memcpy(__entry->comm, task->comm, TASK_COMM_LEN);
		__entry->pid		= task->pid;
		__entry->prio		= task->prio;
		__assign_bitmask(allowed, cpumask_bits(&task->cpus_mask), num_possible_cpus());
		__entry->cpu		= task_cpu(task);
		__entry->state		= task->state;
		__entry->on_rq		= task->on_rq;
		__entry->on_cpu		= task->on_cpu;
	),

	TP_printk("comm=%s pid=%d prio=%d allowed=%s cpu=%d state=%s%s on_rq=%d on_cpu=%d",
		__entry->comm, __entry->pid, __entry->prio, __get_bitmask(allowed), __entry->cpu,
		__entry->state & (TASK_REPORT_MAX) ?
		__print_flags(__entry->state & (TASK_REPORT_MAX), "|",
				{ TASK_INTERRUPTIBLE, "S" },
				{ TASK_UNINTERRUPTIBLE, "D" },
				{ __TASK_STOPPED, "T" },
				{ __TASK_TRACED, "t" },
				{ EXIT_DEAD, "X" },
				{ EXIT_ZOMBIE, "Z" },
				{ TASK_DEAD, "x" },
				{ TASK_WAKEKILL, "K"},
				{ TASK_WAKING, "W"}) : "R",
		__entry->state & TASK_STATE_MAX ? "+" : "",
		__entry->on_rq, __entry->on_cpu)
);

TRACE_EVENT(sched_rtg_valid_normalized_util,

	TP_PROTO(unsigned int id, unsigned int nr_running,
		 const struct cpumask *rtg_cpus, unsigned int valid),

	TP_ARGS(id, nr_running, rtg_cpus, valid),

	TP_STRUCT__entry(
		__field(unsigned int,	id)
		__field(unsigned int,	nr_running)
		__bitmask(cpus,	num_possible_cpus())
		__field(unsigned int,	valid)
	),

	TP_fast_assign(
		__entry->id		= id;
		__entry->nr_running	= nr_running;
		__assign_bitmask(cpus, cpumask_bits(rtg_cpus), num_possible_cpus());
		__entry->valid		= valid;
	),

	TP_printk("id=%d nr_running=%d cpus=%s valid=%d",
		__entry->id, __entry->nr_running,
		__get_bitmask(cpus), __entry->valid)
);

#ifdef CONFIG_SCHED_RTG_FRAME
TRACE_EVENT(rtg_frame_sched,

	TP_PROTO(int rtgid, const char *s, s64 value),

	TP_ARGS(rtgid, s, value),
	TP_STRUCT__entry(
		__field(int, rtgid)
		__field(struct frame_info *, frame)
		__field(pid_t, pid)
		__string(str, s)
		__field(s64, value)
	),

	TP_fast_assign(
		__assign_str(str, s);
		__entry->rtgid = rtgid != -1 ? rtgid : (current->grp ? current->grp->id : 0);
		__entry->frame = rtg_frame_info(rtgid);
		__entry->pid = __entry->frame ? ((__entry->frame->thread[0]) ?
						 ((__entry->frame->thread[0])->pid) :
						 current->tgid) : current->tgid;
		__entry->value = value;
	),
	TP_printk("C|%d|%s_%d|%lld", __entry->pid, __get_str(str), __entry->rtgid, __entry->value)
);
#endif
#endif /* _TRACE_RTG_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
