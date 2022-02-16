/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM walt

#if !defined(_TRACE_WALT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_WALT_H

#include <linux/trace_seq.h>
#include <linux/tracepoint.h>

struct rq;
extern const char *task_event_names[];

#if defined(CREATE_TRACE_POINTS) && defined(CONFIG_SCHED_WALT)
static inline void __window_data(u32 *dst, u32 *src)
{
	if (src)
		memcpy(dst, src, nr_cpu_ids * sizeof(u32));
	else
		memset(dst, 0, nr_cpu_ids * sizeof(u32));
}

struct trace_seq;
const char *__window_print(struct trace_seq *p, const u32 *buf, int buf_len)
{
	int i;
	const char *ret = p->buffer + seq_buf_used(&p->seq);

	for (i = 0; i < buf_len; i++)
		trace_seq_printf(p, "%u ", buf[i]);

	trace_seq_putc(p, 0);

	return ret;
}

static inline s64 __rq_update_sum(struct rq *rq, bool curr, bool new)
{
	if (curr)
		if (new)
			return rq->nt_curr_runnable_sum;
		else
			return rq->curr_runnable_sum;
	else
		if (new)
			return rq->nt_prev_runnable_sum;
		else
			return rq->prev_runnable_sum;
}

#ifdef CONFIG_SCHED_RTG
static inline s64 __grp_update_sum(struct rq *rq, bool curr, bool new)
{
	if (curr)
		if (new)
			return rq->grp_time.nt_curr_runnable_sum;
		else
			return rq->grp_time.curr_runnable_sum;
	else
		if (new)
			return rq->grp_time.nt_prev_runnable_sum;
		else
			return rq->grp_time.prev_runnable_sum;
}

static inline s64
__get_update_sum(struct rq *rq, enum migrate_types migrate_type,
		 bool src, bool new, bool curr)
{
	switch (migrate_type) {
	case RQ_TO_GROUP:
		if (src)
			return __rq_update_sum(rq, curr, new);
		else
			return __grp_update_sum(rq, curr, new);
	case GROUP_TO_RQ:
		if (src)
			return __grp_update_sum(rq, curr, new);
		else
			return __rq_update_sum(rq, curr, new);
	default:
		WARN_ON_ONCE(1);
		return -1;
	}
}
#endif
#endif

TRACE_EVENT(sched_update_history,

	TP_PROTO(struct rq *rq, struct task_struct *p, u32 runtime, int samples,
			enum task_event evt),

	TP_ARGS(rq, p, runtime, samples, evt),

	TP_STRUCT__entry(
		__array(char, comm, TASK_COMM_LEN)
		__field(pid_t, pid)
		__field(unsigned int, runtime)
		__field(int, samples)
		__field(enum task_event, evt)
		__field(unsigned int, demand)
		__array(u32, hist, RAVG_HIST_SIZE_MAX)
		__field(int, cpu)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid            = p->pid;
		__entry->runtime        = runtime;
		__entry->samples        = samples;
		__entry->evt            = evt;
		__entry->demand         = p->ravg.demand;
		memcpy(__entry->hist, p->ravg.sum_history,
					RAVG_HIST_SIZE_MAX * sizeof(u32));
		__entry->cpu            = rq->cpu;
	),

	TP_printk("%d (%s): runtime %u samples %d event %s demand %u (hist: %u %u %u %u %u) cpu %d",
		__entry->pid, __entry->comm,
		__entry->runtime, __entry->samples,
		task_event_names[__entry->evt], __entry->demand,
		__entry->hist[0], __entry->hist[1],
		__entry->hist[2], __entry->hist[3],
		__entry->hist[4], __entry->cpu)
);

TRACE_EVENT(sched_update_task_ravg,

	TP_PROTO(struct task_struct *p, struct rq *rq, enum task_event evt,
		 u64 wallclock, u64 irqtime),

	TP_ARGS(p, rq, evt, wallclock, irqtime),

	TP_STRUCT__entry(
		__array(char, comm, TASK_COMM_LEN)
		__field(pid_t, pid)
		__field(pid_t, cur_pid)
		__field(unsigned int, cur_freq)
		__field(u64, wallclock)
		__field(u64, mark_start)
		__field(u64, delta_m)
		__field(u64, win_start)
		__field(u64, delta)
		__field(u64, irqtime)
		__field(enum task_event, evt)
		__field(unsigned int, demand)
		__field(unsigned int, sum)
		__field(int, cpu)
		__field(u64, rq_cs)
		__field(u64, rq_ps)
		__field(u32, curr_window)
		__field(u32, prev_window)
		__dynamic_array(u32, curr_sum, nr_cpu_ids)
		__dynamic_array(u32, prev_sum, nr_cpu_ids)
		__field(u64, nt_cs)
		__field(u64, nt_ps)
		__field(u32, active_windows)
	),

	TP_fast_assign(
		__entry->wallclock      = wallclock;
		__entry->win_start      = rq->window_start;
		__entry->delta          = (wallclock - rq->window_start);
		__entry->evt            = evt;
		__entry->cpu            = rq->cpu;
		__entry->cur_pid        = rq->curr->pid;
		__entry->cur_freq       = rq->cluster->cur_freq;
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid            = p->pid;
		__entry->mark_start     = p->ravg.mark_start;
		__entry->delta_m        = (wallclock - p->ravg.mark_start);
		__entry->demand         = p->ravg.demand;
		__entry->sum            = p->ravg.sum;
		__entry->irqtime        = irqtime;
		__entry->rq_cs          = rq->curr_runnable_sum;
		__entry->rq_ps          = rq->prev_runnable_sum;
		__entry->curr_window    = p->ravg.curr_window;
		__entry->prev_window    = p->ravg.prev_window;
		__window_data(__get_dynamic_array(curr_sum), p->ravg.curr_window_cpu);
		__window_data(__get_dynamic_array(prev_sum), p->ravg.prev_window_cpu);
		__entry->nt_cs          = rq->nt_curr_runnable_sum;
		__entry->nt_ps          = rq->nt_prev_runnable_sum;
		__entry->active_windows = p->ravg.active_windows;
	),

	TP_printk("wc %llu ws %llu delta %llu event %s cpu %d cur_freq %u cur_pid %d task %d (%s) ms %llu delta %llu demand %u sum %u irqtime %llu rq_cs %llu rq_ps %llu cur_window %u (%s) prev_window %u (%s) nt_cs %llu nt_ps %llu active_wins %u",
		__entry->wallclock, __entry->win_start, __entry->delta,
		task_event_names[__entry->evt], __entry->cpu,
		__entry->cur_freq, __entry->cur_pid,
		__entry->pid, __entry->comm, __entry->mark_start,
		__entry->delta_m, __entry->demand,
		__entry->sum, __entry->irqtime,
		__entry->rq_cs, __entry->rq_ps, __entry->curr_window,
		__window_print(p, __get_dynamic_array(curr_sum), nr_cpu_ids),
		__entry->prev_window,
		__window_print(p, __get_dynamic_array(prev_sum), nr_cpu_ids),
		__entry->nt_cs, __entry->nt_ps,
		__entry->active_windows)
);

extern const char *migrate_type_names[];

#ifdef CONFIG_SCHED_RTG
TRACE_EVENT(sched_migration_update_sum,

	TP_PROTO(struct task_struct *p, enum migrate_types migrate_type, struct rq *rq),

	TP_ARGS(p, migrate_type, rq),

	TP_STRUCT__entry(
		__field(int, tcpu)
		__field(int, pid)
		__field(enum migrate_types, migrate_type)
		__field(s64, src_cs)
		__field(s64, src_ps)
		__field(s64, dst_cs)
		__field(s64, dst_ps)
		__field(s64, src_nt_cs)
		__field(s64, src_nt_ps)
		__field(s64, dst_nt_cs)
		__field(s64, dst_nt_ps)
	),

	TP_fast_assign(
		__entry->tcpu		= task_cpu(p);
		__entry->pid		= p->pid;
		__entry->migrate_type	= migrate_type;
		__entry->src_cs		= __get_update_sum(rq, migrate_type,
							   true, false, true);
		__entry->src_ps		= __get_update_sum(rq, migrate_type,
							   true, false, false);
		__entry->dst_cs		= __get_update_sum(rq, migrate_type,
							   false, false, true);
		__entry->dst_ps		= __get_update_sum(rq, migrate_type,
							   false, false, false);
		__entry->src_nt_cs	= __get_update_sum(rq, migrate_type,
							   true, true, true);
		__entry->src_nt_ps	= __get_update_sum(rq, migrate_type,
							   true, true, false);
		__entry->dst_nt_cs	= __get_update_sum(rq, migrate_type,
							   false, true, true);
		__entry->dst_nt_ps	= __get_update_sum(rq, migrate_type,
							   false, true, false);
	),

	TP_printk("pid %d task_cpu %d migrate_type %s src_cs %llu src_ps %llu dst_cs %lld dst_ps %lld src_nt_cs %llu src_nt_ps %llu dst_nt_cs %lld dst_nt_ps %lld",
		__entry->pid, __entry->tcpu, migrate_type_names[__entry->migrate_type],
		__entry->src_cs, __entry->src_ps, __entry->dst_cs, __entry->dst_ps,
		__entry->src_nt_cs, __entry->src_nt_ps, __entry->dst_nt_cs, __entry->dst_nt_ps)
);
#endif
#endif /* _TRACE_WALT_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
