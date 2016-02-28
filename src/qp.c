/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "mlx5.h"
#include "doorbell.h"
#include "wqe.h"

#define MLX5_ATOMIC_SIZE 8

static const uint32_t mlx5_ib_opcode[] = {
	[IBV_WR_SEND]			= MLX5_OPCODE_SEND,
	[IBV_WR_SEND_WITH_IMM]		= MLX5_OPCODE_SEND_IMM,
	[IBV_WR_RDMA_WRITE]		= MLX5_OPCODE_RDMA_WRITE,
	[IBV_WR_RDMA_WRITE_WITH_IMM]	= MLX5_OPCODE_RDMA_WRITE_IMM,
	[IBV_WR_RDMA_READ]		= MLX5_OPCODE_RDMA_READ,
	[IBV_WR_ATOMIC_CMP_AND_SWP]	= MLX5_OPCODE_ATOMIC_CS,
	[IBV_WR_ATOMIC_FETCH_AND_ADD]	= MLX5_OPCODE_ATOMIC_FA,
	[IBV_WR_SEND_ENABLE]		= MLX5_OPCODE_SEND_ENABLE,
	[IBV_WR_RECV_ENABLE]		= MLX5_OPCODE_RECV_ENABLE,
	[IBV_WR_CQE_WAIT]		= MLX5_OPCODE_CQE_WAIT
};

static inline void set_wait_en_seg(void *wqe_seg, uint32_t obj_num, uint32_t count)
{
	struct mlx5_wqe_wait_en_seg *seg = (struct mlx5_wqe_wait_en_seg *)wqe_seg;

	seg->pi      = htonl(count);
	seg->obj_num = htonl(obj_num);
	return;
}

static void *get_recv_wqe(struct mlx5_qp *qp, int n)
{
	return qp->buf.buf + qp->rq.offset + (n << qp->rq.wqe_shift);
}

static int copy_to_scat(struct mlx5_wqe_data_seg *scat, void *buf, int *size,
			 int max)
{
	int copy;
	int i;

	if (unlikely(!(*size)))
		return IBV_WC_SUCCESS;

	for (i = 0; i < max; ++i) {
		copy = min(*size, ntohl(scat->byte_count));
		memcpy((void *)(unsigned long)ntohll(scat->addr), buf, copy);
		*size -= copy;
		if (*size == 0)
			return IBV_WC_SUCCESS;

		buf += copy;
		++scat;
	}
	return IBV_WC_LOC_LEN_ERR;
}

int mlx5_copy_to_recv_wqe(struct mlx5_qp *qp, int idx, void *buf, int size)
{
	struct mlx5_wqe_data_seg *scat;
	int max = 1 << (qp->rq.wqe_shift - 4);

	scat = get_recv_wqe(qp, idx);
	if (unlikely(qp->wq_sig))
		++scat;

	return copy_to_scat(scat, buf, &size, max);
}

int mlx5_copy_to_send_wqe(struct mlx5_qp *qp, int idx, void *buf, int size)
{
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_data_seg *scat;
	void *p;
	int max;

	idx &= (qp->sq.wqe_cnt - 1);
	ctrl = mlx5_get_send_wqe(qp, idx);
	if (qp->ibv_qp->qp_type != IBV_QPT_RC) {
		fprintf(stderr, "scatter to CQE is supported only for RC QPs\n");
		return IBV_WC_GENERAL_ERR;
	}
	p = ctrl + 1;

	switch (ntohl(ctrl->opmod_idx_opcode) & 0xff) {
	case MLX5_OPCODE_RDMA_READ:
		p = p + sizeof(struct mlx5_wqe_raddr_seg);
		break;

	case MLX5_OPCODE_ATOMIC_CS:
	case MLX5_OPCODE_ATOMIC_FA:
		p = p + sizeof(struct mlx5_wqe_raddr_seg) +
			sizeof(struct mlx5_wqe_atomic_seg);
		break;

	default:
		fprintf(stderr, "scatter to CQE for opcode %d\n",
			ntohl(ctrl->opmod_idx_opcode) & 0xff);
		return IBV_WC_REM_INV_REQ_ERR;
	}

	scat = p;
	max = (ntohl(ctrl->qpn_ds) & 0x3F) - (((void *)scat - (void *)ctrl) >> 4);
	if (unlikely((void *)(scat + max) > qp->sq.qend)) {
		int tmp = ((void *)qp->sq.qend - (void *)scat) >> 4;
		int orig_size = size;

		if (copy_to_scat(scat, buf, &size, tmp) == IBV_WC_SUCCESS)
			return IBV_WC_SUCCESS;
		max = max - tmp;
		buf += orig_size - size;
		scat = mlx5_get_send_wqe(qp, 0);
	}

	return copy_to_scat(scat, buf, &size, max);
}

void *mlx5_get_send_wqe(struct mlx5_qp *qp, int n)
{
	return qp->sq_start + (n << MLX5_SEND_WQE_SHIFT);
}

void mlx5_init_qp_indices(struct mlx5_qp *qp)
{
	qp->sq.head	 = 0;
	qp->sq.tail	 = 0;
	qp->rq.head	 = 0;
	qp->rq.tail	 = 0;
	qp->sq.cur_post  = 0;
	qp->sq.head_en_index = 0;
	qp->sq.head_en_count = 0;
	qp->rq.head_en_index = 0;
	qp->rq.head_en_count = 0;
}

static int mlx5_wq_overflow(struct mlx5_wq *wq, int nreq, struct mlx5_cq *cq)
{
	unsigned cur;

	cur = wq->head - wq->tail;
	if (cur + nreq < wq->max_post)
		return 0;

	mlx5_spin_lock(&cq->lock);
	cur = wq->head - wq->tail;
	mlx5_spin_unlock(&cq->lock);

	return cur + nreq >= wq->max_post;
}

static inline void set_raddr_seg(struct mlx5_wqe_raddr_seg *rseg,
				 uint64_t remote_addr, uint32_t rkey)
{
	rseg->raddr    = htonll(remote_addr);
	rseg->rkey     = htonl(rkey);
	rseg->reserved = 0;
}

static void set_atomic_seg(struct mlx5_wqe_atomic_seg *aseg,
			   enum ibv_wr_opcode   opcode,
			   uint64_t swap,
			   uint64_t compare_add)
{
	if (opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
		aseg->swap_add = htonll(swap);
		aseg->compare  = htonll(compare_add);
	} else {
		aseg->swap_add = htonll(compare_add);
	}
}

static void set_datagram_seg(struct mlx5_wqe_datagram_seg *dseg,
			     struct ibv_send_wr *wr)
{
	memcpy(&dseg->av, &to_mah(wr->wr.ud.ah)->av, sizeof dseg->av);
	dseg->av.dqp_dct = htonl(wr->wr.ud.remote_qpn | MLX5_EXTENED_UD_AV);
	dseg->av.key.qkey.qkey = htonl(wr->wr.ud.remote_qkey);
}

static void set_data_ptr_seg(struct mlx5_wqe_data_seg *dseg, struct ibv_sge *sg,
			     int offset)
{
	dseg->byte_count = htonl(sg->length - offset);
	dseg->lkey       = htonl(sg->lkey);
	dseg->addr       = htonll(sg->addr + offset);
}

static void set_data_ptr_seg_atomic(struct mlx5_wqe_data_seg *dseg,
				    struct ibv_sge *sg)
{
	dseg->byte_count = htonl(MLX5_ATOMIC_SIZE);
	dseg->lkey       = htonl(sg->lkey);
	dseg->addr       = htonll(sg->addr);
}

/*
 * Avoid using memcpy() to copy to BlueFlame page, since memcpy()
 * implementations may use move-string-buffer assembler instructions,
 * which do not guarantee order of copying.
 */
static void mlx5_bf_copy(unsigned long long *dst, unsigned long long *src,
			 unsigned bytecnt, struct mlx5_qp *qp)
{
	while (bytecnt > 0) {
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		bytecnt -= 8 * sizeof(unsigned long long);
		if (unlikely(src == qp->sq.qend))
			src = qp->sq_start;
	}
}

static uint32_t send_ieth(struct ibv_send_wr *wr)
{
	switch (wr->opcode) {
	case IBV_WR_SEND_WITH_IMM:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		return wr->imm_data;
	default:
		return 0;
	}
}

static int set_data_inl_seg(struct mlx5_qp *qp, struct ibv_send_wr *wr,
			    void *wqe, int *sz,
			    struct mlx5_sg_copy_ptr *sg_copy_ptr)
{
	struct mlx5_wqe_inline_seg *seg;
	void *addr;
	int len;
	int i;
	int inl = 0;
	void *qend = qp->sq.qend;
	int copy;
	int offset = sg_copy_ptr->offset;

	seg = wqe;
	wqe += sizeof *seg;
	for (i = sg_copy_ptr->index; i < wr->num_sge; ++i) {
		addr = (void *) (unsigned long)(wr->sg_list[i].addr + offset);
		len  = wr->sg_list[i].length - offset;
		inl += len;
		offset = 0;

		if (unlikely(inl > qp->max_inline_data)) {
			errno = ENOMEM;
			return -1;
		}

		if (unlikely(wqe + len > qend)) {
			copy = qend - wqe;
			memcpy(wqe, addr, copy);
			addr += copy;
			len -= copy;
			wqe = mlx5_get_send_wqe(qp, 0);
		}
		memcpy(wqe, addr, len);
		wqe += len;
	}

	if (likely(inl)) {
		seg->byte_count = htonl(inl | MLX5_INLINE_SEG);
		*sz = align(inl + sizeof seg->byte_count, 16) / 16;
	} else
		*sz = 0;

	return 0;
}

static uint8_t wq_sig(struct mlx5_wqe_ctrl_seg *ctrl)
{
	return calc_sig(ctrl, ntohl(ctrl->qpn_ds));
}

#ifdef MLX5_DEBUG
void dump_wqe(FILE *fp, int idx, int size_16, struct mlx5_qp *qp)
{
	uint32_t *uninitialized_var(p);
	int i, j;
	int tidx = idx;

	fprintf(fp, "dump wqe at %p\n", mlx5_get_send_wqe(qp, tidx));
	for (i = 0, j = 0; i < size_16 * 4; i += 4, j += 4) {
		if ((i & 0xf) == 0) {
			void *buf = mlx5_get_send_wqe(qp, tidx);
			tidx = (tidx + 1) & (qp->sq.wqe_cnt - 1);
			p = buf;
			j = 0;
		}
		fprintf(fp, "%08x %08x %08x %08x\n", ntohl(p[j]), ntohl(p[j + 1]),
			ntohl(p[j + 2]), ntohl(p[j + 3]));
	}
}
#endif /* MLX5_DEBUG */


void *mlx5_get_atomic_laddr(struct mlx5_qp *qp, uint16_t idx, int *byte_count)
{
	struct mlx5_wqe_data_seg *dpseg;
	void *addr;

	dpseg = mlx5_get_send_wqe(qp, idx) + sizeof(struct mlx5_wqe_ctrl_seg) +
		sizeof(struct mlx5_wqe_raddr_seg) +
		sizeof(struct mlx5_wqe_atomic_seg);
	addr = (void *)(unsigned long)ntohll(dpseg->addr);

	/*
	 * Currently byte count is always 8 bytes. Fix this when
	 * we support variable size of atomics
	 */
	*byte_count = 8;
	return addr;
}

static inline int copy_eth_inline_headers(struct ibv_qp *ibqp,
					  struct ibv_send_wr *wr,
					  struct mlx5_wqe_eth_seg *eseg,
					  struct mlx5_sg_copy_ptr *sg_copy_ptr)
{
	int inl_hdr_size = MLX5_ETH_L2_INLINE_HEADER_SIZE;
	int inl_hdr_copy_size = 0;
	int j = 0;
#ifdef MLX5_DEBUG
	FILE *fp = to_mctx(ibqp->context)->dbg_fp;
#endif

	if (unlikely(wr->num_sge < 1)) {
		mlx5_dbg(fp, MLX5_DBG_QP_SEND, "illegal num_sge: %d, minimum is 1\n",
			 wr->num_sge);
		return EINVAL;
	}

	if (likely(wr->sg_list[0].length >= MLX5_ETH_L2_INLINE_HEADER_SIZE)) {
		inl_hdr_copy_size = MLX5_ETH_L2_INLINE_HEADER_SIZE;
		memcpy(eseg->inline_hdr_start,
		       (void *)(uintptr_t)wr->sg_list[0].addr,
		       inl_hdr_copy_size);
	} else {
		for (j = 0; j < wr->num_sge && inl_hdr_size > 0; ++j) {
			inl_hdr_copy_size = min(wr->sg_list[j].length,
						inl_hdr_size);
			memcpy(eseg->inline_hdr_start +
			       (MLX5_ETH_L2_INLINE_HEADER_SIZE - inl_hdr_size),
			       (void *)(uintptr_t)wr->sg_list[j].addr,
			       inl_hdr_copy_size);
			inl_hdr_size -= inl_hdr_copy_size;
		}
		if (unlikely(inl_hdr_size)) {
			mlx5_dbg(fp, MLX5_DBG_QP_SEND, "Ethernet headers < 16 bytes\n");
			return EINVAL;
		}
		--j;
	}


	eseg->inline_hdr_sz = htons(MLX5_ETH_L2_INLINE_HEADER_SIZE);

	/* If we copied all the sge into the inline-headers, then we need to
	 * start copying from the next sge into the data-segment.
	 */
	if (unlikely(wr->sg_list[j].length == inl_hdr_copy_size)) {
		++j;
		inl_hdr_copy_size = 0;
	}

	sg_copy_ptr->index = j;
	sg_copy_ptr->offset = inl_hdr_copy_size;

	return 0;
}

int mlx5_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
			  struct ibv_send_wr **bad_wr)
{
	struct mlx5_context *ctx;
	struct mlx5_qp *qp = to_mqp(ibqp);
	void *seg;
	struct mlx5_wqe_ctrl_seg *ctrl = NULL;
	struct mlx5_wqe_data_seg *dpseg;
	struct mlx5_sg_copy_ptr sg_copy_ptr = {.index = 0, .offset = 0};
	int nreq;
	int inl = 0;
	int err = 0;
	int size = 0;
	int i;
	unsigned idx;
	uint8_t opmod = 0;
	struct mlx5_bf *bf = qp->bf;
	void *qend = qp->sq.qend;
	uint32_t mlx5_opcode;
	struct mlx5_wqe_xrc_seg *xrc;
	struct mlx5_cq *wait_cq;
	uint32_t wait_index = 0;
	unsigned head_en_index;
	struct mlx5_wq *wq;

#ifdef MLX5_DEBUG
	FILE *fp = to_mctx(ibqp->context)->dbg_fp;
#endif

	mlx5_spin_lock(&qp->sq.lock);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely(wr->opcode < 0 ||
		    wr->opcode >= sizeof mlx5_ib_opcode / sizeof mlx5_ib_opcode[0])) {
			mlx5_dbg(fp, MLX5_DBG_QP_SEND, "bad opcode %d\n", wr->opcode);
			errno = EINVAL;
			err = -1;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(!(qp->create_flags & IBV_QP_CREATE_IGNORE_SQ_OVERFLOW) && mlx5_wq_overflow(&qp->sq, nreq,
					      to_mcq(qp->ibv_qp->send_cq)))) {
			mlx5_dbg(fp, MLX5_DBG_QP_SEND, "work queue overflow\n");
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->sq.max_gs)) {
			mlx5_dbg(fp, MLX5_DBG_QP_SEND, "max gs exceeded %d (max = %d)\n",
				 wr->num_sge, qp->sq.max_gs);
			errno = ENOMEM;
			err = -1;
			*bad_wr = wr;
			goto out;
		}

		idx = qp->sq.cur_post & (qp->sq.wqe_cnt - 1);
		ctrl = seg = mlx5_get_send_wqe(qp, idx);
		*(uint32_t *)(seg + 8) = 0;
		ctrl->imm = send_ieth(wr);
		ctrl->fm_ce_se = qp->sq_signal_bits |
			(wr->send_flags & IBV_SEND_SIGNALED ?
			 MLX5_WQE_CTRL_CQ_UPDATE : 0) |
			(wr->send_flags & IBV_SEND_SOLICITED ?
			 MLX5_WQE_CTRL_SOLICITED : 0) |
			(wr->send_flags & IBV_SEND_FENCE ?
			 MLX5_WQE_CTRL_FENCE : 0);

		seg += sizeof *ctrl;
		size = sizeof *ctrl / 16;

		switch (ibqp->qp_type) {
		case IBV_QPT_XRC_SEND:
			xrc = seg;
			xrc->xrc_srqn = htonl(wr->qp_type.xrc.remote_srqn);
			seg += sizeof(*xrc);
			size += sizeof(*xrc) / 16;
			/* fall through */
		case IBV_QPT_RC:
			switch (wr->opcode) {
			case IBV_WR_RDMA_READ:
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
				set_raddr_seg(seg, wr->wr.rdma.remote_addr,
					      wr->wr.rdma.rkey);
				seg  += sizeof(struct mlx5_wqe_raddr_seg);
				size += sizeof(struct mlx5_wqe_raddr_seg) / 16;
				break;

			case IBV_WR_ATOMIC_CMP_AND_SWP:
			case IBV_WR_ATOMIC_FETCH_AND_ADD:
				if (unlikely(!qp->atomics_enabled)) {
					mlx5_dbg(fp, MLX5_DBG_QP_SEND, "atomic operations are not supported\n");
					err = ENOSYS;
					*bad_wr = wr;
					goto out;
				}
				set_raddr_seg(seg, wr->wr.atomic.remote_addr,
					      wr->wr.atomic.rkey);
				seg  += sizeof(struct mlx5_wqe_raddr_seg);

				set_atomic_seg(seg, wr->opcode,
					       wr->wr.atomic.swap,
					       wr->wr.atomic.compare_add);
				seg  += sizeof(struct mlx5_wqe_atomic_seg);

				size += (sizeof(struct mlx5_wqe_raddr_seg) +
				sizeof(struct mlx5_wqe_atomic_seg)) / 16;
				break;
			case IBV_WR_CQE_WAIT:
				if (!(qp->create_flags & IBV_QP_CREATE_CROSS_CHANNEL)) {
					err = EINVAL;
					*bad_wr = wr;
					goto out;
				}

				wait_cq = to_mcq(wr->wr.cqe_wait.cq);
				wait_index = wait_cq->wait_index + wr->wr.cqe_wait.cq_count;
				wait_cq->wait_count = max(wait_cq->wait_count, wr->wr.cqe_wait.cq_count);
				if (wr->send_flags & IBV_SEND_WAIT_EN_LAST) {
					wait_cq->wait_index += wait_cq->wait_count;
					wait_cq->wait_count = 0;
				}
				set_wait_en_seg(seg, wait_cq->cqn, wait_index);
				seg += sizeof(struct mlx5_wqe_wait_en_seg);
				size += sizeof(struct mlx5_wqe_wait_en_seg) / 16;
				break;

			case IBV_WR_SEND_ENABLE:
			case IBV_WR_RECV_ENABLE:
				if (((wr->opcode == IBV_WR_SEND_ENABLE) &&
					!(to_mqp(wr->wr.wqe_enable.qp)->create_flags &
							IBV_QP_CREATE_MANAGED_SEND)) ||
					((wr->opcode == IBV_WR_RECV_ENABLE) &&
					!(to_mqp(wr->wr.wqe_enable.qp)->create_flags &
							IBV_QP_CREATE_MANAGED_RECV))) {
					err = EINVAL;
					*bad_wr = wr;
					goto out;
				}

				wq = (wr->opcode == IBV_WR_SEND_ENABLE) ?
					&to_mqp(wr->wr.wqe_enable.qp)->sq :
					&to_mqp(wr->wr.wqe_enable.qp)->rq;

				/* If wqe_count is 0 release all WRs from queue */
				if (wr->wr.wqe_enable.wqe_count) {
					head_en_index = wq->head_en_index +
								wr->wr.wqe_enable.wqe_count;
					wq->head_en_count = max(wq->head_en_count,
								wr->wr.wqe_enable.wqe_count);

					if ((int)(wq->head - head_en_index) < 0) {
						err = EINVAL;
						*bad_wr = wr;
						goto out;
					}
				} else {
					head_en_index = wq->head;
					wq->head_en_count = wq->head - wq->head_en_index;
				}

				if (wr->send_flags & IBV_SEND_WAIT_EN_LAST) {
					wq->head_en_index += wq->head_en_count;
					wq->head_en_count = 0;
				}

				set_wait_en_seg(seg, wr->wr.wqe_enable.qp->qp_num, head_en_index);

				seg += sizeof(struct mlx5_wqe_wait_en_seg);
				size += sizeof(struct mlx5_wqe_wait_en_seg) / 16;
				break;

			default:
				break;
			}
			break;

		case IBV_QPT_UC:
			switch (wr->opcode) {
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
				set_raddr_seg(seg, wr->wr.rdma.remote_addr,
					      wr->wr.rdma.rkey);
				seg  += sizeof(struct mlx5_wqe_raddr_seg);
				size += sizeof(struct mlx5_wqe_raddr_seg) / 16;
				break;

			default:
				break;
			}
			break;

		case IBV_QPT_UD:
			set_datagram_seg(seg, wr);
			seg  += sizeof(struct mlx5_wqe_datagram_seg);
			size += sizeof(struct mlx5_wqe_datagram_seg) / 16;
			if (unlikely((seg == qend)))
				seg = mlx5_get_send_wqe(qp, 0);
			break;

		case IBV_QPT_RAW_PACKET:
			memset(seg, 0, sizeof(struct mlx5_wqe_eth_seg));

			err = copy_eth_inline_headers(ibqp, wr, seg, &sg_copy_ptr);
			if (unlikely(err)) {
				*bad_wr = wr;
				mlx5_dbg(fp, MLX5_DBG_QP_SEND,
					 "copy_eth_inline_headers failed, err: %d\n",
					 err);
				goto out;
			}

			if (wr->send_flags & IBV_SEND_IP_CSUM) {
				if (!(qp->qp_cap_cache & MLX5_CSUM_SUPPORT_RAW_OVER_ETH)) {
					err = EINVAL;
					*bad_wr = wr;
					goto out;
				}

				((struct mlx5_wqe_eth_seg *)seg)->cs_flags |=
					MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
			}

			seg += sizeof(struct mlx5_wqe_eth_seg);
			size += sizeof(struct mlx5_wqe_eth_seg) / 16;
			break;

		default:
			break;
		}

		if (wr->send_flags & IBV_SEND_INLINE && wr->num_sge) {
			int uninitialized_var(sz);

			err = set_data_inl_seg(qp, wr, seg, &sz, &sg_copy_ptr);
			if (unlikely(err)) {
				*bad_wr = wr;
				mlx5_dbg(fp, MLX5_DBG_QP_SEND,
					 "inline layout failed, err %d\n", err);
				goto out;
			}
			inl = 1;
			size += sz;
		} else {
			dpseg = seg;
			for (i = sg_copy_ptr.index; i < wr->num_sge; ++i) {
				if (unlikely(dpseg == qend)) {
					seg = mlx5_get_send_wqe(qp, 0);
					dpseg = seg;
				}
				if (likely(wr->sg_list[i].length)) {
					if (unlikely(wr->opcode ==
						   IBV_WR_ATOMIC_CMP_AND_SWP ||
						   wr->opcode ==
						   IBV_WR_ATOMIC_FETCH_AND_ADD))
						set_data_ptr_seg_atomic(dpseg, wr->sg_list + i);
					else
						set_data_ptr_seg(dpseg, wr->sg_list + i,
								 sg_copy_ptr.offset);
					sg_copy_ptr.offset = 0;
					++dpseg;
					size += sizeof(struct mlx5_wqe_data_seg) / 16;
				}
			}
		}

		mlx5_opcode = mlx5_ib_opcode[wr->opcode];
		ctrl->opmod_idx_opcode = htonl(((qp->sq.cur_post & 0xffff) << 8) |
					       mlx5_opcode			 |
					       (opmod << 24));
		ctrl->qpn_ds = htonl(size | (ibqp->qp_num << 8));

		if (unlikely(qp->wq_sig))
			ctrl->signature = wq_sig(ctrl);

		qp->sq.wrid[idx] = wr->wr_id;
		qp->sq.wqe_head[idx] = qp->sq.head + nreq;
		qp->sq.cur_post += DIV_ROUND_UP(size * 16, MLX5_SEND_WQE_BB);

#ifdef MLX5_DEBUG
		if (mlx5_debug_mask & MLX5_DBG_QP_SEND)
			dump_wqe(to_mctx(ibqp->context)->dbg_fp, idx, size, qp);
#endif
	}

out:
	if (likely(nreq)) {
		qp->sq.head += nreq;

		if (qp->create_flags & IBV_QP_CREATE_MANAGED_SEND) {
			wmb();
			goto post_send_no_db;
		}

		/*
		 * Make sure that descriptors are written before
		 * updating doorbell record and ringing the doorbell
		 */
		wmb();
		qp->db[MLX5_SND_DBR] = htonl(qp->sq.cur_post & 0xffff);

		wc_wmb();
		ctx = to_mctx(ibqp->context);
		if (bf->need_lock)
			mlx5_spin_lock(&bf->lock);

		if (!ctx->shut_up_bf && nreq == 1 && bf->uuarn &&
		    (inl || ctx->prefer_bf) && size > 1 &&
		    size <= bf->buf_size / 16)
			mlx5_bf_copy(bf->reg + bf->offset, (unsigned long long *)ctrl,
				     align(size * 16, 64), qp);
		else
			mlx5_write64((__be32 *)ctrl, bf->reg + bf->offset,
				     &ctx->lock32);

		/*
		 * use wc_wmb() to ensure write combining buffers are flushed out
		 * of the running CPU. This must be carried inside the spinlock.
		 * Otherwise, there is a potential race. In the race, CPU A
		 * writes doorbell 1, which is waiting in the WC buffer. CPU B
		 * writes doorbell 2, and it's write is flushed earlier. Since
		 * the wc_wmb is CPU local, this will result in the HCA seeing
		 * doorbell 2, followed by doorbell 1.
		 */
		wc_wmb();
		bf->offset ^= bf->buf_size;
		if (bf->need_lock)
			mlx5_spin_unlock(&bf->lock);
	}

post_send_no_db:
	mlx5_spin_unlock(&qp->sq.lock);

	return err;
}

static void set_sig_seg(struct mlx5_qp *qp, struct mlx5_rwqe_sig *sig,
			int size, uint16_t idx)
{
	uint8_t  sign;
	uint32_t qpn = qp->ibv_qp->qp_num;

	sign = calc_sig(sig, size);
	sign ^= calc_sig(&qpn, 4);
	sign ^= calc_sig(&idx, 2);
	sig->signature = sign;
}

int mlx5_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad_wr)
{
	struct mlx5_qp *qp = to_mqp(ibqp);
	struct mlx5_wqe_data_seg *scat;
	int err = 0;
	int nreq;
	int ind;
	int i, j;
	struct mlx5_rwqe_sig *sig;

	mlx5_spin_lock(&qp->rq.lock);

	ind = qp->rq.head & (qp->rq.wqe_cnt - 1);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely(!(qp->create_flags & IBV_QP_CREATE_IGNORE_RQ_OVERFLOW) &&
				mlx5_wq_overflow(&qp->rq, nreq,
					      to_mcq(qp->ibv_qp->recv_cq)))) {
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->rq.max_gs)) {
			errno = EINVAL;
			*bad_wr = wr;
			err = -1;
			goto out;
		}

		scat = get_recv_wqe(qp, ind);
		sig = (struct mlx5_rwqe_sig *)scat;
		if (unlikely(qp->wq_sig)) {
			memset(sig, 0, 1 << qp->rq.wqe_shift);
			++scat;
		}

		for (i = 0, j = 0; i < wr->num_sge; ++i) {
			if (unlikely(!wr->sg_list[i].length))
				continue;
			set_data_ptr_seg(scat + j++, wr->sg_list + i, 0);
		}

		if (j < qp->rq.max_gs) {
			scat[j].byte_count = 0;
			scat[j].lkey       = htonl(MLX5_INVALID_LKEY);
			scat[j].addr       = 0;
		}

		if (unlikely(qp->wq_sig))
			set_sig_seg(qp, sig, (wr->num_sge + 1) << 4,
				    qp->rq.head & 0xffff);

		qp->rq.wrid[ind] = wr->wr_id;

		ind = (ind + 1) & (qp->rq.wqe_cnt - 1);
	}

out:
	if (likely(nreq)) {
		qp->rq.head += nreq;

		/*
		 * Make sure that descriptors are written before
		 * doorbell record.
		 */
		wmb();
		/*
		 * For Raw Packet QP, avoid updating the doorbell record
		 * as long as the QP isn't in RTR state, to avoid receiving
		 * packets in illegal states.
		 * This is only for Raw Packet QPs since they are represented
		 * differently in the hardware.
		 */
		if (likely(!(ibqp->qp_type == IBV_QPT_RAW_PACKET &&
			     ibqp->state < IBV_QPS_RTR)))
			qp->db[MLX5_RCV_DBR] = htonl(qp->rq.head & 0xffff);
	}

	mlx5_spin_unlock(&qp->rq.lock);

	return err;
}

int mlx5_use_huge(const char *key)
{
	char *e;
	e = getenv(key);
	if (e && !strcmp(e, "y"))
		return 1;

	return 0;
}

struct mlx5_qp *mlx5_find_qp(struct mlx5_context *ctx, uint32_t qpn)
{
	int tind = qpn >> MLX5_QP_TABLE_SHIFT;

	if (ctx->qp_table[tind].refcnt)
		return ctx->qp_table[tind].table[qpn & MLX5_QP_TABLE_MASK];
	else
		return NULL;
}

int mlx5_store_qp(struct mlx5_context *ctx, uint32_t qpn, struct mlx5_qp *qp)
{
	int tind = qpn >> MLX5_QP_TABLE_SHIFT;

	if (!ctx->qp_table[tind].refcnt) {
		ctx->qp_table[tind].table = calloc(MLX5_QP_TABLE_MASK + 1,
						   sizeof(struct mlx5_qp *));
		if (!ctx->qp_table[tind].table)
			return -1;
	}

	++ctx->qp_table[tind].refcnt;
	ctx->qp_table[tind].table[qpn & MLX5_QP_TABLE_MASK] = qp;
	return 0;
}

void mlx5_clear_qp(struct mlx5_context *ctx, uint32_t qpn)
{
	int tind = qpn >> MLX5_QP_TABLE_SHIFT;

	if (!--ctx->qp_table[tind].refcnt)
		free(ctx->qp_table[tind].table);
	else
		ctx->qp_table[tind].table[qpn & MLX5_QP_TABLE_MASK] = NULL;
}
